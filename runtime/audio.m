/* NFSU2 iOS Port - CoreAudio / RemoteIO / DirectSound Audio Layer
 *
 * EA Trax (interaktif muzik akisi), SFX (ses efektleri), ve motor sesleri
 * icin dusuk gecikmeli, kilit-serbest cift tamponlu (ring buffer) ve
 * dinamik donanim ornekleme hizina (44.1 kHz / 48 kHz) uyarlanabilen mimari.
 *
 * iOS AVAudioSession ve RemoteIO AudioUnit yasam dongusu:
 * - Kesintiler (AVAudioSessionInterruptionNotification): Arama / Alarm sirasinda
 *   ses unitesi guvenli sekilde durdurulur, sonrasinda otomatik surdurulur.
 * - Rota degisiklikleri (AVAudioSessionRouteChangeNotification): AirPods veya
 *   kulaklik takilip cikarildiginda donanim ornekleme hizi (44.1 <-> 48 kHz)
 *   ve tampon boyutu calisma aninda yeniden yapilandirilir.
 * - Medya sifirlama (AVAudioSessionMediaServicesWereResetNotification): audiod
 *   cokerse AudioUnit bastan olusturulur.
 * - Real-time thread priority inversion korumasi: au_cb asla bekletici kilit
 *   tutmaz; kilit-serbest ring buffer ve atomik bayraklar uzerinden calisir.
 */

#import <AudioToolbox/AudioToolbox.h>
#import <AudioUnit/AudioUnit.h>
#include <TargetConditionals.h>

#if TARGET_OS_IPHONE
#import <AVFoundation/AVFoundation.h>
#import <UIKit/UIKit.h>
#endif

#include "audio.h"
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>
#include <math.h>
#include <stdatomic.h>

extern uint8_t *g_mem;
uint64_t host_us(void);          /* oyunun SANAL saati (kare basina 16.67 ms) */

/* --- Donanim ve Durum Degiskenleri --- */
static atomic_uint_fast32_t g_hw_rate        = AUDIO_DEFAULT_RATE; /* 44100 veya 48000 Hz */
static atomic_bool          g_audio_suspended   = false;
static atomic_bool          g_audio_reconfiguring = false;
static atomic_bool          g_audio_on          = false;
static int                  g_backend           = 0;     /* 1 = AudioUnit, 2 = AudioQueue */

/* Oyun ses verisini kendi sanal zamaninda uretir; karistirici ise gercek
 * zamanda tuketiyordu. Emulator 60 fps altina dusunce sesin kesilmesini
 * onlemek icin tuketimi oyunun uretim hizina baglayan servo (PLL). */
static double g_rate_ratio = 1.0;
static int    g_sync_mode  = -1;      /* SNDSYNC: 1 = oyun hizina bagla */

static void update_rate_ratio(void){
    if (g_sync_mode < 0){
        const char *e = getenv("SNDSYNC");
        g_sync_mode = (e && *e) ? (*e != '0') : 1;      /* varsayilan: acik */
    }
    if (!g_sync_mode){ g_rate_ratio = 1.0; return; }
    static uint64_t lv = 0, lr = 0;
    struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts);
    uint64_t rus = (uint64_t)ts.tv_sec*1000000ull + (uint64_t)ts.tv_nsec/1000ull;
    uint64_t vus = host_us();
    if (lv && rus > lr){
        double dv = (double)(vus - lv), dr = (double)(rus - lr);
        if (dr > 1000.0){
            double k = dv / dr;
            if (k < 0.25) k = 0.25;
            /* TAVAN 1.0: ses GERCEK ZAMANDAN HIZLI calmamali. */
            if (k > 1.00) k = 1.00;
            g_rate_ratio += (k - g_rate_ratio) * 0.10;
        }
    }
    lv = vus; lr = rus;
}

#define OUT_CH     AUDIO_OUT_CHANNELS
#define NBUF       6
#define FRAMES     2048

#define MAXSND     AUDIO_MAX_BUFFERS

typedef struct {
    uint32_t data, bytes, rate, chans, bits;
    int      used, playing, loop;
    double   cursor;          /* kaynak ornek cinsinden */
    float    vol;             /* 0..1 */
    uint32_t wpos;            /* oyunun yazdigi son baytin bitisi */
    int      wseen;           /* hic yazma gorduk mu */
    double   trim;            /* hiz duzeltmesi (servo) */
    double   target;          /* kilitlenecek dolgu orani (uyarlanir) */
    double   freq;            /* SetFrequency orani (1.0 = ozgun hiz) */
    uint64_t plays, stops, wr_bytes, wr_calls, wr_nonzero;
    uint64_t over;            /* yaziciyi gectigimiz geri-cagirma sayisi */
} SndBuf;

static SndBuf g_snd[MAXSND];
static int    g_sndn = 1;                    /* 0 = gecersiz kimlik */
static pthread_mutex_t g_slock = PTHREAD_MUTEX_INITIALIZER;

static AudioQueueRef        g_q;
static AudioQueueBufferRef  g_qb[NBUF];
static AudioUnit            g_au = NULL;     /* Dusuk gecikmeli RemoteIO */
static unsigned             g_au_slice = 0;  /* Geri cagirma basina gerceklesen kare */

static uint64_t g_mixed_frames = 0, g_active_peak = 0;
static uint64_t g_replay = 0, g_reissue = 0, g_starved = 0, g_worst_gap_us = 0;
static uint64_t g_out_frames = 0, g_out_zero = 0, g_gap_cb = 0;

/* Tani dosyalari */
static FILE *g_dump = NULL;      /* SNDDUMP=<yol> : ham s16le stereo */
static FILE *g_csv  = NULL;      /* SNDCSV=<yol>  : geri-cagirma basina durum */
static uint64_t g_cb_no = 0;

/* --- Kilit-Serbest (Lock-Free) SPSC Dairesel Tampon Uygulamasi --- */
static AudioRingBuffer g_stream_rb;

bool audio_ringbuf_init(AudioRingBuffer *rb, size_t capacity_frames, uint32_t channels){
    if (!rb || (capacity_frames & (capacity_frames - 1)) != 0) return false;
    rb->channels = (channels > 0) ? channels : OUT_CH;
    rb->capacity_frames = capacity_frames;
    rb->mask = capacity_frames - 1;
    atomic_init(&rb->write_pos, 0);
    atomic_init(&rb->read_pos, 0);
    rb->buffer = (int16_t *)calloc(capacity_frames * rb->channels, sizeof(int16_t));
    return rb->buffer != NULL;
}

void audio_ringbuf_destroy(AudioRingBuffer *rb){
    if (rb && rb->buffer){
        free(rb->buffer);
        rb->buffer = NULL;
    }
}

void audio_ringbuf_reset(AudioRingBuffer *rb){
    if (!rb) return;
    atomic_store_explicit(&rb->write_pos, 0, memory_order_relaxed);
    atomic_store_explicit(&rb->read_pos, 0, memory_order_relaxed);
    if (rb->buffer){
        memset(rb->buffer, 0, rb->capacity_frames * rb->channels * sizeof(int16_t));
    }
}

size_t audio_ringbuf_available_read(const AudioRingBuffer *rb){
    if (!rb) return 0;
    size_t w = atomic_load_explicit(&rb->write_pos, memory_order_acquire);
    size_t r = atomic_load_explicit(&rb->read_pos, memory_order_relaxed);
    return (w >= r) ? (w - r) : 0;
}

size_t audio_ringbuf_available_write(const AudioRingBuffer *rb){
    if (!rb) return 0;
    size_t w = atomic_load_explicit(&rb->write_pos, memory_order_relaxed);
    size_t r = atomic_load_explicit(&rb->read_pos, memory_order_acquire);
    size_t used = (w >= r) ? (w - r) : 0;
    return (used < rb->capacity_frames) ? (rb->capacity_frames - used) : 0;
}

size_t audio_ringbuf_write(AudioRingBuffer *rb, const int16_t *src, size_t frames){
    if (!rb || !src || !frames) return 0;
    size_t avail = audio_ringbuf_available_write(rb);
    if (frames > avail) frames = avail;
    if (frames == 0) return 0;

    size_t w = atomic_load_explicit(&rb->write_pos, memory_order_relaxed);
    size_t idx = w & rb->mask;
    size_t first = rb->capacity_frames - idx;
    if (first > frames) first = frames;
    size_t second = frames - first;

    memcpy(rb->buffer + idx * rb->channels, src, first * rb->channels * sizeof(int16_t));
    if (second > 0){
        memcpy(rb->buffer, src + first * rb->channels, second * rb->channels * sizeof(int16_t));
    }

    atomic_store_explicit(&rb->write_pos, w + frames, memory_order_release);
    return frames;
}

size_t audio_ringbuf_read(AudioRingBuffer *rb, int16_t *dst, size_t frames){
    if (!rb || !dst || !frames) return 0;
    size_t avail = audio_ringbuf_available_read(rb);
    if (frames > avail) frames = avail;
    if (frames == 0) return 0;

    size_t r = atomic_load_explicit(&rb->read_pos, memory_order_relaxed);
    size_t idx = r & rb->mask;
    size_t first = rb->capacity_frames - idx;
    if (first > frames) first = frames;
    size_t second = frames - first;

    memcpy(dst, rb->buffer + idx * rb->channels, first * rb->channels * sizeof(int16_t));
    if (second > 0){
        memcpy(dst + first * rb->channels, rb->buffer, second * rb->channels * sizeof(int16_t));
    }

    atomic_store_explicit(&rb->read_pos, r + frames, memory_order_release);
    return frames;
}

/* --- DirectSound COM Katmani Fonksiyonlari --- */

int audio_register(uint32_t data, uint32_t bytes, uint32_t rate,
                   uint32_t chans, uint32_t bits){
    if (!data || !bytes) return 0;
    if (rate < 4000u || rate > 192000u) rate = AUDIO_DEFAULT_RATE;
    if (chans < 1u || chans > 2u) chans = 1u;
    if (bits != 8u && bits != 16u) bits = 16u;
    pthread_mutex_lock(&g_slock);
    int id = 0;
    if (g_sndn < MAXSND){
        id = g_sndn++;
        SndBuf *b = &g_snd[id];
        b->data = data; b->bytes = bytes; b->rate = rate;
        b->chans = chans; b->bits = bits;
        b->used = 1; b->playing = 0; b->loop = 0; b->cursor = 0.0; b->vol = 1.f;
        b->wpos = 0; b->wseen = 0; b->trim = 1.0; b->target = 0.0; b->over = 0;
        b->freq = 1.0; b->plays = b->stops = 0;
        b->wr_bytes = b->wr_calls = b->wr_nonzero = 0;
        fprintf(stderr, "  [ses] tampon #%d: %u Hz, %u kanal, %u bit, %u bayt (%.2f sn)\n",
                id, rate, chans, bits, bytes,
                (double)bytes / (double)(rate * chans * (bits/8u)));
    }
    pthread_mutex_unlock(&g_slock);
    return id;
}

void audio_play(int id, int loop){
    if (id <= 0 || id >= MAXSND) return;
    pthread_mutex_lock(&g_slock);
    if (g_snd[id].used){
        /* Calan akis tamponunda imleci SIFIRLAMA; dur-basla teklemelerini engeller */
        if (!g_snd[id].playing){ g_snd[id].cursor = 0.0; g_replay++; }
        else g_reissue++;
        g_snd[id].playing = 1;
        g_snd[id].loop = loop;
        g_snd[id].plays++;
    }
    pthread_mutex_unlock(&g_slock);
}

void audio_stop(int id){
    if (id <= 0 || id >= MAXSND) return;
    pthread_mutex_lock(&g_slock);
    if (g_snd[id].used){ g_snd[id].playing = 0; g_snd[id].stops++; }
    pthread_mutex_unlock(&g_slock);
}

void audio_note_write(int id, uint32_t end_off){
    if (id <= 0 || id >= MAXSND) return;
    pthread_mutex_lock(&g_slock);
    if (g_snd[id].used && g_snd[id].bytes){
        g_snd[id].wpos = end_off % g_snd[id].bytes;
        g_snd[id].wseen = 1;
    }
    pthread_mutex_unlock(&g_slock);
}

void audio_note_write_stat(int id, uint32_t n, int nonzero){
    if (id <= 0 || id >= MAXSND) return;
    pthread_mutex_lock(&g_slock);
    if (g_snd[id].used){
        g_snd[id].wr_calls++;
        g_snd[id].wr_bytes += n;
        if (nonzero) g_snd[id].wr_nonzero++;
    }
    pthread_mutex_unlock(&g_slock);
}

void audio_set_freq(int id, uint32_t hz){
    if (id <= 0 || id >= MAXSND) return;
    pthread_mutex_lock(&g_slock);
    if (g_snd[id].used && g_snd[id].rate){
        if (!hz) g_snd[id].freq = 1.0;
        else {
            double f = (double)hz / (double)g_snd[id].rate;
            if (f < 0.05) f = 0.05;
            if (f > 8.00) f = 8.00;
            g_snd[id].freq = f;
        }
    }
    pthread_mutex_unlock(&g_slock);
}

int audio_duplicate(int src){
    if (src <= 0 || src >= MAXSND) return 0;
    int id = 0;
    pthread_mutex_lock(&g_slock);
    if (g_snd[src].used && g_sndn < MAXSND){
        id = g_sndn++;
        g_snd[id] = g_snd[src];
        g_snd[id].playing = 0; g_snd[id].cursor = 0.0; g_snd[id].trim = 1.0;
        g_snd[id].target = 0.0; g_snd[id].over = 0;
        g_snd[id].plays = g_snd[id].stops = 0;
        g_snd[id].wr_bytes = g_snd[id].wr_calls = g_snd[id].wr_nonzero = 0;
    }
    pthread_mutex_unlock(&g_slock);
    return id;
}

#define WRITE_LEAD_MS 50u
void audio_cursors(int id, uint32_t *play, uint32_t *write){
    uint32_t p = 0, w = 0;
    if (id > 0 && id < MAXSND){
        pthread_mutex_lock(&g_slock);
        if (g_snd[id].used && g_snd[id].bytes){
            uint32_t bpf = g_snd[id].chans * (g_snd[id].bits/8u);
            uint32_t sz  = g_snd[id].bytes;
            p = (uint32_t)(g_snd[id].cursor * (double)bpf) % sz;
            uint32_t lead = (g_snd[id].rate * WRITE_LEAD_MS / 1000u) * bpf;
            if (lead >= sz) lead = sz / 4u;
            w = (p + lead) % sz;
        }
        pthread_mutex_unlock(&g_slock);
    }
    if (play)  *play  = p;
    if (write) *write = w;
}

uint32_t audio_cursor(int id){
    uint32_t p = 0;
    audio_cursors(id, &p, NULL);
    return p;
}

void audio_set_volume(int id, long millibel){
    if (id <= 0 || id >= MAXSND) return;
    float v = (millibel <= -10000L) ? 0.f : powf(10.f, (float)millibel / 2000.f);
    if (v > 1.f) v = 1.f;
    pthread_mutex_lock(&g_slock);
    if (g_snd[id].used) g_snd[id].vol = v;
    pthread_mutex_unlock(&g_slock);
}

double audio_time(void){
    uint32_t hw_rate = (uint32_t)atomic_load_explicit(&g_hw_rate, memory_order_relaxed);
    if (!hw_rate) hw_rate = AUDIO_DEFAULT_RATE;
    return (double)g_mixed_frames / (double)hw_rate;
}

uint32_t audio_get_hardware_rate(void){
    return (uint32_t)atomic_load_explicit(&g_hw_rate, memory_order_relaxed);
}

int audio_is_active(void){
    return atomic_load_explicit(&g_audio_on, memory_order_relaxed) &&
           !atomic_load_explicit(&g_audio_suspended, memory_order_relaxed);
}

int audio_is_suspended(void){
    return atomic_load_explicit(&g_audio_suspended, memory_order_relaxed);
}

/* --- Karistirici (Mixer) Cekirdegi ---
 * Dinamik Donanim Hizina (44.1 kHz / 48 kHz) Dogrusal Ara-Degerleme (Linear Interpolation)
 * ile yuksek kaliteli resample yapar; motor sesi ve EA Trax'te aliasing'i onler. */
static void mix_into(int16_t *out, unsigned frames){
    static float acc[FRAMES * OUT_CH];
    if (frames > FRAMES) frames = FRAMES;
    memset(acc, 0, sizeof(float) * frames * OUT_CH);
    uint64_t active = 0;
    update_rate_ratio();

    uint32_t hw_rate = (uint32_t)atomic_load_explicit(&g_hw_rate, memory_order_relaxed);
    if (!hw_rate) hw_rate = AUDIO_DEFAULT_RATE;

    pthread_mutex_lock(&g_slock);
    for (int i = 1; i < g_sndn; i++){
        SndBuf *b = &g_snd[i];
        if (!b->used || !b->playing || !b->bytes) continue;
        uint32_t bps  = b->bits / 8u;
        uint32_t bpf  = b->chans * bps;
        if (!bpf) continue;
        uint32_t nsrc = b->bytes / bpf;
        if (!nsrc) continue;

        /* Oynatma imlecini oyunun YAZMA imlecine kilitle (PLL / Servo) */
        if (b->wseen){
            uint32_t bpf2 = b->chans * (b->bits/8u);
            uint32_t pbyte = ((uint32_t)(b->cursor * (double)bpf2)) % b->bytes;
            uint32_t avail = (b->wpos + b->bytes - pbyte) % b->bytes;
            double frac = (double)avail / (double)b->bytes;
            double want;
            if (frac > 0.85){
                b->over++;
                want = 0.94;
            } else {
                if (b->target <= 0.0) b->target = frac;
                else b->target += (frac - b->target) * 0.0008;
                if (b->target < 0.12) b->target = 0.12;
                if (b->target > 0.60) b->target = 0.60;
                want = 1.0 + (frac - b->target) * 1.5;
                if (want < 0.97) want = 0.97;
                if (want > 1.03) want = 1.03;
            }
            b->trim += (want - b->trim) * 0.05;
        } else {
            b->trim += (1.0 - b->trim) * 0.08;
        }
        if (b->trim < 0.5 || b->trim > 2.0) b->trim = 1.0;

        /* Dinamik adim: Kaynak Frekans / Donanim Cikis Frekansi * Senkron * Servo * Pitch */
        double step = ((double)b->rate / (double)hw_rate) * g_rate_ratio * b->trim * b->freq;
        active++;

        /* Dogrusal Ara-Degerlemeli (Linear Interpolated) Karistirma */
        for (unsigned f = 0; f < frames; f++){
            double sp = b->cursor + step * (double)f;
            if (sp >= (double)nsrc){
                if (b->loop) sp = fmod(sp, (double)nsrc);
                else { b->playing = 0; break; }
            }
            uint32_t si0 = (uint32_t)sp;
            uint32_t si1 = (si0 + 1 < nsrc) ? (si0 + 1) : (b->loop ? 0 : si0);
            float alpha = (float)(sp - (double)si0);

            for (int c = 0; c < OUT_CH; c++){
                uint32_t sc = (b->chans == 2u) ? (uint32_t)c : 0u;
                uint32_t off0 = b->data + si0 * bpf + sc * bps;
                uint32_t off1 = b->data + si1 * bpf + sc * bps;
                float s0, s1;
                if (b->bits == 16u){
                    int16_t v0, v1;
                    memcpy(&v0, g_mem + off0, 2);
                    memcpy(&v1, g_mem + off1, 2);
                    s0 = (float)v0 / 32768.f;
                    s1 = (float)v1 / 32768.f;
                } else {
                    s0 = ((float)g_mem[off0] - 128.f) / 128.f;
                    s1 = ((float)g_mem[off1] - 128.f) / 128.f;
                }
                float sample = s0 + alpha * (s1 - s0);
                acc[f * OUT_CH + c] += sample * b->vol;
            }
        }

        b->cursor += step * (double)frames;
        if (nsrc){
            if (b->cursor >= (double)nsrc){
                if (b->loop) b->cursor = fmod(b->cursor, (double)nsrc);
                else { b->cursor = 0.0; b->playing = 0; }
            }
        }
    }
    pthread_mutex_unlock(&g_slock);

    if (active > g_active_peak) g_active_peak = active;
    g_mixed_frames += frames;

    /* Sessizlik kontrolu */
    if (active){
        unsigned zero = 0;
        for (unsigned k = 0; k < frames * OUT_CH; k++) if (acc[k] == 0.f) zero++;
        g_out_frames += frames * OUT_CH;
        g_out_zero   += zero;
        if (zero > (frames * OUT_CH) * 3u / 4u) g_gap_cb++;
    }

    /* Doygunluk ve int16 paketleme */
    for (unsigned k = 0; k < frames * OUT_CH; k++){
        float v = acc[k];
        if (v >  1.f) v =  1.f;
        if (v < -1.f) v = -1.f;
        out[k] = (int16_t)(v * 32767.f);
    }
    g_cb_no++;
    if (g_dump) fwrite(out, sizeof(int16_t), (size_t)frames * OUT_CH, g_dump);
}

static uint64_t now_us_a(void){
    struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000ull + (uint64_t)ts.tv_nsec / 1000ull;
}

/* AudioQueue Geri Cagirmasi (Yedek Yol) */
static void cb(void *ud, AudioQueueRef q, AudioQueueBufferRef buf){
    (void)ud;
    if (atomic_load_explicit(&g_audio_suspended, memory_order_relaxed)){
        memset(buf->mAudioData, 0, FRAMES * OUT_CH * sizeof(int16_t));
        buf->mAudioDataByteSize = FRAMES * OUT_CH * sizeof(int16_t);
        AudioQueueEnqueueBuffer(q, buf, 0, NULL);
        return;
    }
    uint32_t hw_rate = (uint32_t)atomic_load_explicit(&g_hw_rate, memory_order_relaxed);
    if (!hw_rate) hw_rate = AUDIO_DEFAULT_RATE;

    static uint64_t last = 0;
    uint64_t now = now_us_a();
    uint64_t budget = (uint64_t)FRAMES * 1000000ull / (uint64_t)hw_rate;
    if (last && now - last > budget * (uint64_t)NBUF) g_starved++;
    if (last){ uint64_t d = now - last; if (d > g_worst_gap_us) g_worst_gap_us = d; }
    last = now;

    mix_into((int16_t *)buf->mAudioData, FRAMES);
    buf->mAudioDataByteSize = FRAMES * OUT_CH * sizeof(int16_t);
    AudioQueueEnqueueBuffer(q, buf, 0, NULL);
}

/* RemoteIO AudioUnit Render Geri Cagirmasi (Ana Dusuk Gecikmeli Yol)
 * Priority Inversion Korumasi: Asla bekletici kilit almaz veya sistem cagrilarina takilmaz. */
static OSStatus au_cb(void *ud, AudioUnitRenderActionFlags *flags,
                      const AudioTimeStamp *ts, UInt32 bus, UInt32 nframes,
                      AudioBufferList *abl){
    (void)ud; (void)flags; (void)ts; (void)bus;
    if (!abl || abl->mNumberBuffers < 1 || !abl->mBuffers[0].mData) return noErr;

    /* Askiya alma veya rota rekonfigrasyonu sirasinda koruma: sessizlik ver ve don */
    if (atomic_load_explicit(&g_audio_suspended, memory_order_relaxed) ||
        atomic_load_explicit(&g_audio_reconfiguring, memory_order_relaxed) ||
        !atomic_load_explicit(&g_audio_on, memory_order_relaxed)){
        memset(abl->mBuffers[0].mData, 0, nframes * OUT_CH * sizeof(int16_t));
        abl->mBuffers[0].mDataByteSize = nframes * OUT_CH * sizeof(int16_t);
        return noErr;
    }

    static uint64_t last = 0;
    uint64_t now = now_us_a();
    if (last){ uint64_t d = now - last; if (d > g_worst_gap_us) g_worst_gap_us = d; }
    last = now;

    int16_t *out = (int16_t *)abl->mBuffers[0].mData;
    if (nframes > (UInt32)FRAMES) nframes = (UInt32)FRAMES;
    if (nframes > g_au_slice) g_au_slice = nframes;

    mix_into(out, (unsigned)nframes);
    abl->mBuffers[0].mDataByteSize = nframes * OUT_CH * sizeof(int16_t);
    return noErr;
}

#if TARGET_OS_IPHONE

/* --- iOS AVAudioSession ve Yasam Dongusu Gozlemcisi --- */
@interface NFSU2AudioLifecycleObserver : NSObject
@end

@implementation NFSU2AudioLifecycleObserver

- (instancetype)init {
    self = [super init];
    if (self) {
        NSNotificationCenter *nc = [NSNotificationCenter defaultCenter];
        AVAudioSession *session = [AVAudioSession sharedInstance];

        [nc addObserver:self
               selector:@selector(handleInterruption:)
                   name:AVAudioSessionInterruptionNotification
                 object:session];

        [nc addObserver:self
               selector:@selector(handleRouteChange:)
                   name:AVAudioSessionRouteChangeNotification
                 object:session];

        [nc addObserver:self
               selector:@selector(handleMediaReset:)
                   name:AVAudioSessionMediaServicesWereResetNotification
                 object:session];

#if !TARGET_OS_SIMULATOR && !TARGET_OS_MACCATALYST
        [nc addObserver:self
               selector:@selector(handleAppDidEnterBackground:)
                   name:UIApplicationDidEnterBackgroundNotification
                 object:nil];

        [nc addObserver:self
               selector:@selector(handleAppWillEnterForeground:)
                   name:UIApplicationWillEnterForegroundNotification
                 object:nil];
#endif
    }
    return self;
}

- (void)handleInterruption:(NSNotification *)note {
    NSDictionary *info = note.userInfo;
    if (!info) return;
    AVAudioSessionInterruptionType type = (AVAudioSessionInterruptionType)[[info objectForKey:AVAudioSessionInterruptionTypeKey] unsignedIntegerValue];

    if (type == AVAudioSessionInterruptionTypeBegan) {
        fprintf(stderr, "  [ses-ios] Kesinti basladi (Telefon/Alarm/Siri), ses guvenle durduruluyor\n");
        audio_ios_pause();
    } else if (type == AVAudioSessionInterruptionTypeEnded) {
        NSUInteger opts = [[info objectForKey:AVAudioSessionInterruptionOptionKey] unsignedIntegerValue];
        fprintf(stderr, "  [ses-ios] Kesinti bitti, surdurulme bayragi=%d\n",
                (opts & AVAudioSessionInterruptionOptionShouldResume) ? 1 : 0);
        if (opts & AVAudioSessionInterruptionOptionShouldResume) {
            audio_ios_resume();
        }
    }
}

- (void)handleRouteChange:(NSNotification *)note {
    NSDictionary *info = note.userInfo;
    if (!info) return;
    AVAudioSessionRouteChangeReason reason = (AVAudioSessionRouteChangeReason)[[info objectForKey:AVAudioSessionRouteChangeReasonKey] unsignedIntegerValue];
    fprintf(stderr, "  [ses-ios] Rota degisikligi algilandi (sebep: %u)\n", (unsigned)reason);

    AVAudioSession *session = [AVAudioSession sharedInstance];
    double currentHW = session.sampleRate;
    if (currentHW > 4000.0 && currentHW < 192000.0) {
        uint32_t target_rate = (uint32_t)round(currentHW);
        uint32_t current_rate = (uint32_t)atomic_load_explicit(&g_hw_rate, memory_order_relaxed);
        if (target_rate != current_rate) {
            fprintf(stderr, "  [ses-ios] Donanim ornekleme hizi degisimi: %u Hz -> %u Hz\n",
                    current_rate, target_rate);
            audio_ios_reconfigure_sample_rate(target_rate);
        }
    }
}

- (void)handleMediaReset:(NSNotification *)note {
    (void)note;
    fprintf(stderr, "  [ses-ios] KRITIK: audiod MediaServicesWereReset! Ses hatti bastan kuruluyor.\n");
    audio_ios_restart_subsystem();
}

#if !TARGET_OS_SIMULATOR && !TARGET_OS_MACCATALYST
- (void)handleAppDidEnterBackground:(NSNotification *)note {
    (void)note;
    fprintf(stderr, "  [ses-ios] Uygulama arka plana gecti, RemoteIO durduruluyor\n");
    audio_ios_pause();
}

- (void)handleAppWillEnterForeground:(NSNotification *)note {
    (void)note;
    fprintf(stderr, "  [ses-ios] Uygulama on plana dondu, RemoteIO canlandiriliyor\n");
    audio_ios_resume();
}
#endif

@end

static NFSU2AudioLifecycleObserver *g_lifecycle_observer = nil;

static int audio_setup_ios_session(void){
    @autoreleasepool {
        AVAudioSession *session = [AVAudioSession sharedInstance];
        NSError *err = nil;

        BOOL ok = [session setCategory:AVAudioSessionCategoryPlayback
                           withOptions:AVAudioSessionCategoryOptionMixWithOthers
                                 error:&err];
        if (!ok || err){
            fprintf(stderr, "  [ses-ios] AVAudioSession setCategory hatasi: %s\n",
                    err ? [[err localizedDescription] UTF8String] : "bilinmiyor");
            return 0;
        }

        /* 5-10 ms ultra dusuk gecikmeli donanim tamponu */
        [session setPreferredIOBufferDuration:0.008 error:&err];
        if (err) err = nil;

        /* Donanim ornekleme hizi tercihi: 44.1 kHz */
        [session setPreferredSampleRate:(double)AUDIO_DEFAULT_RATE error:&err];
        if (err) err = nil;

        ok = [session setActive:YES error:&err];
        if (!ok || err){
            fprintf(stderr, "  [ses-ios] AVAudioSession setActive hatasi: %s\n",
                    err ? [[err localizedDescription] UTF8String] : "bilinmiyor");
            return 0;
        }

        /* Gercek donanim ornekleme hizini sorgula (AirPods 48kHz, Dahili 44.1kHz/48kHz) */
        double actRate = session.sampleRate;
        if (actRate >= 4000.0 && actRate <= 192000.0){
            atomic_store_explicit(&g_hw_rate, (uint32_t)round(actRate), memory_order_relaxed);
        } else {
            atomic_store_explicit(&g_hw_rate, AUDIO_DEFAULT_RATE, memory_order_relaxed);
        }

        fprintf(stderr, "  [ses-ios] AVAudioSession baslatildi (Gercek Donanim: %u Hz, IO: %.1f ms)\n",
                (uint32_t)atomic_load_explicit(&g_hw_rate, memory_order_relaxed),
                session.IOBufferDuration * 1000.0);

        if (!g_lifecycle_observer){
            g_lifecycle_observer = [[NFSU2AudioLifecycleObserver alloc] init];
        }
        return 1;
    }
}
#endif

/* RemoteIO AudioUnit Baslatma */
static int au_start(uint32_t rate){
    AudioComponentDescription d;
    memset(&d, 0, sizeof d);
    d.componentType         = kAudioUnitType_Output;
#if TARGET_OS_IPHONE
    d.componentSubType      = kAudioUnitSubType_RemoteIO;
#else
    d.componentSubType      = kAudioUnitSubType_DefaultOutput;
#endif
    d.componentManufacturer = kAudioUnitManufacturer_Apple;

    AudioComponent comp = AudioComponentFindNext(NULL, &d);
    if (!comp) return 0;
    if (AudioComponentInstanceNew(comp, &g_au) != noErr) return 0;

#if TARGET_OS_IPHONE
    {
        UInt32 enableOutput = 1;
        AudioUnitSetProperty(g_au, kAudioOutputUnitProperty_EnableIO,
                             kAudioUnitScope_Output, 0, &enableOutput, sizeof enableOutput);
    }
#endif

    AudioStreamBasicDescription f;
    memset(&f, 0, sizeof f);
    f.mSampleRate       = (double)rate;
    f.mFormatID         = kAudioFormatLinearPCM;
    f.mFormatFlags      = kAudioFormatFlagIsSignedInteger | kAudioFormatFlagIsPacked;
    f.mChannelsPerFrame = OUT_CH;
    f.mBitsPerChannel   = 16;
    f.mFramesPerPacket  = 1;
    f.mBytesPerFrame    = OUT_CH * sizeof(int16_t);
    f.mBytesPerPacket   = f.mBytesPerFrame;

    if (AudioUnitSetProperty(g_au, kAudioUnitProperty_StreamFormat,
                             kAudioUnitScope_Input, 0, &f, sizeof f) != noErr) goto fail;

    {
        UInt32 mx = FRAMES;
        AudioUnitSetProperty(g_au, kAudioUnitProperty_MaximumFramesPerSlice,
                             kAudioUnitScope_Global, 0, &mx, sizeof mx);
    }

    {
        AURenderCallbackStruct rc;
        rc.inputProc = au_cb;
        rc.inputProcRefCon = NULL;
        if (AudioUnitSetProperty(g_au, kAudioUnitProperty_SetRenderCallback,
                                 kAudioUnitScope_Input, 0, &rc, sizeof rc) != noErr) goto fail;
    }

    if (AudioUnitInitialize(g_au) != noErr) goto fail;
    if (AudioOutputUnitStart(g_au) != noErr){
        AudioUnitUninitialize(g_au);
        goto fail;
    }
    return 1;

fail:
    if (g_au){
        AudioComponentInstanceDispose(g_au);
        g_au = NULL;
    }
    return 0;
}

/* --- Yasam Dongusu API Fonksiyonlari --- */

void audio_ios_pause(void){
    atomic_store_explicit(&g_audio_suspended, true, memory_order_release);
    if (g_backend == 1 && g_au){
        AudioOutputUnitStop(g_au);
    } else if (g_backend == 2 && g_q){
        AudioQueuePause(g_q);
    }
}

void audio_ios_resume(void){
#if TARGET_OS_IPHONE
    @autoreleasepool {
        NSError *err = nil;
        [[AVAudioSession sharedInstance] setActive:YES error:&err];
    }
#endif
    if (g_backend == 1 && g_au){
        AudioOutputUnitStart(g_au);
    } else if (g_backend == 2 && g_q){
        AudioQueueStart(g_q, NULL);
    }
    atomic_store_explicit(&g_audio_suspended, false, memory_order_release);
}

void audio_ios_reconfigure_sample_rate(uint32_t new_rate){
    if (new_rate < 4000u || new_rate > 192000u) return;
    if (g_backend != 1 || !g_au) {
        atomic_store_explicit(&g_hw_rate, new_rate, memory_order_relaxed);
        return;
    }

    atomic_store_explicit(&g_audio_reconfiguring, true, memory_order_release);

    AudioOutputUnitStop(g_au);
    AudioUnitUninitialize(g_au);

    atomic_store_explicit(&g_hw_rate, new_rate, memory_order_release);

    AudioStreamBasicDescription f;
    memset(&f, 0, sizeof f);
    f.mSampleRate       = (double)new_rate;
    f.mFormatID         = kAudioFormatLinearPCM;
    f.mFormatFlags      = kAudioFormatFlagIsSignedInteger | kAudioFormatFlagIsPacked;
    f.mChannelsPerFrame = OUT_CH;
    f.mBitsPerChannel   = 16;
    f.mFramesPerPacket  = 1;
    f.mBytesPerFrame    = OUT_CH * sizeof(int16_t);
    f.mBytesPerPacket   = f.mBytesPerFrame;

    AudioUnitSetProperty(g_au, kAudioUnitProperty_StreamFormat,
                         kAudioUnitScope_Input, 0, &f, sizeof f);

    AudioUnitInitialize(g_au);
    AudioOutputUnitStart(g_au);

    atomic_store_explicit(&g_audio_reconfiguring, false, memory_order_release);
    fprintf(stderr, "  [ses-ios] RemoteIO hatti %u Hz icin basariyla guncellendi\n", new_rate);
}

void audio_ios_restart_subsystem(void){
    atomic_store_explicit(&g_audio_reconfiguring, true, memory_order_release);
    audio_shutdown();
    audio_init();
    atomic_store_explicit(&g_audio_reconfiguring, false, memory_order_release);
}

/* --- Ana Baslatma ve Kapatma Fonksiyonlari --- */

void audio_init(void){
    if (atomic_load_explicit(&g_audio_on, memory_order_relaxed)) return;
    { const char *e = getenv("NOSOUND"); if (e && *e && *e != '0') return; }

    /* Ring buffer baslat */
    audio_ringbuf_init(&g_stream_rb, AUDIO_RING_FRAMES, OUT_CH);

#if TARGET_OS_IPHONE
    if (!audio_setup_ios_session()){
        fprintf(stderr, "ses: iOS AVAudioSession baslatilamadi, ses devre disi\n");
        return;
    }
#endif

    uint32_t hw_rate = (uint32_t)atomic_load_explicit(&g_hw_rate, memory_order_relaxed);
    if (!hw_rate) hw_rate = AUDIO_DEFAULT_RATE;

    { const char *d = getenv("SNDDUMP");
      if (d && *d){ g_dump = fopen(d, "wb");
          fprintf(stderr, "ses: cikis dokumu -> %s (%d Hz s16le %d kanal)\n", d, hw_rate, OUT_CH); } }
    { const char *d = getenv("SNDCSV");
      if (d && *d){ g_csv = fopen(d, "w");
          if (g_csv) fprintf(g_csv, "cb,t,id,rate,bytes,pbyte,wpos,avail,frac,target,trim,ratio,zero\n"); } }

    /* SNDBACKEND=queue ile AudioQueue yedek yoluna donulebilir */
    {
        const char *e = getenv("SNDBACKEND");
        if (!(e && *e == 'q') && au_start(hw_rate)){
            g_backend = 1;
            atomic_store_explicit(&g_audio_on, true, memory_order_release);
            fprintf(stderr, "ses: CoreAudio cikisi acildi (AudioUnit RemoteIO, %d Hz, %d kanal)\n",
                    hw_rate, OUT_CH);
            return;
        }
    }

    AudioStreamBasicDescription f;
    memset(&f, 0, sizeof f);
    f.mSampleRate       = hw_rate;
    f.mFormatID         = kAudioFormatLinearPCM;
    f.mFormatFlags      = kAudioFormatFlagIsSignedInteger | kAudioFormatFlagIsPacked;
    f.mChannelsPerFrame = OUT_CH;
    f.mBitsPerChannel   = 16;
    f.mFramesPerPacket  = 1;
    f.mBytesPerFrame    = OUT_CH * sizeof(int16_t);
    f.mBytesPerPacket   = f.mBytesPerFrame;

    if (AudioQueueNewOutput(&f, cb, NULL, NULL, NULL, 0, &g_q) != noErr){
        fprintf(stderr, "ses: AudioQueue acilamadi\n");
        return;
    }
    for (int i = 0; i < NBUF; i++){
        if (AudioQueueAllocateBuffer(g_q, FRAMES * OUT_CH * sizeof(int16_t), &g_qb[i]) != noErr)
            continue;
        memset(g_qb[i]->mAudioData, 0, FRAMES * OUT_CH * sizeof(int16_t));
        g_qb[i]->mAudioDataByteSize = FRAMES * OUT_CH * sizeof(int16_t);
        AudioQueueEnqueueBuffer(g_q, g_qb[i], 0, NULL);
    }
    AudioQueueSetParameter(g_q, kAudioQueueParam_Volume, 1.0f);
    if (AudioQueueStart(g_q, NULL) != noErr){
        fprintf(stderr, "ses: AudioQueue baslatilamadi\n");
        return;
    }
    g_backend = 2;
    atomic_store_explicit(&g_audio_on, true, memory_order_release);
    fprintf(stderr, "ses: CoreAudio cikisi acildi (AudioQueue, %d Hz, %d kanal)\n",
            hw_rate, OUT_CH);
}

void audio_shutdown(void){
    atomic_store_explicit(&g_audio_on, false, memory_order_release);
    if (g_backend == 1 && g_au){
        AudioOutputUnitStop(g_au);
        AudioUnitUninitialize(g_au);
        AudioComponentInstanceDispose(g_au);
        g_au = NULL;
    } else if (g_backend == 2 && g_q){
        AudioQueueStop(g_q, true);
        AudioQueueDispose(g_q, true);
        g_q = NULL;
    }
    audio_ringbuf_destroy(&g_stream_rb);
    g_backend = 0;
}

void audio_report(void){
    if (g_dump){ fflush(g_dump); fclose(g_dump); g_dump = NULL; }
    if (g_csv){  fflush(g_csv);  fclose(g_csv);  g_csv  = NULL; }
    uint32_t hw_rate = (uint32_t)atomic_load_explicit(&g_hw_rate, memory_order_relaxed);
    if (!hw_rate) hw_rate = AUDIO_DEFAULT_RATE;

    fprintf(stderr, "  ses cikisi        : %s (Donanim: %u Hz), %llu kare karistirildi, "
            "en fazla %llu es zamanli tampon, %d kayitli\n",
            atomic_load_explicit(&g_audio_on, memory_order_relaxed) ? "acik" : "KAPALI",
            hw_rate,
            (unsigned long long)g_mixed_frames,
            (unsigned long long)g_active_peak, g_sndn - 1);
    fprintf(stderr, "  ses Play cagrisi  : %llu bastan basladi, %llu zaten caliyordu\n",
            (unsigned long long)g_replay, (unsigned long long)g_reissue);
    fprintf(stderr, "  ses hiz orani    : %.3f (oyun sanal zamani / gercek zaman)%s\n",
            g_rate_ratio, g_sync_mode ? "" : "  [SNDSYNC=0: kapali]");
    fprintf(stderr, "  ses veri boslugu  : ornek %.1f%% sessiz, %llu geri-cagirmanin cogu bos\n",
            g_out_frames ? 100.0*(double)g_out_zero/(double)g_out_frames : 0.0,
            (unsigned long long)g_gap_cb);
    fprintf(stderr, "  --- ses tamponu basina ---\n");
    for (int i = 1; i < g_sndn; i++){
        SndBuf *b = &g_snd[i];
        if (!b->used) continue;
        fprintf(stderr, "   #%-3d %6u Hz %uch %5.2f sn  Play=%-4llu Stop=%-4llu  "
                "yazma=%llu (%llu dolu, %.1f KB)  %s\n",
                i, b->rate, b->chans,
                (double)b->bytes/(double)(b->rate*b->chans*(b->bits/8u)),
                (unsigned long long)b->plays, (unsigned long long)b->stops,
                (unsigned long long)b->wr_calls, (unsigned long long)b->wr_nonzero,
                b->wr_bytes/1024.0, b->playing ? "CALIYOR" : "durdu");
    }
    {
        uint64_t ov = 0;
        for (int i = 1; i < g_sndn; i++) ov += g_snd[i].over;
        fprintf(stderr, "  ses imlec asimi   : %llu geri-cagirmada oynatma yaziciyi gecti\n",
                (unsigned long long)ov);
    }
    fprintf(stderr, "  ses cikis yolu    : %s, geri cagirma %u kare (%.1f ms kuyruk gecikmesi)\n",
            g_backend == 1 ? "AudioUnit RemoteIO" : g_backend == 2 ? "AudioQueue" : "yok",
            g_backend == 1 ? g_au_slice : (unsigned)(FRAMES*NBUF),
            (g_backend == 1 ? (double)g_au_slice : (double)(FRAMES*NBUF))
                * 1000.0 / (double)hw_rate);
    fprintf(stderr, "  ses kesilmesi     : %llu aclik, en uzun geri-cagirma araligi %.1f ms"
            " (tampon %.1f ms)\n",
            (unsigned long long)g_starved, g_worst_gap_us/1000.0,
            (double)FRAMES*NBUF*1000.0/(double)hw_rate);
}
