/* NFSU2 iOS Port - Audio Subsystem Header
 *
 * CoreAudio / RemoteIO / DirectSound emulasyon katmani arayuzu.
 * EA Trax (muzik akisi), SFX (ses efektleri), ve motor sesleri icin
 * 44.1 kHz / 48 kHz donanim cikis hizina uyumlanan ses katmani. Uretim
 * karistiricisi konuk PCM yazilarini Unlock sonrasinda yayinlanan host aynasindan
 * okur; ring-buffer API'si su an render yolunda kullanilmaz.
 */

#ifndef NFSU2_AUDIO_H
#define NFSU2_AUDIO_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdatomic.h>

#ifdef __cplusplus
extern "C" {
#endif

#define AUDIO_DEFAULT_RATE    44100u
#define AUDIO_BT_RATE         48000u
#define AUDIO_OUT_CHANNELS    2u
#define AUDIO_MAX_BUFFERS     128
#define AUDIO_RING_FRAMES     8192u     /* Lock-free ring buffer boyutu (2'nin kuvveti) */
#define AUDIO_SNAPSHOT_MAX_BUFFERS 16u  /* Status timer icin sinirli snapshot listesi */

/* IDirectSoundBuffer::GetStatus result bits used by the COM adapter. */
#define AUDIO_STATUS_PLAYING  0x00000001u
#define AUDIO_STATUS_LOOPING  0x00000004u

/* Per-buffer values are a bounded observational snapshot, not an underrun
 * classification. DuplicateSoundBuffer entries share a storage_id and expose
 * the shared PCM write history. write_bytes_reported is the total byte count
 * published from both Unlock regions. Age and gap are producer timing
 * observations, not underrun evidence or proof that an active loop is static.
 * last_write_age_us is zero until a producer write timestamp is observed. */
typedef struct {
    uint32_t id;
    uint32_t storage_id;
    uint32_t size_bytes;
    uint32_t rate;
    uint32_t channels;
    uint32_t bits;
    uint32_t active;
    uint32_t looping;
    uint32_t write_seen;
    uint32_t play_cursor_bytes;
    uint32_t write_cursor_bytes;
    uint32_t write_end_offset;
    uint32_t last_write_bytes_reported;
    uint64_t write_calls;
    uint64_t write_bytes_reported;
    uint64_t last_write_age_us;
    uint64_t max_write_gap_us;
} AudioBufferSnapshot;

/* Bounded, nonblocking buffer and callback diagnostics for the app status log. */
typedef struct {
    uint64_t active_buffers;
    uint64_t plays;
    uint64_t reissues;
    uint64_t stops;
    uint64_t write_calls;
    uint32_t hardware_rate;
    uint32_t buffer_count;
    uint32_t buffers_captured;
    uint32_t buffers_omitted;
    uint32_t callback_max_frames;
    uint64_t callback_count;
    uint64_t callback_gap_max_us;
    uint64_t callback_duration_max_us;
    uint64_t callback_late_count;
    uint64_t callback_over_budget_count;
    uint64_t mirror_bytes;       /* committed unique host PCM bytes */
    uint64_t publish_calls;
    uint64_t publish_bytes;
    uint64_t publish_max_ns;     /* max wall time incl. mutex wait and copy */
    uint64_t rejected_writes;    /* invalid IDs or Unlock spans */
    AudioBufferSnapshot buffers[AUDIO_SNAPSHOT_MAX_BUFFERS];
} AudioSnapshot;

/* --- Kilit-Serbest SPSC Dairesel Tampon yardimcisi ---
 * Bu API mevcut production render yolundan bagimsizdir. */
typedef struct {
    int16_t        *buffer;             /* Interleaved 16-bit PCM stereo */
    size_t          capacity_frames;    /* 2'nin kuvveti */
    size_t          mask;
    atomic_size_t   write_pos;          /* Uretici yazma konumu (frame) */
    atomic_size_t   read_pos;           /* Tuketici okuma konumu (frame) */
    uint32_t        channels;
} AudioRingBuffer;

bool   audio_ringbuf_init(AudioRingBuffer *rb, size_t capacity_frames, uint32_t channels);
void   audio_ringbuf_destroy(AudioRingBuffer *rb);
size_t audio_ringbuf_available_read(const AudioRingBuffer *rb);
size_t audio_ringbuf_available_write(const AudioRingBuffer *rb);
size_t audio_ringbuf_write(AudioRingBuffer *rb, const int16_t *src, size_t frames);
size_t audio_ringbuf_read(AudioRingBuffer *rb, int16_t *dst, size_t frames);
void   audio_ringbuf_reset(AudioRingBuffer *rb);

/* --- DirectSound COM Katmani Temel API --- */
void     audio_init(void);
void     audio_shutdown(void);
int      audio_is_active(void);
/* Cheap advisory preflight before allocating guest/COM storage. Registration
 * still reserves and rechecks its own budget; this call makes no reservation. */
int      audio_registration_available(uint32_t bytes);
int      audio_register(uint32_t data, uint32_t bytes, uint32_t rate, uint32_t chans, uint32_t bits);
void     audio_play(int id, int loop);
void     audio_stop(int id);
int      audio_set_position(int id, uint32_t byte_pos);
uint32_t audio_status(int id);
int      audio_snapshot(AudioSnapshot *out);
uint32_t audio_cursor(int id);
void     audio_cursors(int id, uint32_t *play, uint32_t *write);
void     audio_set_volume(int id, long millibel);
void     audio_set_freq(int id, uint32_t hz);
uint32_t audio_get_freq(int id);
int      audio_duplicate(int src);
void     audio_note_write(int id, uint32_t end_off);
void     audio_note_write_stat(int id, uint32_t n, int nonzero);
/* Publish actual DirectSound Unlock regions from guest PCM into the host mirror.
 * Caller holds the guest GIL and validates both guest RAM spans. This API also
 * validates both offsets against the registered buffer before either copy.
 * nonzero_sample is diagnostic-only: positive means sampled nonzero PCM, zero
 * means sampled silence, and negative means unknown. Returns 1 on success. */
int      audio_publish_write(int id, uint32_t p1, uint32_t n1,
                             uint32_t p2, uint32_t n2, int nonzero_sample);
double   audio_time(void);
void     audio_report(void);

/* --- iOS AVAudioSession ve Donanim Yasam Dongusu API --- */
void     audio_ios_pause(void);
void     audio_ios_resume(void);
void     audio_ios_reconfigure_sample_rate(uint32_t new_rate);
void     audio_ios_restart_subsystem(void);
uint32_t audio_get_hardware_rate(void);
int      audio_is_suspended(void);

#ifdef __cplusplus
}
#endif

#endif /* NFSU2_AUDIO_H */
