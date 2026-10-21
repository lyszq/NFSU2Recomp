/* NFSU2 iOS Port - Audio Subsystem Header
 *
 * CoreAudio / RemoteIO / DirectSound emulasyon katmani arayuzu.
 * EA Trax (muzik akisi), SFX (ses efektleri), ve motor sesleri icin
 * dusuk gecikmeli, cift tamponlu (ring buffer) ve ornekleme hizi
 * uyarlamali (44.1 kHz / 48 kHz) ses mimarisi.
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

/* --- Kilit-Serbest (Lock-Free) SPSC Dairesel Tampon (Ring Buffer) ---
 * Real-time CoreAudio render is parcacigi ile oyun thread'ini birbirinden
 * tamamen ayirir (priority inversion ve ses teklemelerini onler). */
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
int      audio_register(uint32_t data, uint32_t bytes, uint32_t rate, uint32_t chans, uint32_t bits);
void     audio_play(int id, int loop);
void     audio_stop(int id);
uint32_t audio_cursor(int id);
void     audio_cursors(int id, uint32_t *play, uint32_t *write);
void     audio_set_volume(int id, long millibel);
void     audio_set_freq(int id, uint32_t hz);
int      audio_duplicate(int src);
void     audio_note_write(int id, uint32_t end_off);
void     audio_note_write_stat(int id, uint32_t n, int nonzero);
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
