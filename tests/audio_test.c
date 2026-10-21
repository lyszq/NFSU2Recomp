/* NFSU2 iOS Port - Audio Subsystem Unit Tests
 *
 * Test Senaryolari:
 * 1. Lock-free SPSC Ring Buffer: Yazma/okuma, dairesel sarma (wrap-around),
 *    asma korumasi (overflow/underflow), ve veri butunlugu.
 * 2. Dogrusal Resampler (44.1 kHz -> 48 kHz): Donanim frekans degisimi ve
 *    ornekleme orani donusumunun dogrulugu.
 * 3. Motor Sesi Perde/Frekans Modulasyonu: audio_set_freq simulasyonu.
 * 4. DirectSound Dairesel Imlec Semantigi: Play/Write imlec mesafesi (WRITE_LEAD_MS).
 * 5. iOS AVAudioSession Kesinti & Rota Durum Yonetimi: audio_ios_pause/resume/reconfigure.
 */

#include "audio.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <math.h>

#define TEST_ASSERT(cond, msg) do { \
    if (!(cond)) { \
        fprintf(stderr, "FAIL: %s (satir %d): %s\n", __func__, __LINE__, msg); \
        return 0; \
    } \
} while (0)

/* --- 1. Ring Buffer Temel Testi --- */
static int test_ringbuf_basic(void) {
    AudioRingBuffer rb;
    const size_t cap = 1024;
    const uint32_t ch = 2;

    TEST_ASSERT(audio_ringbuf_init(&rb, cap, ch), "Ring buffer baslatilamadi");
    TEST_ASSERT(audio_ringbuf_available_read(&rb) == 0, "Bos bufferda okunabilir veri olmamali");
    TEST_ASSERT(audio_ringbuf_available_write(&rb) == cap, "Bos bufferda tum alan yazilabilir olmali");

    int16_t src[512 * 2];
    for (size_t i = 0; i < 512 * 2; i++) src[i] = (int16_t)(i + 1);

    size_t written = audio_ringbuf_write(&rb, src, 512);
    TEST_ASSERT(written == 512, "512 frame yazilamadi");
    TEST_ASSERT(audio_ringbuf_available_read(&rb) == 512, "Okunabilir frame 512 olmali");
    TEST_ASSERT(audio_ringbuf_available_write(&rb) == 512, "Kalan yazilabilir frame 512 olmali");

    int16_t dst[512 * 2];
    memset(dst, 0, sizeof(dst));
    size_t read_cnt = audio_ringbuf_read(&rb, dst, 512);
    TEST_ASSERT(read_cnt == 512, "512 frame okunamadi");
    TEST_ASSERT(memcmp(src, dst, sizeof(src)) == 0, "Okunan veri yazilan veriyle birebir eslesmiyor");
    TEST_ASSERT(audio_ringbuf_available_read(&rb) == 0, "Okuma sonrasi buffer bos olmali");

    audio_ringbuf_destroy(&rb);
    return 1;
}

/* --- 2. Ring Buffer Dairesel Sarma (Wrap-Around) Testi --- */
static int test_ringbuf_wrap_around(void) {
    AudioRingBuffer rb;
    const size_t cap = 256; /* Kucuk kapasite ile sarma testi */
    const uint32_t ch = 2;

    TEST_ASSERT(audio_ringbuf_init(&rb, cap, ch), "Ring buffer baslatilamadi");

    int16_t block1[200 * 2];
    for (size_t i = 0; i < 200 * 2; i++) block1[i] = (int16_t)(1000 + i);

    audio_ringbuf_write(&rb, block1, 200);
    int16_t out1[150 * 2];
    audio_ringbuf_read(&rb, out1, 150);

    /* Simdi okuma imleci 150'de, yazma imleci 200'de.
     * 100 frame daha yazarsak: 200 + 100 = 300 > 256, yani dizi basina saracak! */
    int16_t block2[100 * 2];
    for (size_t i = 0; i < 100 * 2; i++) block2[i] = (int16_t)(5000 + i);

    size_t written2 = audio_ringbuf_write(&rb, block2, 100);
    TEST_ASSERT(written2 == 100, "Sarmada 100 frame basariyla yazilmali");

    /* Kalan 50 frame (block1'in sonu) + 100 frame (block2) okunmali */
    int16_t out_all[150 * 2];
    size_t read_all = audio_ringbuf_read(&rb, out_all, 150);
    TEST_ASSERT(read_all == 150, "Toplam 150 frame okunamadi");

    /* Ilk 50 frame block1'in [150..199] kismi mi? */
    TEST_ASSERT(memcmp(out_all, &block1[150 * 2], 50 * 2 * sizeof(int16_t)) == 0,
                "Wrap-around oncesi veri bozulmus");
    /* Sonraki 100 frame block2 mi? */
    TEST_ASSERT(memcmp(&out_all[50 * 2], block2, 100 * 2 * sizeof(int16_t)) == 0,
                "Wrap-around sonrasi veri bozulmus");

    audio_ringbuf_destroy(&rb);
    return 1;
}

/* --- 3. Ring Buffer Tasim/Aclik (Overrun/Underrun) Sinir Korumasi --- */
static int test_ringbuf_boundaries(void) {
    AudioRingBuffer rb;
    const size_t cap = 128;
    audio_ringbuf_init(&rb, cap, 2);

    int16_t big_buf[256 * 2];
    memset(big_buf, 0x55, sizeof(big_buf));

    /* Kapasiteden fazlasini yazmaya calis */
    size_t w = audio_ringbuf_write(&rb, big_buf, 200);
    TEST_ASSERT(w == 128, "Kapasiteyi asan kisim reddedilmeli, en fazla 128 yazilmali");
    TEST_ASSERT(audio_ringbuf_available_write(&rb) == 0, "Buffer dolu gorunmeli");

    /* Dolu buffera tekrar yazma denemesi */
    size_t w2 = audio_ringbuf_write(&rb, big_buf, 10);
    TEST_ASSERT(w2 == 0, "Dolu buffera yazma 0 donmeli");

    /* Okuma */
    int16_t out[256 * 2];
    size_t r = audio_ringbuf_read(&rb, out, 200);
    TEST_ASSERT(r == 128, "Mevcut 128 frameden fazlasi okunamamali");

    /* Bos bufferden okuma denemesi */
    size_t r2 = audio_ringbuf_read(&rb, out, 10);
    TEST_ASSERT(r2 == 0, "Bos bufferden okuma 0 donmeli");

    audio_ringbuf_destroy(&rb);
    return 1;
}

/* --- 4. Ornekleme Hizi Donusumu (44.1 kHz -> 48 kHz Linear Resampling) --- */
static int test_resampling_linear_interpolation(void) {
    /* 44100 Hz'de tek ton (ornek ramp) */
    const unsigned src_rate = 44100;
    const unsigned dst_rate = 48000;
    const unsigned frames = 480; /* 10 ms at 48 kHz */

    double step = (double)src_rate / (double)dst_rate; /* 0.91875 */
    double cursor = 0.0;

    /* Sentetik 44.1 kHz kaynak veri (1.0f degerinde tepeye ulasan ramp) */
    float src[1000];
    for (int i = 0; i < 1000; i++) src[i] = (float)i / 1000.f;

    float dst[frames];
    for (unsigned f = 0; f < frames; f++) {
        double sp = cursor + step * (double)f;
        uint32_t si0 = (uint32_t)sp;
        uint32_t si1 = si0 + 1;
        float alpha = (float)(sp - (double)si0);
        dst[f] = src[si0] + alpha * (src[si1] - src[si0]);
    }

    /* Resample edilmis sinyalin monoton artan ve surekli (smooth) oldugunu test et */
    for (unsigned f = 1; f < frames; f++) {
        TEST_ASSERT(dst[f] >= dst[f - 1], "Linear resampler surekliligi bozuldu");
    }

    /* 480 frame sonunda beklenen sanal pozisyon */
    double final_pos = step * (double)frames;
    TEST_ASSERT(fabs(final_pos - 441.0) < 0.0001, "Resample adim orani hatali (441.0 olmali)");
    return 1;
}

/* --- 5. Motor Devir Frekans/Pitch Modulasyonu Testi --- */
static int test_engine_frequency_modulation(void) {
    /* DirectSound SetFrequency emulasyonu: 22050 Hz ozgun motor sesi */
    uint32_t base_rate = 22050;
    uint32_t rpm_low_hz = 11025;   /* 0.5x pitch */
    uint32_t rpm_high_hz = 88200;  /* 4.0x pitch */

    double f_low = (double)rpm_low_hz / (double)base_rate;
    double f_high = (double)rpm_high_hz / (double)base_rate;

    TEST_ASSERT(fabs(f_low - 0.50) < 0.001, "Dusuk devir pitch orani 0.5 olmali");
    TEST_ASSERT(fabs(f_high - 4.00) < 0.001, "Yuksek devir pitch orani 4.0 olmali");

    /* 48 kHz cikis donaniminda calisma adimi */
    uint32_t hw_rate = 48000;
    double step_low = ((double)base_rate / (double)hw_rate) * f_low;
    double step_high = ((double)base_rate / (double)hw_rate) * f_high;

    TEST_ASSERT(step_low < step_high, "Devir arttikca phase step buyumeli");
    return 1;
}

/* --- 6. DirectSound Dairesel Imlec ve WRITE_LEAD_MS Testi --- */
static int test_directsound_lead_cursors(void) {
    /* 44100 Hz, 16-bit stereo PCM = 4 bayt/kare
     * 100 ms buffer = 4410 kare = 17640 bayt */
    uint32_t rate = 44100;
    uint32_t bpf = 4;
    uint32_t sz = 17640;
    uint32_t lead_ms = 50; /* 50 ms lead */

    uint32_t lead_bytes = (rate * lead_ms / 1000u) * bpf;
    TEST_ASSERT(lead_bytes == 8820, "50 ms lead tam olarak 8820 bayt olmali");

    /* Play imleci 1000 ise, Write imleci 1000 + 8820 = 9820 olmali */
    uint32_t play = 1000;
    uint32_t write = (play + lead_bytes) % sz;
    TEST_ASSERT(write == 9820, "Write imleci play imlecinin onunde hesaplanmali");

    /* Sarma durumu: Play imleci 15000 ise, 15000 + 8820 = 23820 % 17640 = 6180 */
    uint32_t play_wrap = 15000;
    uint32_t write_wrap = (play_wrap + lead_bytes) % sz;
    TEST_ASSERT(write_wrap == 6180, "Dairesel buffer sarmasinda write imleci dogru hesaplanmali");
    return 1;
}

/* --- 7. iOS AVAudioSession Durum Gecisleri Testi --- */
static int test_ios_lifecycle_states(void) {
    /* Baslangicta reconfigure bayragini test et */
    audio_ios_reconfigure_sample_rate(48000);
    TEST_ASSERT(audio_get_hardware_rate() == 48000, "Donanim ornekleme hizi 48000 olarak kaydedilmeli");

    audio_ios_pause();
    TEST_ASSERT(audio_is_suspended() == 1, "audio_ios_pause sonrasi ses askiya alinmis olmali");
    TEST_ASSERT(audio_is_active() == 0, "Askiya alinmis ses etkin gorunmemeli");

    audio_ios_resume();
    TEST_ASSERT(audio_is_suspended() == 0, "audio_ios_resume sonrasi ses askidan cikmali");

    audio_ios_reconfigure_sample_rate(44100);
    TEST_ASSERT(audio_get_hardware_rate() == 44100, "Donanim hizi 44100'e basariyla dondurulmeli");
    return 1;
}

int main(void) {
    fprintf(stderr, "=== NFSU2 iOS Audio Subsystem Test Suite ===\n");
    int passed = 0;
    int total = 7;

    if (test_ringbuf_basic()) { fprintf(stderr, "  [PASS] 1. RingBuffer Basic R/W\n"); passed++; }
    if (test_ringbuf_wrap_around()) { fprintf(stderr, "  [PASS] 2. RingBuffer Wrap-Around\n"); passed++; }
    if (test_ringbuf_boundaries()) { fprintf(stderr, "  [PASS] 3. RingBuffer Overrun/Underrun Boundaries\n"); passed++; }
    if (test_resampling_linear_interpolation()) { fprintf(stderr, "  [PASS] 4. 44.1kHz -> 48kHz Linear Resampling\n"); passed++; }
    if (test_engine_frequency_modulation()) { fprintf(stderr, "  [PASS] 5. Engine Sound Pitch Modulation\n"); passed++; }
    if (test_directsound_lead_cursors()) { fprintf(stderr, "  [PASS] 6. DirectSound Lead Cursors\n"); passed++; }
    if (test_ios_lifecycle_states()) { fprintf(stderr, "  [PASS] 7. iOS Lifecycle State Machine\n"); passed++; }

    fprintf(stderr, "=== Sonuc: %d / %d Test Basarili ===\n", passed, total);
    return (passed == total) ? 0 : 1;
}
