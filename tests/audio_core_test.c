/* Deterministic tests for the real mixer/API. The included audio.m keeps
 * static render state visible here without adding a shipping test hook. */
#define NFSU2_AUDIO_CORE_TEST 1
#include "../runtime/audio.m"
#include <assert.h>

uint8_t *g_mem;

#define TEST_MEM_SIZE (2u * 1024u * 1024u)
#define TEST_DATA_A   256u
#define TEST_DATA_B   131072u

static void reset_audio(uint32_t hw_rate){
    pthread_mutex_lock(&g_slock);
    memset(g_snd, 0, sizeof(g_snd));
    g_sndn = 1;
    pthread_mutex_unlock(&g_slock);
    atomic_store_explicit(&g_hw_rate, hw_rate, memory_order_relaxed);
    atomic_store_explicit(&g_audio_on, false, memory_order_relaxed);
    atomic_store_explicit(&g_audio_suspended, false, memory_order_relaxed);
    atomic_store_explicit(&g_audio_reconfiguring, false, memory_order_relaxed);
    g_rate_ratio = 1.0;
    g_sync_mode = -1;
    g_mixed_frames = g_active_peak = 0;
    g_replay = g_reissue = g_starved = g_worst_gap_us = 0;
    g_late_callbacks = g_out_frames = g_out_zero = g_gap_cb = 0;
    g_cb_no = 0;
    g_backend = 0;
    g_au_slice = 0;
    g_dump = NULL;
    g_csv = NULL;
}

static int16_t marker_sample(unsigned index){
    return (int16_t)(1000 + (int)index * 300);
}

static void write_mono16(uint32_t offset, const int16_t *src, size_t count){
    assert((size_t)offset + count * sizeof(*src) <= TEST_MEM_SIZE);
    memcpy(g_mem + offset, src, count * sizeof(*src));
}

static void assert_output_sample(const int16_t *out, unsigned frame, int16_t input){
    int expected = (int)(((float)input / 32768.f) * 32767.f);
    int left = out[frame * 2u];
    int right = out[frame * 2u + 1u];
    assert(abs(left - expected) <= 1);
    assert(left == right);
}

static void test_stop_resume_and_seek(void){
    int16_t pcm[32];
    for (unsigned i = 0; i < 32; i++) pcm[i] = marker_sample(i);
    write_mono16(TEST_DATA_A, pcm, 32);
    reset_audio(44100);
    int id = audio_register(TEST_DATA_A, sizeof(pcm), 44100, 1, 16);
    assert(id > 0);

    int16_t out[16] = {0};
    audio_play(id, 0);
    assert(audio_status(id) == AUDIO_STATUS_PLAYING);
    mix_into(out, 4);
    assert(audio_cursor(id) == 8u);
    audio_stop(id);
    assert(audio_status(id) == 0u);
    uint32_t stopped_play = UINT32_MAX, stopped_write = UINT32_MAX;
    audio_cursors(id, &stopped_play, &stopped_write);
    assert(stopped_play == 8u);
    audio_play(id, 0);
    mix_into(out, 1);
    assert_output_sample(out, 0, pcm[4]);
    assert(audio_cursor(id) == 10u);

    audio_stop(id);
    assert(audio_set_position(id, 0u));
    assert(audio_cursor(id) == 0u);
    audio_play(id, 0);
    mix_into(out, 1);
    assert_output_sample(out, 0, pcm[0]);

    /* SetCurrentPosition also takes effect while the buffer is playing. */
    assert(audio_set_position(id, 20u));
    mix_into(out, 1);
    assert_output_sample(out, 0, pcm[10]);
    audio_stop(id);
    assert(audio_set_position(id, 24u));
    assert(audio_cursor(id) == 24u);
    assert(!audio_set_position(id, sizeof(pcm)));
}

static void test_one_shot_eos_and_looping(void){
    const int16_t pcm[] = { 1200, 2400, 3600, 4800 };
    write_mono16(TEST_DATA_A, pcm, 4);
    reset_audio(44100);
    int id = audio_register(TEST_DATA_A, sizeof(pcm), 44100, 1, 16);
    assert(id > 0);
    int16_t out[16] = {0};

    audio_play(id, 0);
    assert(audio_status(id) == AUDIO_STATUS_PLAYING);
    mix_into(out, 4);
    assert_output_sample(out, 3, pcm[3]);
    assert(audio_status(id) == 0u);
    assert(audio_cursor(id) == 0u);
    audio_play(id, 0);
    mix_into(out, 1);
    assert_output_sample(out, 0, pcm[0]);

    audio_stop(id);
    assert(audio_set_position(id, 0));
    audio_play(id, 1);
    assert(audio_status(id) == (AUDIO_STATUS_PLAYING | AUDIO_STATUS_LOOPING));
    mix_into(out, 6);
    for (unsigned i = 0; i < 6; i++) assert_output_sample(out, i, pcm[i % 4]);
    assert(audio_status(id) == (AUDIO_STATUS_PLAYING | AUDIO_STATUS_LOOPING));
    assert(audio_cursor(id) == 4u);
    audio_stop(id);
    assert(audio_status(id) == 0u);
    audio_play(id, 1);
    mix_into(out, 1);
    assert_output_sample(out, 0, pcm[2]);
    assert(audio_status(id) == (AUDIO_STATUS_PLAYING | AUDIO_STATUS_LOOPING));
}

static void test_static_full_write_pitch(void){
    enum { SOURCE_FRAMES = 44100, RENDER_FRAMES = 4410 };
    int16_t *pcm = (int16_t *)malloc(SOURCE_FRAMES * sizeof(*pcm));
    int16_t *out = (int16_t *)calloc(RENDER_FRAMES * 2u, sizeof(*out));
    assert(pcm && out);
    for (unsigned i = 0; i < SOURCE_FRAMES; i++)
        pcm[i] = (int16_t)lrint(10000.0 * sin(6.28318530717958647692 * 440.0 * i / 44100.0));
    write_mono16(TEST_DATA_B, pcm, SOURCE_FRAMES);
    reset_audio(44100);
    int id = audio_register(TEST_DATA_B, SOURCE_FRAMES * sizeof(*pcm), 44100, 1, 16);
    assert(id > 0);

    /* A full write is still a valid static looping buffer; its write cursor
     * must not pitch-shift iOS output. */
    audio_note_write_stat(id, SOURCE_FRAMES * sizeof(*pcm), 1);
    audio_note_write(id, SOURCE_FRAMES * sizeof(*pcm));
    audio_play(id, 1);
    mix_into(out, RENDER_FRAMES);
    unsigned crossings = 0;
    for (unsigned i = 1; i < RENDER_FRAMES; i++)
        if (out[(i - 1u) * 2u] <= 0 && out[i * 2u] > 0) crossings++;
    assert(crossings >= 43u && crossings <= 45u);
    assert(audio_status(id) == (AUDIO_STATUS_PLAYING | AUDIO_STATUS_LOOPING));
    assert(audio_cursor(id) == RENDER_FRAMES * 2u);
    assert(audio_get_freq(id) == 44100u);
    free(out);
    free(pcm);
}

static void test_hardware_rate_frequency_and_chunk_tail(void){
    int16_t ramp[2048];
    for (unsigned i = 0; i < 2048; i++){
        int v = (int)i * 300;
        if (v > 30000) v = 30000;
        ramp[i] = (int16_t)v;
    }
    write_mono16(TEST_DATA_A, ramp, 2048);
    reset_audio(48000);
    int id = audio_register(TEST_DATA_A, sizeof(ramp), 44100, 1, 16);
    assert(id > 0);
    int16_t out[480 * 2] = {0};

    audio_play(id, 0);
    mix_into(out, 480);
    assert(audio_cursor(id) == 882u);  /* 480 * 44100 / 48000 source frames */
    assert(abs((int)out[20u * 2u] - 5512) <= 2);

    audio_stop(id);
    assert(audio_set_position(id, 0));
    audio_set_freq(id, 88200u);
    assert(audio_get_freq(id) == 88200u);
    audio_play(id, 0);
    mix_into(out, 480);
    assert(audio_cursor(id) == 1764u);
    assert(abs((int)out[20u * 2u] - 11025) <= 2);

    /* Exercise the bounded chunk wrapper with a request larger than FRAMES;
     * the tail must be rendered and the static loop cursor must advance. */
    enum { LOOP_FRAMES = FRAMES + 17, REQUEST_FRAMES = FRAMES + 31 };
    int16_t *loop_pcm = (int16_t *)malloc(LOOP_FRAMES * sizeof(*loop_pcm));
    int16_t *large_out = (int16_t *)calloc(REQUEST_FRAMES * 2u, sizeof(*large_out));
    assert(loop_pcm && large_out);
    for (unsigned i = 0; i < LOOP_FRAMES; i++)
        loop_pcm[i] = (int16_t)((int)(i % 100u) * 200 - 10000);
    write_mono16(TEST_DATA_B, loop_pcm, LOOP_FRAMES);
    reset_audio(44100);
    int loop_id = audio_register(TEST_DATA_B, LOOP_FRAMES * sizeof(*loop_pcm), 44100, 1, 16);
    assert(loop_id > 0);
    audio_play(loop_id, 1);
    mix_into(large_out, REQUEST_FRAMES);
    assert_output_sample(large_out, REQUEST_FRAMES - 1u, loop_pcm[13]);
    assert(audio_cursor(loop_id) == 14u * 2u);
    free(large_out);
    free(loop_pcm);
}

static void test_nonblocking_snapshot(void){
    const int16_t pcm[] = { 1000, 2000, 3000, 4000 };
    write_mono16(TEST_DATA_A, pcm, 4);
    reset_audio(48000);
    int id = audio_register(TEST_DATA_A, sizeof(pcm), 44100, 1, 16);
    assert(id > 0);
    audio_note_write_stat(id, sizeof(pcm), 1);
    audio_play(id, 1);
    audio_play(id, 1); /* Reissue while already playing. */

    AudioSnapshot snap;
    assert(audio_snapshot(&snap));
    assert(snap.active_buffers == 1u);
    assert(snap.plays == 2u);
    assert(snap.reissues == 1u);
    assert(snap.stops == 0u);
    assert(snap.write_calls == 1u);
    assert(snap.hardware_rate == 48000u);

    pthread_mutex_lock(&g_slock);
    assert(!audio_snapshot(&snap));
    pthread_mutex_unlock(&g_slock);
}

int main(void){
    g_mem = (uint8_t *)calloc(TEST_MEM_SIZE, 1);
    assert(g_mem);
    test_stop_resume_and_seek();
    test_one_shot_eos_and_looping();
    test_static_full_write_pitch();
    test_hardware_rate_frequency_and_chunk_tail();
    test_nonblocking_snapshot();
    free(g_mem);
    puts("audio core tests passed");
    return 0;
}
