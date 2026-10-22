#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "cpu.h"
#include "fileio.h"
#include "guest_memory.h"

#define TEST_MEMORY_BYTES (2u << 20)
#define STACK_ADDRESS 0x1000u
#define PATH_ADDRESS 0x4000u
#define DATA_ADDRESS 0x8000u
#define READ_COUNT_ADDRESS 0x9000u
#define OVERLAPPED_ADDRESS 0xA000u
#define ASSET_COUNT 500u

static uint8_t test_memory[TEST_MEMORY_BYTES];
uint8_t *g_mem = test_memory;
uint8_t g_cbits[GUEST_MEMORY_BITMAP_SIZE];

int fileio_call(CPU *cpu, const char *name, uint32_t *result);
void fileio_set_root(const char *executable_path);
void fileio_set_write_root(const char *directory);

#define CHECK(condition) do { \
    if (!(condition)) { \
        fprintf(stderr, "FAIL: %s (%s:%d)\n", #condition, __FILE__, __LINE__); \
        return 1; \
    } \
} while (0)

void *guest_memory_pointer(uint32_t address, uint64_t size, int write_access) {
    (void)write_access;
    uint64_t end = (uint64_t)address + size;
    if (!size || end > TEST_MEMORY_BYTES) return NULL;
    return test_memory + address;
}

void mem_commit(uint32_t address, uint32_t size) {
    (void)address;
    (void)size;
}

void win32_set_last_error(CPU *cpu, uint32_t error) {
    (void)cpu;
    (void)error;
}

void win32_signal_event(uint32_t event) {
    (void)event;
}

double audio_time(void) {
    return 0.0;
}

static uint32_t guest_read_u32(uint32_t address) {
    uint32_t value;
    memcpy(&value, test_memory + address, sizeof(value));
    return value;
}

static void guest_write_u32(uint32_t address, uint32_t value) {
    memcpy(test_memory + address, &value, sizeof(value));
}

static int host_mkdir(const char *path) {
    if (mkdir(path, 0755) == 0 || errno == EEXIST) return 1;
    return 0;
}

static int host_mkdirs(const char *path) {
    char buffer[2048];
    size_t length = strlen(path);
    if (!length || length >= sizeof(buffer)) return 0;
    memcpy(buffer, path, length + 1u);
    for (char *cursor = buffer + 1; *cursor; cursor++) {
        if (*cursor != '/') continue;
        *cursor = '\0';
        if (!host_mkdir(buffer)) return 0;
        *cursor = '/';
    }
    return host_mkdir(buffer);
}

static int host_write_file(const char *path, const void *data, size_t size) {
    char parent[2048];
    size_t length = strlen(path);
    if (!length || length >= sizeof(parent)) return 0;
    memcpy(parent, path, length + 1u);
    char *slash = strrchr(parent, '/');
    if (!slash) return 0;
    *slash = '\0';
    if (!host_mkdirs(parent)) return 0;
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) return 0;
    const uint8_t *cursor = (const uint8_t *)data;
    size_t written = 0;
    while (written < size) {
        ssize_t count = write(fd, cursor + written, size - written);
        if (count <= 0) { close(fd); return 0; }
        written += (size_t)count;
    }
    return close(fd) == 0;
}

static void set_guest_string(const char *value) {
    size_t length = strlen(value) + 1u;
    if (length > 2048u) abort();
    memcpy(test_memory + PATH_ADDRESS, value, length);
}

static uint32_t call_api(CPU *cpu, const char *name, const uint32_t *arguments,
                         size_t argument_count) {
    uint32_t result = 0;
    if (argument_count > 7u) return UINT32_MAX;
    memset(test_memory + STACK_ADDRESS, 0, 7u * sizeof(uint32_t));
    memcpy(test_memory + STACK_ADDRESS, arguments,
           argument_count * sizeof(uint32_t));
    cpu->esp = STACK_ADDRESS;
    if (!fileio_call(cpu, name, &result)) return UINT32_MAX;
    return result;
}

static uint32_t call_get_attrs(CPU *cpu, const char *path) {
    set_guest_string(path);
    uint32_t arguments[1] = { PATH_ADDRESS };
    return call_api(cpu, "GetFileAttributesA", arguments, 1u);
}

static uint32_t open_guest_file(CPU *cpu, const char *path, uint32_t access,
                               uint32_t disposition) {
    set_guest_string(path);
    uint32_t arguments[7] = { PATH_ADDRESS, access, 0u, 0u, disposition, 0u, 0u };
    return call_api(cpu, "CreateFileA", arguments, 7u);
}

static int close_guest_file(CPU *cpu, uint32_t handle) {
    uint32_t arguments[1] = { handle };
    return call_api(cpu, "CloseHandle", arguments, 1u) == 1u;
}

static int open_close_asset(CPU *cpu, const char *path) {
    uint32_t handle = open_guest_file(cpu, path, 0u, 3u);
    if (handle == UINT32_MAX) return 0;
    return close_guest_file(cpu, handle);
}

static int write_guest_file(CPU *cpu, const char *path, const char *contents) {
    uint32_t handle = open_guest_file(cpu, path, 0x40000000u, 2u);
    if (handle == UINT32_MAX) return 0;
    size_t length = strlen(contents);
    memcpy(test_memory + DATA_ADDRESS, contents, length);
    uint32_t arguments[5] = { handle, DATA_ADDRESS, (uint32_t)length,
                              READ_COUNT_ADDRESS, 0u };
    int success = call_api(cpu, "WriteFile", arguments, 5u) == 1u &&
                  guest_read_u32(READ_COUNT_ADDRESS) == (uint32_t)length;
    return close_guest_file(cpu, handle) && success;
}

static int read_guest_file(CPU *cpu, const char *path, void *output,
                           uint32_t length, int overlapped) {
    uint32_t handle = open_guest_file(cpu, path, 0u, 3u);
    if (handle == UINT32_MAX) return 0;
    memset(test_memory + DATA_ADDRESS, 0xCC, length);
    guest_write_u32(READ_COUNT_ADDRESS, UINT32_MAX);
    uint32_t arguments[5] = { handle, DATA_ADDRESS, length,
                              READ_COUNT_ADDRESS,
                              overlapped ? OVERLAPPED_ADDRESS : 0u };
    if (overlapped) {
        memset(test_memory + OVERLAPPED_ADDRESS, 0, 32u);
        uint32_t page = (OVERLAPPED_ADDRESS + 19u) >> 14;
        g_cbits[page >> 3] |= (uint8_t)(1u << (page & 7u));
    }
    int success = call_api(cpu, "ReadFile", arguments, 5u) == 1u;
    uint32_t bytes_read = guest_read_u32(READ_COUNT_ADDRESS);
    if (success) memcpy(output, test_memory + DATA_ADDRESS, length);
    int closed = close_guest_file(cpu, handle);
    return success && closed && bytes_read == length;
}

static int remove_tree(const char *path) {
    DIR *directory = opendir(path);
    if (!directory) return unlink(path) == 0 || errno == ENOENT;
    struct dirent *entry;
    int success = 1;
    while ((entry = readdir(directory)) != NULL) {
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) continue;
        char child[2048];
        int length = snprintf(child, sizeof(child), "%s/%s", path, entry->d_name);
        if (length < 0 || (size_t)length >= sizeof(child) || !remove_tree(child))
            success = 0;
    }
    closedir(directory);
    return rmdir(path) == 0 && success;
}

static int test_exact_case_priority(CPU *cpu, const char *game_root,
                                    int case_sensitive) {
    if (!case_sensitive) return 1;
    char upper[2048], lower[2048], upper_file[2048], lower_file[2048];
    snprintf(upper, sizeof(upper), "%s/CaseTwin", game_root);
    snprintf(lower, sizeof(lower), "%s/casetwin", game_root);
    snprintf(upper_file, sizeof(upper_file), "%s/exact.bin", upper);
    snprintf(lower_file, sizeof(lower_file), "%s/exact.bin", lower);
    if (!host_mkdir(upper) || !host_mkdir(lower) ||
        !host_write_file(upper_file, "UP", 2u) ||
        !host_write_file(lower_file, "LO", 2u)) return 0;

    fileio_set_write_root(NULL);
    FileioPerfSnapshot before, after;
    fileio_perf_snapshot(&before);
    char output[2];
    if (!read_guest_file(cpu, "C:\\NFSU2\\CaseTwin\\exact.bin",
                         output, sizeof(output), 0) ||
        memcmp(output, "UP", sizeof(output)) != 0) return 0;
    fileio_perf_snapshot(&after);
    return after.directory_scans == before.directory_scans;
}

int main(void) {
    char temporary_root[] = "/tmp/nfsu2-fileio-cache-XXXXXX";
    char game_root[2048], saves_root[2048], game2_root[2048], saves2_root[2048];
    char executable_path[2048], path[2048], host_path[2048];
    if (!mkdtemp(temporary_root)) {
        perror("mkdtemp");
        return 1;
    }
    snprintf(game_root, sizeof(game_root), "%s/game", temporary_root);
    snprintf(saves_root, sizeof(saves_root), "%s/saves", temporary_root);
    snprintf(game2_root, sizeof(game2_root), "%s/game2", temporary_root);
    snprintf(saves2_root, sizeof(saves2_root), "%s/saves2", temporary_root);
    snprintf(executable_path, sizeof(executable_path), "%s/NFSU2.exe", game_root);
    CHECK(host_mkdir(game_root));
    CHECK(host_mkdir(saves_root));
    CHECK(host_mkdir(game2_root));
    CHECK(host_mkdir(saves2_root));

    CPU cpu;
    memset(&cpu, 0, sizeof(cpu));
    CHECK(host_mkdirs("/tmp"));
    for (uint32_t i = 0; i < ASSET_COUNT; i++) {
        snprintf(host_path, sizeof(host_path), "%s/GLOBAL/RACE/asset_%03u.bin",
                 game_root, i);
        char contents[8];
        int count = snprintf(contents, sizeof(contents), "G%03u", i);
        CHECK(count == 4 && host_write_file(host_path, contents, (size_t)count));
    }
    snprintf(host_path, sizeof(host_path), "%s/GLOBAL/RACE/overlay.bin", game_root);
    CHECK(host_write_file(host_path, "GAME", 4u));
    snprintf(host_path, sizeof(host_path), "%s/GLOBAL/RACE/rename-source.bin", game_root);
    CHECK(host_write_file(host_path, "GOLD", 4u));
    snprintf(host_path, sizeof(host_path), "%s/GLOBAL/RACE/mute-me-1.bin", game_root);
    CHECK(host_write_file(host_path, "abc", 3u));
    snprintf(host_path, sizeof(host_path), "%s/GLOBAL/RACE/mute-me-2.bin", game_root);
    CHECK(host_write_file(host_path, "def", 3u));
    snprintf(host_path, sizeof(host_path), "%s/GLOBAL/RACE/mute-me-3.bin", game_root);
    CHECK(host_write_file(host_path, "ghi", 3u));

    CHECK(setenv("MUTEFILE", "mute-me", 1) == 0);
    CHECK(setenv("MUTESIZE", "3", 1) == 0);
    CHECK(setenv("MUTEMIN", "0", 1) == 0);
    CHECK(unsetenv("READLOG") == 0);
    fileio_set_root(executable_path);
    fileio_set_write_root(saves_root);

    FileioPerfSnapshot baseline, after_assets;
    fileio_perf_snapshot(&baseline);
    for (uint32_t i = 0; i < ASSET_COUNT; i++) {
        snprintf(path, sizeof(path), "C:\\NFSU2\\GLOBAL\\RACE\\asset_%03u.bin", i);
        CHECK(open_close_asset(&cpu, path));
    }
    fileio_perf_snapshot(&after_assets);
    uint64_t scan_delta = after_assets.directory_scans - baseline.directory_scans;
    uint64_t hit_delta = after_assets.case_cache_hits - baseline.case_cache_hits;
    CHECK(scan_delta == 1u);
    CHECK(hit_delta >= ASSET_COUNT - 1u);

    /* On case-sensitive volumes, both names can coexist; exact stat must win
     * without consulting the folded fallback. */
    snprintf(path, sizeof(path), "%s/CaseTwin", game_root);
    int case_sensitive = mkdir(path, 0755) == 0;
    if (case_sensitive) {
        snprintf(path, sizeof(path), "%s/casetwin", game_root);
        case_sensitive = mkdir(path, 0755) == 0;
    }
    CHECK(test_exact_case_priority(&cpu, game_root, case_sensitive));

    /* More unique wrong-case components than the fixed cache capacity force
     * LRU eviction while keeping its memory use bounded. */
    if (case_sensitive) {
        fileio_set_root(executable_path);
        fileio_set_write_root(NULL);
        /* Stabilize the parent directory before any cache lookups, so its
         * metadata cannot invalidate entries during the eviction check. */
        for (uint32_t i = 0; i < FILEIO_CASE_CACHE_CAPACITY + 6u; i++) {
            snprintf(host_path, sizeof(host_path), "%s/DirCase%03u", game_root, i);
            CHECK(host_mkdir(host_path));
        }

        FileioPerfSnapshot before, filled, recent, after;
        fileio_perf_snapshot(&before);
        for (uint32_t i = 0; i < FILEIO_CASE_CACHE_CAPACITY + 6u; i++) {
            snprintf(path, sizeof(path), "C:\\NFSU2\\dircase%03u", i);
            CHECK(call_get_attrs(&cpu, path) == 0x10u);
        }
        fileio_perf_snapshot(&filled);
        CHECK(filled.directory_scans - before.directory_scans ==
              FILEIO_CASE_CACHE_CAPACITY + 6u);

        /* The newest cache entry remains hot, then the oldest has been
         * evicted because all 70 lookups shared an unchanged parent stamp. */
        CHECK(call_get_attrs(&cpu, "C:\\NFSU2\\dircase069") == 0x10u);
        fileio_perf_snapshot(&recent);
        CHECK(recent.directory_scans == filled.directory_scans);
        CHECK(recent.case_cache_hits == filled.case_cache_hits + 1u);

        CHECK(call_get_attrs(&cpu, "C:\\NFSU2\\dircase000") == 0x10u);
        fileio_perf_snapshot(&after);
        CHECK(after.directory_scans == recent.directory_scans + 1u);
        CHECK(after.directory_scans - before.directory_scans ==
              FILEIO_CASE_CACHE_CAPACITY + 7u);
    }

    /* Oversized components bypass the folded-name cache; repeated malformed
     * requests remain safe and perform a fresh bounded directory scan. */
    fileio_set_root(executable_path);
    fileio_set_write_root(NULL);
    char long_component[261];
    memset(long_component, 'x', sizeof(long_component) - 1u);
    long_component[sizeof(long_component) - 1u] = '\0';
    snprintf(path, sizeof(path), "C:\\NFSU2\\GLOBAL\\RACE\\%s", long_component);
    FileioPerfSnapshot long_before, long_after;
    fileio_perf_snapshot(&long_before);
    CHECK(call_get_attrs(&cpu, path) == UINT32_MAX);
    CHECK(call_get_attrs(&cpu, path) == UINT32_MAX);
    fileio_perf_snapshot(&long_after);
    CHECK(long_after.directory_scans - long_before.directory_scans == 2u);

    /* A longer than resolver-buffer guest path must fail closed without
     * overflowing the bounded parent/name storage. */
    char long_guest_path[1400];
    size_t cursor = (size_t)snprintf(long_guest_path, sizeof(long_guest_path), "C:\\NFSU2");
    snprintf(host_path, sizeof(host_path), "%s", game_root);
    for (int i = 0; i < 4; i++) {
        char component[251];
        memset(component, (int)('a' + i), sizeof(component) - 1u);
        component[sizeof(component) - 1u] = '\0';
        size_t host_length = strlen(host_path);
        size_t host_remaining = sizeof(host_path) - host_length;
        int written = snprintf(host_path + host_length,
                               host_remaining, "/%s", component);
        CHECK(written > 0 && (size_t)written < host_remaining);
        /* Darwin's host PATH_MAX is 1024 too. Prepare only prefixes that fit
         * the resolver; the remainder is deliberately an invalid guest path. */
        if (strlen(host_path) < 1024u) CHECK(host_mkdirs(host_path));
        size_t guest_length = strlen(component);
        CHECK(cursor + guest_length + 2u < sizeof(long_guest_path));
        long_guest_path[cursor++] = '\\';
        memcpy(long_guest_path + cursor, component, guest_length);
        cursor += guest_length;
    }
    long_guest_path[cursor++] = '\\';
    memset(long_guest_path + cursor, 'z', 20u);
    long_guest_path[cursor + 20u] = '\0';
    CHECK(strlen(long_guest_path) > 1024u);
    CHECK(call_get_attrs(&cpu, long_guest_path) == UINT32_MAX);

    char output[8];
    FileioPerfSnapshot reads_before, reads_after;
    fileio_perf_snapshot(&reads_before);
    CHECK(read_guest_file(&cpu, "C:\\NFSU2\\GLOBAL\\RACE\\mute-me-1.bin",
                          output, 3u, 0));
    CHECK(memcmp(output, "\0\0\0", 3u) == 0);
    CHECK(setenv("MUTEFILE", "does-not-match", 1) == 0);
    CHECK(setenv("MUTESIZE", "99", 1) == 0);
    CHECK(read_guest_file(&cpu, "C:\\NFSU2\\GLOBAL\\RACE\\mute-me-2.bin",
                          output, 3u, 0));
    CHECK(memcmp(output, "\0\0\0", 3u) == 0);
    CHECK(read_guest_file(&cpu, "C:\\NFSU2\\GLOBAL\\RACE\\mute-me-3.bin",
                          output, 3u, 1));
    CHECK(memcmp(output, "\0\0\0", 3u) == 0);
    fileio_perf_snapshot(&reads_after);
    CHECK(reads_after.read_calls - reads_before.read_calls == 3u);
    CHECK(reads_after.read_bytes - reads_before.read_bytes == 9u);

    /* Re-enter the Saves namespace and create the overlay through production
     * APIs; the resolver sees a missing component before each mkdir. */
    fileio_set_root(executable_path);
    fileio_set_write_root(saves_root);
    set_guest_string("C:\\NFSU2\\GLOBAL");
    uint32_t one_arg[1] = { PATH_ADDRESS };
    CHECK(call_api(&cpu, "CreateDirectoryA", one_arg, 1u) == 1u);
    set_guest_string("C:\\NFSU2\\GLOBAL\\RACE");
    CHECK(call_api(&cpu, "CreateDirectoryA", one_arg, 1u) == 1u);
    CHECK(write_guest_file(&cpu, "C:\\NFSU2\\GLOBAL\\RACE\\overlay.bin", "SAVE"));

    /* Populate a positive case-folded entry, delete its target through the
     * wrapper, and verify the underlying game file is exposed again. */
    CHECK(call_get_attrs(&cpu, "C:\\NFSU2\\GLOBAL\\RACE\\OVERLAY.BIN") == 0x80u);
    FileioPerfSnapshot mutation_before, mutation_after;
    fileio_perf_snapshot(&mutation_before);
    set_guest_string("C:\\NFSU2\\GLOBAL\\RACE\\overlay.bin");
    CHECK(call_api(&cpu, "DeleteFileA", one_arg, 1u) == 1u);
    CHECK(read_guest_file(&cpu, "C:\\NFSU2\\GLOBAL\\RACE\\OVERLAY.BIN",
                          output, 4u, 0));
    CHECK(memcmp(output, "GAME", 4u) == 0);

    CHECK(write_guest_file(&cpu, "C:\\NFSU2\\GLOBAL\\RACE\\rename-source.bin", "SAVE"));
    set_guest_string("C:\\NFSU2\\GLOBAL\\RACE\\rename-source.bin");
    uint32_t move_arguments[2] = { PATH_ADDRESS, PATH_ADDRESS + 512u };
    set_guest_string("C:\\NFSU2\\GLOBAL\\RACE\\rename-source.bin");
    memcpy(test_memory + move_arguments[1],
           "C:\\NFSU2\\GLOBAL\\RACE\\Renamed.BIN",
           sizeof("C:\\NFSU2\\GLOBAL\\RACE\\Renamed.BIN"));
    CHECK(call_api(&cpu, "MoveFileA", move_arguments, 2u) == 1u);
    CHECK(read_guest_file(&cpu, "C:\\NFSU2\\GLOBAL\\RACE\\renamed.bin",
                          output, 4u, 0));
    CHECK(memcmp(output, "SAVE", 4u) == 0);
    CHECK(read_guest_file(&cpu, "C:\\NFSU2\\GLOBAL\\RACE\\rename-source.bin",
                          output, 4u, 0));
    CHECK(memcmp(output, "GOLD", 4u) == 0);
    fileio_perf_snapshot(&mutation_after);
    CHECK(mutation_after.cache_invalidations > mutation_before.cache_invalidations);

    /* Parent metadata validation notices direct out-of-process directory
     * changes even when no fileio mutator issued an invalidation. */
    fileio_set_write_root(NULL);
    CHECK(call_get_attrs(&cpu, "C:\\NFSU2\\ExternalCase") == UINT32_MAX);
    snprintf(host_path, sizeof(host_path), "%s/ExternalCase", game_root);
    CHECK(host_mkdir(host_path));
    CHECK(call_get_attrs(&cpu, "C:\\NFSU2\\externalcase") == 0x10u);

    /* A new write root and a new game root select their own namespace. */
    snprintf(host_path, sizeof(host_path), "%s/GLOBAL/RACE/overlay.bin", saves2_root);
    CHECK(host_write_file(host_path, "TWO!", 4u));
    snprintf(host_path, sizeof(host_path), "%s/GLOBAL/RACE/overlay.bin", game2_root);
    CHECK(host_write_file(host_path, "NEW!", 4u));
    snprintf(executable_path, sizeof(executable_path), "%s/NFSU2.exe", game2_root);
    fileio_set_write_root(saves2_root);
    CHECK(read_guest_file(&cpu, "C:\\NFSU2\\GLOBAL\\RACE\\overlay.bin",
                          output, 4u, 0));
    CHECK(memcmp(output, "TWO!", 4u) == 0);
    fileio_set_write_root(NULL);
    CHECK(read_guest_file(&cpu, "C:\\NFSU2\\GLOBAL\\RACE\\overlay.bin",
                          output, 4u, 0));
    CHECK(memcmp(output, "GAME", 4u) == 0);
    fileio_set_root(executable_path);
    CHECK(read_guest_file(&cpu, "C:\\NFSU2\\GLOBAL\\RACE\\overlay.bin",
                          output, 4u, 0));
    CHECK(memcmp(output, "NEW!", 4u) == 0);

    FileioPerfSnapshot final_snapshot;
    fileio_perf_snapshot(&final_snapshot);
    printf("PASS: fileio_case_cache_test assets=%u scans=%llu hits=%llu reads=%llu bytes=%llu\n",
           ASSET_COUNT, (unsigned long long)scan_delta,
           (unsigned long long)hit_delta,
           (unsigned long long)final_snapshot.read_calls,
           (unsigned long long)final_snapshot.read_bytes);
    fileio_set_write_root(NULL);
    CHECK(remove_tree(temporary_root));
    return 0;
}
