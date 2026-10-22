#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "cpu.h"
#include "guest_memory.h"
#include "win32_full_path.h"

#define TEST_MEMORY_BYTES (1u << 20)
#define STACK_ADDRESS 0x10000u
#define INPUT_ADDRESS 0x20000u
#define OUTPUT_ADDRESS 0x40000u
#define FILE_PART_ADDRESS 0x50000u

static uint8_t test_memory[TEST_MEMORY_BYTES];
static uint8_t test_readable[TEST_MEMORY_BYTES / GUEST_MEMORY_GRANULE];
static uint8_t test_writable[TEST_MEMORY_BYTES / GUEST_MEMORY_GRANULE];
uint8_t *g_mem = test_memory;
uint8_t g_cbits[GUEST_MEMORY_BITMAP_SIZE];

static uint32_t last_error;

int fileio_call(CPU *cpu, const char *name, uint32_t *result);

#define CHECK(condition) do { \
    if (!(condition)) { \
        fprintf(stderr, "FAIL: %s (%s:%d)\n", #condition, __FILE__, __LINE__); \
        return 1; \
    } \
} while (0)

void *guest_memory_pointer(uint32_t address, uint64_t size, int write_access) {
    uint64_t end = (uint64_t)address + size;
    if (!size || end > TEST_MEMORY_BYTES) return NULL;
    uint32_t first = address / GUEST_MEMORY_GRANULE;
    uint32_t last = (uint32_t)((end - 1u) / GUEST_MEMORY_GRANULE);
    for (uint32_t page = first; page <= last; page++) {
        if (!test_readable[page] || (write_access && !test_writable[page]))
            return NULL;
    }
    return test_memory + address;
}

void mem_commit(uint32_t address, uint32_t size) {
    (void)address;
    (void)size;
}

void win32_set_last_error(CPU *cpu, uint32_t error) {
    (void)cpu;
    last_error = error;
}

void win32_signal_event(uint32_t event) {
    (void)event;
}

double audio_time(void) {
    return 0.0;
}

static void set_guest_string(uint32_t address, const char *value) {
    size_t size = strlen(value) + 1u;
    void *destination = guest_memory_pointer(address, size, 1);
    if (destination) memcpy(destination, value, size);
}

static int check_normalized(const char *input, const char *expected,
                            size_t file_part_offset, int has_file_part) {
    char output[WIN32_FULL_PATH_STORAGE];
    Win32FullPathInfo info;
    uint32_t error = UINT32_MAX;
    if (!win32_full_path_normalize(input, output, &info, &error)) return 0;
    return error == 0u && strcmp(output, expected) == 0 &&
           info.length == strlen(expected) &&
           info.file_part_offset == file_part_offset &&
           info.has_file_part == has_file_part;
}

static int check_rejected(const char *input, uint32_t expected_error) {
    char output[WIN32_FULL_PATH_STORAGE];
    Win32FullPathInfo info;
    uint32_t error = 0u;
    return !win32_full_path_normalize(input, output, &info, &error) &&
           error == expected_error;
}

static uint32_t call_get_full_path(CPU *cpu, uint32_t filename,
                                   uint32_t capacity, uint32_t output,
                                   uint32_t file_part, int *handled) {
    uint32_t arguments[4] = { filename, capacity, output, file_part };
    memcpy(test_memory + STACK_ADDRESS, arguments, sizeof arguments);
    cpu->esp = STACK_ADDRESS;
    uint32_t result = UINT32_MAX;
    *handled = fileio_call(cpu, "GetFullPathNameA", &result);
    return result;
}

static int test_production_import(void) {
    CPU cpu;
    memset(&cpu, 0, sizeof cpu);
    last_error = 0xA5A5A5A5u;
    set_guest_string(INPUT_ADDRESS,
                     "C:\\NFSU2\\TRACKS\\..\\CARS\\350Z\\GEOMETRY.BIN");
    memset(test_memory + OUTPUT_ADDRESS, 0xCC, 260u);
    uint32_t file_part = UINT32_MAX;
    memcpy(test_memory + FILE_PART_ADDRESS, &file_part, sizeof file_part);

    int handled = 0;
    uint32_t result = call_get_full_path(&cpu, INPUT_ADDRESS, 260u,
                                         OUTPUT_ADDRESS, FILE_PART_ADDRESS,
                                         &handled);
    const char *expected = "C:\\NFSU2\\CARS\\350Z\\GEOMETRY.BIN";
    CHECK(handled == 1);
    CHECK(result == strlen(expected));
    CHECK(strcmp((char *)test_memory + OUTPUT_ADDRESS, expected) == 0);
    memcpy(&file_part, test_memory + FILE_PART_ADDRESS, sizeof file_part);
    CHECK(file_part == OUTPUT_ADDRESS + (uint32_t)strlen("C:\\NFSU2\\CARS\\350Z\\"));
    CHECK(last_error == 0xA5A5A5A5u);

    memset(test_memory + OUTPUT_ADDRESS, 0xCC, 260u);
    file_part = 0x12345678u;
    memcpy(test_memory + FILE_PART_ADDRESS, &file_part, sizeof file_part);
    result = call_get_full_path(&cpu, INPUT_ADDRESS, 1u, OUTPUT_ADDRESS,
                                FILE_PART_ADDRESS, &handled);
    CHECK(handled == 1);
    CHECK(result == strlen(expected) + 1u);
    CHECK((uint8_t)test_memory[OUTPUT_ADDRESS] == 0xCCu);
    memcpy(&file_part, test_memory + FILE_PART_ADDRESS, sizeof file_part);
    CHECK(file_part == 0x12345678u);
    CHECK(last_error == 0xA5A5A5A5u);

    result = call_get_full_path(&cpu, INPUT_ADDRESS, 0u, 0u,
                                FILE_PART_ADDRESS, &handled);
    CHECK(handled == 1 && result == strlen(expected) + 1u);

    set_guest_string(INPUT_ADDRESS, ".\\");
    result = call_get_full_path(&cpu, INPUT_ADDRESS, 260u, OUTPUT_ADDRESS,
                                FILE_PART_ADDRESS, &handled);
    CHECK(handled == 1 && result == strlen("C:\\NFSU2\\"));
    CHECK(strcmp((char *)test_memory + OUTPUT_ADDRESS, "C:\\NFSU2\\") == 0);
    memcpy(&file_part, test_memory + FILE_PART_ADDRESS, sizeof file_part);
    CHECK(file_part == 0u);

    set_guest_string(INPUT_ADDRESS, "D:\\NFSU2\\FILE.BIN");
    result = call_get_full_path(&cpu, INPUT_ADDRESS, 260u, OUTPUT_ADDRESS,
                                FILE_PART_ADDRESS, &handled);
    CHECK(handled == 1 && result == 0u);
    CHECK(last_error == WIN32_FULL_PATH_ERROR_INVALID_DRIVE);

    last_error = 0u;
    result = call_get_full_path(&cpu, 0u, 260u, OUTPUT_ADDRESS,
                                FILE_PART_ADDRESS, &handled);
    CHECK(handled == 1 && result == 0u);
    CHECK(last_error == WIN32_FULL_PATH_ERROR_INVALID_PARAMETER);

    last_error = 0u;
    result = call_get_full_path(&cpu, 0xF0000000u, 260u, OUTPUT_ADDRESS,
                                FILE_PART_ADDRESS, &handled);
    CHECK(handled == 1 && result == 0u);
    CHECK(last_error == WIN32_FULL_PATH_ERROR_NOACCESS);

    last_error = 0u;
    set_guest_string(INPUT_ADDRESS, "C:\\NFSU2\\FILE.BIN");
    result = call_get_full_path(&cpu, INPUT_ADDRESS, 260u, 0xF0000000u,
                                FILE_PART_ADDRESS, &handled);
    CHECK(handled == 1 && result == 0u);
    CHECK(last_error == WIN32_FULL_PATH_ERROR_NOACCESS);

    last_error = 0u;
    memset(test_memory + OUTPUT_ADDRESS, 0xCC, 260u);
    result = call_get_full_path(&cpu, INPUT_ADDRESS, 260u, OUTPUT_ADDRESS,
                                0xF0000000u, &handled);
    CHECK(handled == 1 && result == 0u);
    CHECK(last_error == WIN32_FULL_PATH_ERROR_NOACCESS);
    CHECK((uint8_t)test_memory[OUTPUT_ADDRESS] == 0xCCu);

    last_error = 0u;
    cpu.esp = 0xF0000000u;
    result = UINT32_MAX;
    handled = fileio_call(&cpu, "GetFullPathNameA", &result);
    CHECK(handled == 1 && result == 0u);
    CHECK(last_error == WIN32_FULL_PATH_ERROR_NOACCESS);
    return 0;
}

int main(void) {
    memset(test_readable, 1, sizeof test_readable);
    memset(test_writable, 1, sizeof test_writable);
    CHECK(check_normalized("TRACKS\\L2R.BUN", "C:\\NFSU2\\TRACKS\\L2R.BUN",
                           strlen("C:\\NFSU2\\TRACKS\\"), 1));
    CHECK(check_normalized("C:TRACKS\\..\\GLOBAL", "C:\\NFSU2\\GLOBAL",
                           strlen("C:\\NFSU2\\"), 1));
    CHECK(check_normalized("\\WINDOWS", "C:\\WINDOWS", strlen("C:\\"), 1));
    CHECK(check_normalized("foo\\..", "C:\\NFSU2", strlen("C:\\"), 1));
    CHECK(check_normalized(".", "C:\\NFSU2", strlen("C:\\"), 1));
    CHECK(check_normalized("C:", "C:\\NFSU2", strlen("C:\\"), 1));
    CHECK(check_normalized("C:\\", "C:\\", 0u, 0));
    CHECK(check_normalized("C:\\NFSU2\\", "C:\\NFSU2\\", 0u, 0));
    CHECK(check_rejected("D:\\file.bin", WIN32_FULL_PATH_ERROR_INVALID_DRIVE));
    CHECK(check_rejected("\\\\server\\share", WIN32_FULL_PATH_ERROR_INVALID_NAME));
    CHECK(check_rejected("", WIN32_FULL_PATH_ERROR_INVALID_NAME));
    {
        char too_long[WIN32_FULL_PATH_STORAGE + 1u];
        memset(too_long, 'x', sizeof too_long);
        too_long[sizeof too_long - 1u] = '\0';
        CHECK(check_rejected(too_long, WIN32_FULL_PATH_ERROR_FILENAME_EXCED_RANGE));
    }
    CHECK(test_production_import() == 0);
    puts("PASS: win32_full_path_test");
    return 0;
}
