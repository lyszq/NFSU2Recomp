#include "guest_execution.h"
#include "guest_memory.h"
#include "guest_bootstrap.h"

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

enum { TRACE_WORDS = 9, TRACE_RECORD_BYTES = TRACE_WORDS * 4, TRACE_CHUNK = 4096 };

static const char trace_path[] = "gen/ios-private/startup_trace.bin";
static FILE *trace_file;
static int trace_open_attempted;
static int trace_ip_mismatch_reported;
static int trace_gpr_mismatch_reported;
static int trace_record_error_reported;
static int trace_size_error_reported;
static uint64_t trace_file_size;
static uint64_t trace_bytes_consumed;
static uint64_t trace_steps_seen;

static uint32_t read_le32(const unsigned char *bytes) {
    return (uint32_t)bytes[0] |
           ((uint32_t)bytes[1] << 8) |
           ((uint32_t)bytes[2] << 16) |
           ((uint32_t)bytes[3] << 24);
}

static void reset_trace(void) {
    if (trace_file) fclose(trace_file);
    trace_file = NULL;
    trace_open_attempted = 0;
    trace_ip_mismatch_reported = 0;
    trace_gpr_mismatch_reported = 0;
    trace_record_error_reported = 0;
    trace_size_error_reported = 0;
    trace_file_size = 0;
    trace_bytes_consumed = 0;
    trace_steps_seen = 0;
}

static void open_trace(uint64_t index) {
    long end;
    trace_open_attempted = 1;
    trace_file = fopen(trace_path, "rb");
    if (!trace_file) {
        fprintf(stderr,
                "DIFF | FATAL | step=%llu expected_trace=open native_trace=unavailable errno=%d\n",
                (unsigned long long)index, errno);
        trace_record_error_reported = 1;
        return;
    }
    if (fseek(trace_file, 0, SEEK_END) != 0 || (end = ftell(trace_file)) < 0 ||
        fseek(trace_file, 0, SEEK_SET) != 0) {
        fprintf(stderr,
                "DIFF | FATAL | step=%llu expected_trace=size native_trace=unavailable errno=%d\n",
                (unsigned long long)index, errno);
        trace_record_error_reported = 1;
        fclose(trace_file);
        trace_file = NULL;
        return;
    }
    trace_file_size = (uint64_t)(unsigned long)end;
    if (trace_file_size % TRACE_RECORD_BYTES != 0) {
        fprintf(stderr,
                "DIFF | FATAL | trace_expected_bytes=%llu native_record_bytes=%u remainder=%llu\n",
                (unsigned long long)trace_file_size, (unsigned)TRACE_RECORD_BYTES,
                (unsigned long long)(trace_file_size % TRACE_RECORD_BYTES));
        trace_size_error_reported = 1;
    }
}

void nfs_private_trace_step(const CPU *cpu, uint32_t ip, uint64_t index) {
    unsigned char record[TRACE_RECORD_BYTES];
    size_t got;
    uint32_t expected_ip;

    /* GuestImageProbe executes the same startup twice; index zero starts a
     * fresh comparison against the beginning of the oracle stream. */
    if (index == 0) reset_trace();
    if (!trace_open_attempted) open_trace(index);
    trace_steps_seen++;
    if (!cpu) {
        if (!trace_record_error_reported) {
            fprintf(stderr,
                    "DIFF | step=%llu expected_cpu=present native_cpu=missing\n",
                    (unsigned long long)index);
            trace_record_error_reported = 1;
        }
        return;
    }
    if (!trace_file) return;

    got = fread(record, 1, sizeof record, trace_file);
    trace_bytes_consumed += (uint64_t)got;
    if (got != sizeof record) {
        if (!trace_record_error_reported) {
            if (got >= 4) {
                expected_ip = read_le32(record);
                fprintf(stderr,
                        "DIFF | FATAL | step=%llu expected_record_bytes=%u native_record_bytes=%llu expected_ip=0x%08x native_ip=0x%08x\n",
                        (unsigned long long)index, (unsigned)TRACE_RECORD_BYTES,
                        (unsigned long long)got, expected_ip, ip);
                if (expected_ip != ip && !trace_ip_mismatch_reported) {
                    fprintf(stderr,
                            "DIFF | step=%llu expected_ip=0x%08x native_ip=0x%08x\n",
                            (unsigned long long)index, expected_ip, ip);
                    trace_ip_mismatch_reported = 1;
                }
            } else {
                fprintf(stderr,
                        "DIFF | FATAL | step=%llu expected_record_bytes=%u native_record_bytes=%llu native_ip=0x%08x\n",
                        (unsigned long long)index, (unsigned)TRACE_RECORD_BYTES,
                        (unsigned long long)got, ip);
            }
            trace_record_error_reported = 1;
        }
        return;
    }

    expected_ip = read_le32(record);
    if (expected_ip != ip && !trace_ip_mismatch_reported) {
        fprintf(stderr,
                "DIFF | step=%llu expected_ip=0x%08x native_ip=0x%08x\n",
                (unsigned long long)index, expected_ip, ip);
        trace_ip_mismatch_reported = 1;
    }
    for (uint32_t reg = 0; reg < 8; ++reg) {
        uint32_t expected = read_le32(record + (reg + 1u) * 4u);
        uint32_t native = cpu->r[reg];
        if (expected != native && !trace_gpr_mismatch_reported) {
            fprintf(stderr,
                    "DIFF | step=%llu expected_ip=0x%08x native_ip=0x%08x reg=%u expected=0x%08x native=0x%08x\n",
                    (unsigned long long)index, expected_ip, ip, reg, expected, native);
            trace_gpr_mismatch_reported = 1;
        }
    }
}

static int valid_label(const char *label) {
    if (!label || !*label) return 0;
    for (const unsigned char *p = (const unsigned char *)label; *p; ++p) {
        if (!((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') ||
              (*p >= '0' && *p <= '9') || *p == '_' || *p == '-')) return 0;
    }
    return 1;
}

void nfs_private_trace_memory(const char *label, uint32_t address, size_t size) {
    char path[256];
    FILE *file;
    long end;
    uint64_t expected_size, compare_size, offset = 0, differences = 0;
    const unsigned char *native;
    unsigned char expected[TRACE_CHUNK];
    unsigned reported = 0;
    int read_error = 0;

    if (!valid_label(label)) {
        fprintf(stderr, "DIFF | FATAL | memory_label=invalid\n");
        return;
    }
    int path_length = snprintf(path, sizeof path,
                               "gen/ios-private/startup_%s.bin", label);
    if (path_length < 0 || (size_t)path_length >= sizeof path) {
        fprintf(stderr, "DIFF | FATAL | memory=%s expected_path=valid native_path=too_long\n",
                label);
        return;
    }
    file = fopen(path, "rb");
    if (!file) {
        fprintf(stderr, "DIFF | FATAL | memory=%s expected_file=present native_file=missing errno=%d\n",
                label, errno);
        return;
    }
    if (fseek(file, 0, SEEK_END) != 0 || (end = ftell(file)) < 0 ||
        fseek(file, 0, SEEK_SET) != 0) {
        fprintf(stderr, "DIFF | FATAL | memory=%s expected_file_size=readable native_file_size=unavailable errno=%d\n",
                label, errno);
        fclose(file);
        return;
    }
    expected_size = (uint64_t)(unsigned long)end;
    if (expected_size != (uint64_t)size) {
        fprintf(stderr,
                "DIFF | FATAL | memory=%s expected_size=%llu native_size=%llu\n",
                label, (unsigned long long)expected_size,
                (unsigned long long)size);
    }
    native = size ? (const unsigned char *)guest_memory_pointer(address,
                                                               (uint64_t)size, 0)
                  : NULL;
    if (size && !native) {
        fprintf(stderr,
                "DIFF | FATAL | memory=%s address=0x%08x native_range=unavailable size=%llu\n",
                label, address, (unsigned long long)size);
        fclose(file);
        return;
    }

    compare_size = expected_size < (uint64_t)size ? expected_size : (uint64_t)size;
    while (offset < compare_size) {
        size_t request = (size_t)(compare_size - offset);
        size_t got;
        if (request > sizeof expected) request = sizeof expected;
        got = fread(expected, 1, request, file);
        if (got != request) {
            fprintf(stderr,
                    "DIFF | FATAL | memory=%s expected_read_bytes=%llu native_read_bytes=%llu\n",
                    label, (unsigned long long)request,
                    (unsigned long long)got);
            read_error = 1;
        }
        for (size_t i = 0; i < got; ++i) {
            unsigned char actual = native[(size_t)offset + i];
            if (expected[i] != actual) {
                uint64_t guest_address = (uint64_t)address + offset + i;
                differences++;
                if (reported < 4) {
                    fprintf(stderr,
                            "DIFF | memory=%s address=0x%08x expected=0x%02x native=0x%02x\n",
                            label, (uint32_t)guest_address,
                            (unsigned)expected[i], (unsigned)actual);
                    reported++;
                }
            }
        }
        offset += got;
        if (got != request) break;
    }
    if (differences) {
        fprintf(stderr,
                "DIFF | FATAL | memory=%s differing_bytes=%llu first_differences_reported=%u\n",
                label, (unsigned long long)differences, reported);
    } else if (read_error) {
        fprintf(stderr, "DIFF | FATAL | memory=%s comparison=incomplete\n", label);
    }
    fclose(file);
}

static void finish_trace_stream(void) {
    if (trace_file) {
        if (trace_bytes_consumed != trace_file_size && !trace_size_error_reported) {
            fprintf(stderr,
                    "DIFF | FATAL | trace_expected_bytes=%llu native_consumed_bytes=%llu native_steps=%llu\n",
                    (unsigned long long)trace_file_size,
                    (unsigned long long)trace_bytes_consumed,
                    (unsigned long long)trace_steps_seen);
            trace_size_error_reported = 1;
        }
        fclose(trace_file);
        trace_file = NULL;
    }
    trace_open_attempted = 0;
}

void nfs_private_trace_finish(const GuestPEImage *image) {
    finish_trace_stream();
    if (!image) {
        fprintf(stderr, "DIFF | FATAL | memory=image expected_descriptor=present native_descriptor=missing\n");
        return;
    }
    nfs_private_trace_memory("image", image->image_base, image->image_size);
    nfs_private_trace_memory("teb", GUEST_TEB_BASE, 0x20000u);
}
