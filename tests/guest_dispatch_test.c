#include "guest_dispatch.h"

#include <errno.h>
#include <stdint.h>
#include <stdio.h>

#define CHECK(condition, message) do { \
    if (!(condition)) { \
        fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, (message)); \
        return 1; \
    } \
} while (0)

enum {
    TEXT_BASE = 0x00400000u,
    TEXT_SIZE = 0x1000u
};

static void fn_first(CPU *cpu) { (void)cpu; }
static void fn_middle(CPU *cpu) { (void)cpu; }
static void fn_last(CPU *cpu) { (void)cpu; }

static int expect_init_error(uint32_t base, uint32_t size,
                             const uint32_t *addresses,
                             const GuestFunction *functions, uint32_t count,
                             int expected, const char *label) {
    GuestDispatch table = { 0 };
    int rc = guest_dispatch_init(&table, base, size, addresses, functions, count);
    if (rc != expected) {
        fprintf(stderr, "FAIL %s: expected %d, got %d\n", label, expected, rc);
        guest_dispatch_destroy(&table);
        return 1;
    }
    if (table.indices || table.addresses || table.functions || table.count ||
        table.text_base || table.text_size) {
        fprintf(stderr, "FAIL %s: failed init left partial table state\n", label);
        guest_dispatch_destroy(&table);
        return 1;
    }
    guest_dispatch_destroy(&table);
    return 0;
}

static int test_table_validation(void) {
    const uint32_t duplicate[] = { TEXT_BASE + 4u, TEXT_BASE + 4u };
    const GuestFunction duplicate_fns[] = { fn_first, fn_middle };
    const uint32_t outside[] = { TEXT_BASE + TEXT_SIZE };
    const uint32_t one_address[] = { TEXT_BASE + 4u };
    const uint32_t below[] = { TEXT_BASE - 1u };
    const GuestFunction one_fn[] = { fn_first };
    const GuestFunction null_fn[] = { NULL };

    CHECK(expect_init_error(TEXT_BASE, 0, NULL, NULL, 0, EINVAL,
                            "zero text size") == 0,
          "zero-size table is rejected transactionally");
    CHECK(expect_init_error(0, 64u * 1024u * 1024u + 1u, NULL, NULL, 0,
                            EINVAL, "text size limit") == 0,
          "oversized text range is rejected");
    CHECK(expect_init_error(0xfffff000u, 0x2000u, NULL, NULL, 0, EINVAL,
                            "text range overflows 4 GiB") == 0,
          "text-range overflow is rejected");
    CHECK(expect_init_error(TEXT_BASE, TEXT_SIZE, NULL, one_fn, 1, EINVAL,
                            "missing address array") == 0,
          "missing address array is rejected");
    CHECK(expect_init_error(TEXT_BASE, TEXT_SIZE, one_address, NULL, 1, EINVAL,
                            "missing function array") == 0,
          "missing function array is rejected");
    CHECK(expect_init_error(TEXT_BASE, TEXT_SIZE, duplicate, duplicate_fns, 2,
                            EEXIST, "duplicate address") == 0,
          "duplicate guest addresses are rejected");
    CHECK(expect_init_error(TEXT_BASE, TEXT_SIZE, outside, one_fn, 1, EINVAL,
                            "address at end") == 0,
          "address at the exclusive text end is rejected");
    CHECK(expect_init_error(TEXT_BASE, TEXT_SIZE, below, one_fn, 1, EINVAL,
                            "address below base") == 0,
          "wrapped subtraction cannot alias a below-base address");
    CHECK(expect_init_error(TEXT_BASE, TEXT_SIZE, outside, null_fn, 1, EINVAL,
                            "null function") == 0,
          "null function entries are rejected");
    return 0;
}

static int test_lookup_and_lifecycle(void) {
    GuestDispatch table = { 0 };
    /* Intentionally unsorted: lookup is by exact address, not array order. */
    const uint32_t addresses[] = {
        TEXT_BASE + 0x700u, TEXT_BASE, TEXT_BASE + TEXT_SIZE - 1u
    };
    const GuestFunction functions[] = { fn_middle, fn_first, fn_last };

    CHECK(guest_dispatch_init(&table, TEXT_BASE, TEXT_SIZE,
                              addresses, functions, 3) == 0,
          "valid function table initializes");
    CHECK(guest_dispatch_lookup(&table, TEXT_BASE) == fn_first,
          "base address resolves to its exact function");
    CHECK(guest_dispatch_lookup(&table, TEXT_BASE + 0x700u) == fn_middle,
          "interior function resolves independent of array ordering");
    CHECK(guest_dispatch_lookup(&table, TEXT_BASE + TEXT_SIZE - 1u) == fn_last,
          "last address inside the range resolves");
    CHECK(guest_dispatch_lookup(&table, TEXT_BASE + 0x701u) == NULL,
          "an unregistered interior address remains unresolved");
    CHECK(guest_dispatch_lookup(&table, TEXT_BASE - 1u) == NULL,
          "address immediately below the range is unresolved");
    CHECK(guest_dispatch_lookup(&table, TEXT_BASE + TEXT_SIZE) == NULL,
          "exclusive end address is unresolved");
    CHECK(guest_dispatch_init(&table, TEXT_BASE, TEXT_SIZE,
                              addresses, functions, 3) == EBUSY,
          "active table cannot be initialized over");

    guest_dispatch_destroy(&table);
    CHECK(table.indices == NULL && table.addresses == NULL &&
          table.functions == NULL && table.count == 0,
          "destroy clears the full lifecycle state");
    CHECK(guest_dispatch_lookup(&table, TEXT_BASE) == NULL,
          "destroyed table does not resolve stale functions");
    guest_dispatch_destroy(&table);
    CHECK(guest_dispatch_init(&table, TEXT_BASE, TEXT_SIZE,
                              addresses, functions, 3) == 0,
          "destroyed table can be initialized again");
    guest_dispatch_destroy(&table);
    return 0;
}

static int test_four_gib_boundary(void) {
    GuestDispatch table = { 0 };
    const uint32_t base = UINT32_C(0xffffc000);
    const uint32_t address[] = { UINT32_MAX };
    const GuestFunction functions[] = { fn_last };

    CHECK(guest_dispatch_init(&table, base, 0x4000u,
                              address, functions, 1) == 0,
          "text range ending exactly at 4 GiB is accepted");
    CHECK(guest_dispatch_lookup(&table, UINT32_MAX) == fn_last,
          "final 32-bit guest address resolves without wrap");
    CHECK(guest_dispatch_lookup(&table, base - 1u) == NULL,
          "address below a top-of-space range does not wrap into it");
    CHECK(guest_dispatch_lookup(&table, 0) == NULL,
          "address zero does not alias the final guest range");
    guest_dispatch_destroy(&table);
    return 0;
}

int main(void) {
    CHECK(guest_dispatch_init(NULL, TEXT_BASE, TEXT_SIZE, NULL, NULL, 0) == EINVAL,
          "null table pointer is rejected");
    CHECK(test_table_validation() == 0, "table validation cases pass");
    CHECK(test_lookup_and_lifecycle() == 0, "lookup and lifecycle cases pass");
    CHECK(test_four_gib_boundary() == 0, "4 GiB edge cases pass");
    puts("PASS guest dispatch core");
    return 0;
}
