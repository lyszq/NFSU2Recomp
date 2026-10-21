#include "cpu_flags_test.h"

#include "../../runtime/cpu.h"

#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>

/* Keep the oracle's flag positions separate from cpu.h's definitions. */
enum {
    TEST_F_CF = 0x01u,
    TEST_F_PF = 0x02u,
    TEST_F_AF = 0x04u,
    TEST_F_ZF = 0x08u,
    TEST_F_SF = 0x10u,
    TEST_F_OF = 0x20u,
    TEST_F_ALL = 0x3fu
};

enum {
    TEST_EFLAGS_CF = 1u << 0,
    TEST_EFLAGS_PF = 1u << 2,
    TEST_EFLAGS_AF = 1u << 4,
    TEST_EFLAGS_ZF = 1u << 6,
    TEST_EFLAGS_SF = 1u << 7,
    TEST_EFLAGS_DF = 1u << 10,
    TEST_EFLAGS_OF = 1u << 11,
    TEST_EFLAGS_ID = 1u << 21,
    TEST_EFLAGS_SUPPORTED = TEST_EFLAGS_CF | TEST_EFLAGS_PF | TEST_EFLAGS_AF |
                            TEST_EFLAGS_ZF | TEST_EFLAGS_SF | TEST_EFLAGS_DF |
                            TEST_EFLAGS_OF | TEST_EFLAGS_ID,
    TEST_EFLAGS_FIXED = 0x00000202u
};

typedef enum {
    OP_ADD,
    OP_SUB,
    OP_ADC,
    OP_SBB
} ArithmeticOp;

typedef struct {
    uint32_t result;
    uint32_t cf;
    uint32_t pf;
    uint32_t af;
    uint32_t zf;
    uint32_t sf;
    uint32_t of;
} Reference;

static const char *op_name(ArithmeticOp op) {
    switch (op) {
        case OP_ADD: return "ADD";
        case OP_SUB: return "SUB";
        case OP_ADC: return "ADC";
        case OP_SBB: return "SBB";
    }
    return "UNKNOWN";
}

static uint32_t width_mask(unsigned bits) {
    return (uint32_t)((UINT64_C(1) << bits) - UINT64_C(1));
}

static int64_t signed_value(uint32_t value, uint32_t mask, uint32_t sign_bit) {
    if ((value & sign_bit) != 0u) {
        return (int64_t)value - ((int64_t)mask + 1);
    }
    return (int64_t)value;
}

static uint32_t even_parity_low_byte(uint32_t value) {
    unsigned ones = 0;
    value &= 0xffu;
    for (unsigned bit = 0; bit < 8u; ++bit) {
        ones += (value >> bit) & 1u;
    }
    return (uint32_t)((ones & 1u) == 0u);
}

/* Independent reference: widened unsigned arithmetic for wrap/carry and
 * widened signed arithmetic for OF. It does not use cpu.h's flag formulas. */
static Reference reference_for(ArithmeticOp op, unsigned bits,
                               uint32_t a, uint32_t b, uint32_t carry_in) {
    const uint32_t mask = width_mask(bits);
    const uint32_t sign_bit = UINT32_C(1) << (bits - 1u);
    const uint64_t unsigned_a = (uint64_t)(a & mask);
    const uint64_t unsigned_b = (uint64_t)(b & mask);
    const int64_t signed_a = signed_value((uint32_t)unsigned_a, mask, sign_bit);
    const int64_t signed_b = signed_value((uint32_t)unsigned_b, mask, sign_bit);
    uint64_t wide_result;
    int64_t signed_result;
    int is_add;

    switch (op) {
        case OP_ADD:
            wide_result = unsigned_a + unsigned_b;
            signed_result = signed_a + signed_b;
            is_add = 1;
            break;
        case OP_ADC:
            wide_result = unsigned_a + unsigned_b + (uint64_t)carry_in;
            signed_result = signed_a + signed_b + (int64_t)carry_in;
            is_add = 1;
            break;
        case OP_SUB:
            wide_result = unsigned_a - unsigned_b;
            signed_result = signed_a - signed_b;
            is_add = 0;
            break;
        case OP_SBB:
            wide_result = unsigned_a - unsigned_b - (uint64_t)carry_in;
            signed_result = signed_a - signed_b - (int64_t)carry_in;
            is_add = 0;
            break;
        default:
            wide_result = 0u;
            signed_result = 0;
            is_add = 1;
            break;
    }

    Reference expected = {0};
    expected.result = (uint32_t)(wide_result & (uint64_t)mask);
    expected.cf = is_add
        ? (uint32_t)(wide_result > (uint64_t)mask)
        : (uint32_t)(unsigned_a < unsigned_b + (uint64_t)carry_in);
    expected.pf = even_parity_low_byte(expected.result);
    expected.af = is_add
        ? (uint32_t)(((a & 0x0fu) + (b & 0x0fu) + carry_in) > 0x0fu)
        : (uint32_t)((a & 0x0fu) < ((b & 0x0fu) + carry_in));
    expected.zf = (uint32_t)(expected.result == 0u);
    expected.sf = (uint32_t)((expected.result & sign_bit) != 0u);

    const int64_t signed_limit = (int64_t)(UINT64_C(1) << (bits - 1u));
    expected.of = (uint32_t)(signed_result < -signed_limit ||
                             signed_result > signed_limit - 1);
    return expected;
}

#define DEFINE_APPLIER(bits, type)                                             \
    static uint32_t apply_##bits(CPU *c, ArithmeticOp op, uint32_t a,         \
                                 uint32_t b, uint32_t carry_in,                \
                                 uint32_t flag_mask) {                         \
        const type aa = (type)a;                                               \
        const type bb = (type)b;                                               \
        const type cc = (type)carry_in;                                        \
        type result;                                                           \
        switch (op) {                                                          \
            case OP_ADD:                                                       \
                result = (type)(aa + bb);                                      \
                FLAGS_ADD_M(aa, bb, result, bits, flag_mask);                  \
                break;                                                         \
            case OP_SUB:                                                       \
                result = (type)(aa - bb);                                      \
                FLAGS_SUB_M(aa, bb, result, bits, flag_mask);                  \
                break;                                                         \
            case OP_ADC:                                                       \
                result = (type)(aa + bb + cc);                                 \
                FLAGS_ADC_M(aa, bb, cc, result, bits, flag_mask);              \
                break;                                                         \
            case OP_SBB:                                                       \
                result = (type)(aa - bb - cc);                                 \
                FLAGS_SBB_M(aa, bb, cc, result, bits, flag_mask);              \
                break;                                                         \
            default:                                                           \
                return 0u;                                                     \
        }                                                                      \
        return (uint32_t)result;                                               \
    }

DEFINE_APPLIER(8, uint8_t)
DEFINE_APPLIER(16, uint16_t)
DEFINE_APPLIER(32, uint32_t)

#undef DEFINE_APPLIER

static uint32_t apply_flags(CPU *c, ArithmeticOp op, unsigned bits,
                            uint32_t a, uint32_t b, uint32_t carry_in,
                            uint32_t flag_mask) {
    switch (bits) {
        case 8u: return apply_8(c, op, a, b, carry_in, flag_mask);
        case 16u: return apply_16(c, op, a, b, carry_in, flag_mask);
        case 32u: return apply_32(c, op, a, b, carry_in, flag_mask);
        default: return 0u;
    }
}

static int matches_flags(const CPU *c, const Reference *expected,
                         uint32_t flag_mask, uint32_t initial,
                         uint32_t initial_df, uint32_t initial_id) {
    const uint32_t cf = (flag_mask & TEST_F_CF) ? expected->cf : initial;
    const uint32_t pf = (flag_mask & TEST_F_PF) ? expected->pf : initial;
    const uint32_t af = (flag_mask & TEST_F_AF) ? expected->af : initial;
    const uint32_t zf = (flag_mask & TEST_F_ZF) ? expected->zf : initial;
    const uint32_t sf = (flag_mask & TEST_F_SF) ? expected->sf : initial;
    const uint32_t of = (flag_mask & TEST_F_OF) ? expected->of : initial;

    return c->cf == cf && c->pf == pf && c->af == af && c->zf == zf &&
           c->sf == sf && c->of == of && c->df == initial_df &&
           c->id_flag == initial_id;
}

static int fail_arithmetic(char *out, size_t n, const char *phase,
                           ArithmeticOp op, unsigned bits, uint32_t a,
                           uint32_t b, uint32_t carry_in, uint32_t mask,
                           uint32_t expected_result, uint32_t actual_result,
                           const Reference *expected, const CPU *actual,
                           uint32_t expected_id) {
    if (n != 0u) {
        (void)snprintf(out, n,
            "FAIL | %s | %s%u a=%08" PRIx32 " b=%08" PRIx32
            " cin=%" PRIu32 " mask=%02" PRIx32
            " result=%08" PRIx32 "/%08" PRIx32
            " flags CF/PF/AF/ZF/SF/OF expected=%u%u%u%u%u%u got=%u%u%u%u%u%u"
            " ID expected=%" PRIu32 " got=%" PRIu32,
            phase, op_name(op), bits, a, b, carry_in, mask,
            expected_result, actual_result,
            expected->cf, expected->pf, expected->af, expected->zf,
            expected->sf, expected->of,
            actual->cf, actual->pf, actual->af, actual->zf,
            actual->sf, actual->of, expected_id, actual->id_flag);
    }
    return 1;
}

static int check_arithmetic(char *out, size_t n, ArithmeticOp op, unsigned bits,
                            uint32_t a, uint32_t b, uint32_t carry_in,
                            uint64_t *case_count) {
    const uint32_t mask = width_mask(bits);
    a &= mask;
    b &= mask;
    carry_in &= 1u;

    const Reference expected = reference_for(op, bits, a, b, carry_in);
    CPU actual = {0};
    const uint32_t actual_result = apply_flags(&actual, op, bits, a, b,
                                               carry_in, TEST_F_ALL);
    if (actual_result != expected.result ||
        !matches_flags(&actual, &expected, TEST_F_ALL, 0u, 0u, 0u)) {
        return fail_arithmetic(out, n, "arithmetic reference", op, bits,
                               a, b, carry_in, TEST_F_ALL, expected.result,
                               actual_result, &expected, &actual, 0u);
    }
    ++*case_count;
    return 0;
}

static void set_all_flags(CPU *c, uint32_t value) {
    c->cf = value;
    c->pf = value;
    c->af = value;
    c->zf = value;
    c->sf = value;
    c->of = value;
    c->df = value;
    c->id_flag = value;
}

static int check_flag_masks(char *out, size_t n, uint64_t *mask_count) {
    static const uint32_t masks[] = {
        0u,
        TEST_F_CF, TEST_F_PF, TEST_F_AF, TEST_F_ZF, TEST_F_SF, TEST_F_OF,
        TEST_F_CF | TEST_F_ZF | TEST_F_OF,
        TEST_F_PF | TEST_F_AF | TEST_F_SF,
        TEST_F_ALL
    };
    static const unsigned widths[] = {8u, 16u, 32u};
    static const ArithmeticOp ops[] = {OP_ADD, OP_SUB, OP_ADC, OP_SBB};

    for (size_t wi = 0; wi < sizeof widths / sizeof widths[0]; ++wi) {
        const unsigned bits = widths[wi];
        const uint32_t mask = width_mask(bits);
        const uint32_t signed_max = (UINT32_C(1) << (bits - 1u)) - 1u;
        for (size_t oi = 0; oi < sizeof ops / sizeof ops[0]; ++oi) {
            const ArithmeticOp op = ops[oi];
            const uint32_t a = (op == OP_SUB || op == OP_SBB) ? 0u : signed_max;
            const uint32_t b = 1u;
            const uint32_t carry_in = (op == OP_ADC || op == OP_SBB) ? 1u : 0u;
            const Reference expected = reference_for(op, bits, a, b, carry_in);

            for (size_t mi = 0; mi < sizeof masks / sizeof masks[0]; ++mi) {
                const uint32_t flag_mask = masks[mi];
                for (uint32_t sentinel = 0u; sentinel <= 1u; ++sentinel) {
                    CPU actual = {0};
                    set_all_flags(&actual, sentinel);
                    const uint32_t actual_result = apply_flags(
                        &actual, op, bits, a & mask, b & mask, carry_in,
                        flag_mask);
                    if (actual_result != expected.result ||
                        !matches_flags(&actual, &expected, flag_mask,
                                       sentinel, sentinel, sentinel)) {
                        return fail_arithmetic(out, n, "flag-mask preservation",
                                               op, bits, a, b, carry_in,
                                               flag_mask, expected.result,
                                               actual_result, &expected, &actual,
                                               sentinel);
                    }
                    ++*mask_count;
                }
            }
        }
    }
    return 0;
}

typedef struct {
    ArithmeticOp op;
    uint32_t a;
    uint32_t b;
    uint32_t carry_in;
} BoundaryCase;

static int check_boundary_vectors(char *out, size_t n, uint64_t *case_count) {
    static const unsigned widths[] = {16u, 32u};

    for (size_t wi = 0; wi < sizeof widths / sizeof widths[0]; ++wi) {
        const unsigned bits = widths[wi];
        const uint32_t mask = width_mask(bits);
        const uint32_t sign = UINT32_C(1) << (bits - 1u);
        const uint32_t signed_max = sign - 1u;
        const BoundaryCase cases[] = {
            {OP_ADD, signed_max, 1u, 0u},
            {OP_ADD, mask, 1u, 0u},
            {OP_ADC, mask, 0u, 0u},
            {OP_ADC, mask, 0u, 1u},
            {OP_ADC, signed_max, 0u, 1u},
            {OP_SUB, 0u, 1u, 0u},
            {OP_SUB, sign, 1u, 0u},
            {OP_SBB, 0u, 0u, 0u},
            {OP_SBB, 0u, 0u, 1u},
            {OP_SBB, 0u, mask, 1u},
            {OP_SBB, mask, mask, 1u}
        };

        for (size_t ci = 0; ci < sizeof cases / sizeof cases[0]; ++ci) {
            if (check_arithmetic(out, n, cases[ci].op, bits,
                                 cases[ci].a, cases[ci].b,
                                 cases[ci].carry_in, case_count)) {
                return 1;
            }
        }
    }
    return 0;
}

static uint32_t encode_flag_pattern(uint32_t pattern) {
    uint32_t eflags = 0u;
    if ((pattern & (1u << 0)) != 0u) eflags |= TEST_EFLAGS_CF;
    if ((pattern & (1u << 1)) != 0u) eflags |= TEST_EFLAGS_PF;
    if ((pattern & (1u << 2)) != 0u) eflags |= TEST_EFLAGS_AF;
    if ((pattern & (1u << 3)) != 0u) eflags |= TEST_EFLAGS_ZF;
    if ((pattern & (1u << 4)) != 0u) eflags |= TEST_EFLAGS_SF;
    if ((pattern & (1u << 5)) != 0u) eflags |= TEST_EFLAGS_DF;
    if ((pattern & (1u << 6)) != 0u) eflags |= TEST_EFLAGS_OF;
    return eflags;
}

static int check_eflags_pack_unpack(char *out, size_t n, uint64_t *pattern_count) {
    CPU toggled = {0};
    const uint32_t base_flags = TEST_EFLAGS_FIXED | TEST_EFLAGS_CF;
    eflags_set(&toggled, base_flags);
    eflags_set(&toggled, eflags_get(&toggled) | TEST_EFLAGS_ID);
    if (toggled.id_flag != 1u ||
        eflags_get(&toggled) != (base_flags | TEST_EFLAGS_ID)) {
        if (n != 0u) (void)snprintf(out, n, "FAIL | EFLAGS ID set toggle");
        return 1;
    }
    eflags_set(&toggled, eflags_get(&toggled) & ~((uint32_t)TEST_EFLAGS_ID));
    if (toggled.id_flag != 0u || eflags_get(&toggled) != base_flags) {
        if (n != 0u) (void)snprintf(out, n, "FAIL | EFLAGS ID clear toggle");
        return 1;
    }

    for (uint32_t pattern = 0; pattern < 128u; ++pattern) {
        const uint32_t encoded = encode_flag_pattern(pattern);
        for (uint32_t id = 0u; id <= 1u; ++id) {
            const uint32_t id_bits = id ? TEST_EFLAGS_ID : 0u;
            /* Set every unsupported/reserved bit too; unpack must ignore them. */
            const uint32_t input = encoded | id_bits |
                                   ~((uint32_t)TEST_EFLAGS_SUPPORTED);
            const uint32_t expected = TEST_EFLAGS_FIXED | encoded | id_bits;
            CPU c = {0};
            set_all_flags(&c, 1u);
            eflags_set(&c, input);

            if (c.cf != ((pattern >> 0) & 1u) ||
                c.pf != ((pattern >> 1) & 1u) ||
                c.af != ((pattern >> 2) & 1u) ||
                c.zf != ((pattern >> 3) & 1u) ||
                c.sf != ((pattern >> 4) & 1u) ||
                c.df != ((pattern >> 5) & 1u) ||
                c.of != ((pattern >> 6) & 1u) || c.id_flag != id ||
                eflags_get(&c) != expected) {
                if (n != 0u) {
                    (void)snprintf(out, n,
                        "FAIL | EFLAGS pack/unpack | pattern=%02" PRIx32
                        " id=%" PRIu32 " input=%08" PRIx32
                        " expected=%08" PRIx32 " got=%08" PRIx32,
                        pattern, id, input, expected, eflags_get(&c));
                }
                return 1;
            }
            ++*pattern_count;
        }
    }
    return 0;
}

int nfs_cpu_flags_test(char *diagnostics, size_t diagnostics_capacity) {
    if (diagnostics == NULL || diagnostics_capacity == 0u) return 1;
    diagnostics[0] = '\0';

    uint64_t arithmetic_cases = 0u;
    uint64_t mask_cases = 0u;
    uint64_t eflags_patterns = 0u;

    /* Every 8-bit operand pair; ADC/SBB run with both carry-in values. */
    for (uint32_t a = 0u; a <= 0xffu; ++a) {
        for (uint32_t b = 0u; b <= 0xffu; ++b) {
            if (check_arithmetic(diagnostics, diagnostics_capacity, OP_ADD, 8u,
                                 a, b, 0u, &arithmetic_cases) ||
                check_arithmetic(diagnostics, diagnostics_capacity, OP_SUB, 8u,
                                 a, b, 0u, &arithmetic_cases)) {
                return 1;
            }
            for (uint32_t carry_in = 0u; carry_in <= 1u; ++carry_in) {
                if (check_arithmetic(diagnostics, diagnostics_capacity, OP_ADC,
                                     8u, a, b, carry_in, &arithmetic_cases) ||
                    check_arithmetic(diagnostics, diagnostics_capacity, OP_SBB,
                                     8u, a, b, carry_in, &arithmetic_cases)) {
                    return 1;
                }
            }
        }
    }

    if (check_boundary_vectors(diagnostics, diagnostics_capacity,
                               &arithmetic_cases) ||
        check_flag_masks(diagnostics, diagnostics_capacity, &mask_cases) ||
        check_eflags_pack_unpack(diagnostics, diagnostics_capacity,
                                 &eflags_patterns)) {
        return 1;
    }

    (void)snprintf(diagnostics, diagnostics_capacity,
        "PASS | CPU flags | %" PRIu64
        " arithmetic cases (393216 exhaustive 8-bit + 22 16/32-bit boundaries)"
        " | %" PRIu64 " mask-preservation cases"
        " | %" PRIu64 " EFLAGS pack/unpack patterns",
        arithmetic_cases, mask_cases, eflags_patterns);
    return 0;
}
