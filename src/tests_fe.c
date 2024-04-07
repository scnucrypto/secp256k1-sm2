/***********************************************************************
 * Copyright (c) 2013, 2014, 2015 Pieter Wuille, Gregory Maxwell       *
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

#include "libsecp256k1-config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <time.h>

#include "secp256k1.c"
#include "../include/secp256k1.h"
#include "../include/secp256k1_preallocated.h"
#include "testrand_impl.h"
#include "util.h"

#include "../contrib/lax_der_parsing.c"
#include "../contrib/lax_der_privatekey_parsing.c"

#include "modinv32_impl.h"
#ifdef SECP256K1_WIDEMUL_INT128
#include "modinv64_impl.h"
#endif

static int count = 64;
static secp256k1_context *ctx = NULL;


void random_field_element_magnitude(secp256k1_fe *fe) {
    secp256k1_fe zero;
    int n = secp256k1_testrand_int(9);
    secp256k1_fe_normalize(fe);
    if (n == 0) {
        return;
    }
    secp256k1_fe_clear(&zero);
    secp256k1_fe_negate(&zero, &zero, 0);
    secp256k1_fe_mul_int(&zero, n - 1);
    secp256k1_fe_add(fe, &zero);
#ifdef VERIFY
    CHECK(fe->magnitude == n);
#endif
}

/* compute out = (a*b) mod m; if b=NULL, treat b=1.
 *
 * Out is a 512-bit number (represented as 32 uint16_t's in LE order). The other
 * arguments are 256-bit numbers (represented as 16 uint16_t's in LE order). */
void mulmod256(uint16_t* out, const uint16_t* a, const uint16_t* b, const uint16_t* m) {
    uint16_t mul[32];
    uint64_t c = 0;
    int i, j;
    int m_bitlen = 0;
    int mul_bitlen = 0;

    if (b != NULL) {
        /* Compute the product of a and b, and put it in mul. */
        for (i = 0; i < 32; ++i) {
            for (j = i <= 15 ? 0 : i - 15; j <= i && j <= 15; j++) {
                c += (uint64_t)a[j] * b[i - j];
            }
            mul[i] = c & 0xFFFF;
            c >>= 16;
        }
        CHECK(c == 0);

        /* compute the highest set bit in mul */
        for (i = 511; i >= 0; --i) {
            if ((mul[i >> 4] >> (i & 15)) & 1) {
                mul_bitlen = i;
                break;
            }
        }
    } else {
        /* if b==NULL, set mul=a. */
        memcpy(mul, a, 32);
        memset(mul + 16, 0, 32);
        /* compute the highest set bit in mul */
        for (i = 255; i >= 0; --i) {
            if ((mul[i >> 4] >> (i & 15)) & 1) {
                mul_bitlen = i;
                break;
            }
        }
    }

    /* Compute the highest set bit in m. */
    for (i = 255; i >= 0; --i) {
        if ((m[i >> 4] >> (i & 15)) & 1) {
            m_bitlen = i;
            break;
        }
    }

    /* Try do mul -= m<<i, for i going down to 0, whenever the result is not negative */
    for (i = mul_bitlen - m_bitlen; i >= 0; --i) {
        uint16_t mul2[32];
        int64_t cs;

        /* Compute mul2 = mul - m<<i. */
        cs = 0; /* accumulator */
        for (j = 0; j < 32; ++j) { /* j loops over the output limbs in mul2. */
            /* Compute sub: the 16 bits in m that will be subtracted from mul2[j]. */
            uint16_t sub = 0;
            int p;
            for (p = 0; p < 16; ++p) { /* p loops over the bit positions in mul2[j]. */
                int bitpos = j * 16 - i + p; /* bitpos is the correspond bit position in m. */
                if (bitpos >= 0 && bitpos < 256) {
                    sub |= ((m[bitpos >> 4] >> (bitpos & 15)) & 1) << p;
                }
            }
            /* Add mul[j]-sub to accumulator, and shift bottom 16 bits out to mul2[j]. */
            cs += mul[j];
            cs -= sub;
            mul2[j] = (cs & 0xFFFF);
            cs >>= 16;
        }
        /* If remainder of subtraction is 0, set mul = mul2. */
        if (cs == 0) {
            memcpy(mul, mul2, sizeof(mul));
        }
    }
    /* Sanity check: test that all limbs higher than m's highest are zero */
    for (i = (m_bitlen >> 4) + 1; i < 32; ++i) {
        CHECK(mul[i] == 0);
    }
    memcpy(out, mul, 32);
}


/***** FIELD TESTS *****/
void random_fe(secp256k1_fe *x) {
    unsigned char bin[32];
    do {
        secp256k1_testrand256(bin);
        if (secp256k1_fe_set_b32(x, bin)) {
            return;
        }
    } while(1);
}

void random_fe_test(secp256k1_fe *x) {
    unsigned char bin[32];
    do {
        secp256k1_testrand256_test(bin);
        if (secp256k1_fe_set_b32(x, bin)) {
            return;
        }
    } while(1);
}

void random_fe_non_zero(secp256k1_fe *nz) {
    int tries = 10;
    while (--tries >= 0) {
        random_fe(nz);
        secp256k1_fe_normalize(nz);
        if (!secp256k1_fe_is_zero(nz)) {
            break;
        }
    }
    /* Infinitesimal probability of spurious failure here */
    CHECK(tries >= 0);
}

void random_fe_non_square(secp256k1_fe *ns) {
    secp256k1_fe r;
    random_fe_non_zero(ns);
    if (secp256k1_fe_sqrt(&r, ns)) {
        secp256k1_fe_negate(ns, ns, 1);
    }
}

int check_fe_equal(const secp256k1_fe *a, const secp256k1_fe *b) {
    secp256k1_fe an = *a;
    secp256k1_fe bn = *b;
    secp256k1_fe_normalize_weak(&an);
    secp256k1_fe_normalize_var(&bn);
    return secp256k1_fe_equal_var(&an, &bn);
}

void run_field_convert(void) {
    static const unsigned char b32[32] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29,
        0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x40
    };
    static const secp256k1_fe_storage fes = SECP256K1_FE_STORAGE_CONST(
        0x00010203UL, 0x04050607UL, 0x11121314UL, 0x15161718UL,
        0x22232425UL, 0x26272829UL, 0x33343536UL, 0x37383940UL
    );
    static const secp256k1_fe fe = SECP256K1_FE_CONST(
        0x00010203UL, 0x04050607UL, 0x11121314UL, 0x15161718UL,
        0x22232425UL, 0x26272829UL, 0x33343536UL, 0x37383940UL
    );
    secp256k1_fe fe2;
    unsigned char b322[32];
    secp256k1_fe_storage fes2;
    /* Check conversions to fe. */
    CHECK(secp256k1_fe_set_b32(&fe2, b32));
    CHECK(secp256k1_fe_equal_var(&fe, &fe2));
    secp256k1_fe_from_storage(&fe2, &fes);
    CHECK(secp256k1_fe_equal_var(&fe, &fe2));
    /* Check conversion from fe. */
    secp256k1_fe_get_b32(b322, &fe);
    CHECK(secp256k1_memcmp_var(b322, b32, 32) == 0);
    secp256k1_fe_to_storage(&fes2, &fe);
    CHECK(secp256k1_memcmp_var(&fes2, &fes, sizeof(fes)) == 0);
}

/* Returns true if two field elements have the same representation. */
int fe_identical(const secp256k1_fe *a, const secp256k1_fe *b) {
    int ret = 1;
#ifdef VERIFY
    ret &= (a->magnitude == b->magnitude);
    ret &= (a->normalized == b->normalized);
#endif
    /* Compare the struct member that holds the limbs. */
    ret &= (secp256k1_memcmp_var(a->n, b->n, sizeof(a->n)) == 0);
    return ret;
}

void run_field_misc(void) {
    secp256k1_fe x;
    secp256k1_fe y;
    secp256k1_fe z;
    secp256k1_fe q;
    secp256k1_fe fe5 = SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 5);
    int i, j;
    // for (i = 0; i < 5*count; i++) {
    for (i = 0; i < 1; i++) {

        secp256k1_fe_storage xs, ys, zs;
        random_fe(&x);
        random_fe_non_zero(&y);
        /* Test the fe equality and comparison operations. */
        CHECK(secp256k1_fe_cmp_var(&x, &x) == 0);
        CHECK(secp256k1_fe_equal_var(&x, &x));
        z = x;
        secp256k1_fe_add(&z,&y);
        /* Test fe conditional move; z is not normalized here. */
        q = x;
        secp256k1_fe_cmov(&x, &z, 0);
#ifdef VERIFY
        CHECK(x.normalized && x.magnitude == 1);
#endif
        secp256k1_fe_cmov(&x, &x, 1);
        CHECK(!fe_identical(&x, &z));
        CHECK(fe_identical(&x, &q));
        secp256k1_fe_cmov(&q, &z, 1);
#ifdef VERIFY
        CHECK(!q.normalized && q.magnitude == z.magnitude);
#endif
        CHECK(fe_identical(&q, &z));
        secp256k1_fe_normalize_var(&x);
        secp256k1_fe_normalize_var(&z);
        CHECK(!secp256k1_fe_equal_var(&x, &z));
        secp256k1_fe_normalize_var(&q);
        secp256k1_fe_cmov(&q, &z, (i&1));
#ifdef VERIFY
        CHECK(q.normalized && q.magnitude == 1);
#endif
        for (j = 0; j < 6; j++) {
            secp256k1_fe_negate(&z, &z, j+1);
            secp256k1_fe_normalize_var(&q);
            secp256k1_fe_cmov(&q, &z, (j&1));
#ifdef VERIFY
            CHECK((q.normalized != (j&1)) && q.magnitude == ((j&1) ? z.magnitude : 1));
#endif
        }
        secp256k1_fe_normalize_var(&z);
        /* Test storage conversion and conditional moves. */
        secp256k1_fe_to_storage(&xs, &x);
        secp256k1_fe_to_storage(&ys, &y);
        secp256k1_fe_to_storage(&zs, &z);
        secp256k1_fe_storage_cmov(&zs, &xs, 0);
        secp256k1_fe_storage_cmov(&zs, &zs, 1);
        CHECK(secp256k1_memcmp_var(&xs, &zs, sizeof(xs)) != 0);
        secp256k1_fe_storage_cmov(&ys, &xs, 1);
        CHECK(secp256k1_memcmp_var(&xs, &ys, sizeof(xs)) == 0);
        secp256k1_fe_from_storage(&x, &xs);
        secp256k1_fe_from_storage(&y, &ys);
        secp256k1_fe_from_storage(&z, &zs);
        /* Test that mul_int, mul, and add agree. */
        secp256k1_fe_print("x", &x);
        secp256k1_fe_print("y", &y);
        secp256k1_fe_add(&y, &x);
        secp256k1_fe_print("x+y", &y);

        secp256k1_fe_add(&y, &x);
        z = x;
        secp256k1_fe_mul_int(&z, 3);
        CHECK(check_fe_equal(&y, &z));
        secp256k1_fe_add(&y, &x);
        secp256k1_fe_add(&z, &x);
        CHECK(check_fe_equal(&z, &y));
        z = x;
        secp256k1_fe_mul_int(&z, 5);
        secp256k1_fe_mul(&q, &x, &fe5);
        CHECK(check_fe_equal(&z, &q));
        secp256k1_fe_negate(&x, &x, 1);
        secp256k1_fe_add(&z, &x);
        secp256k1_fe_add(&q, &x);
        CHECK(check_fe_equal(&y, &z));
        CHECK(check_fe_equal(&q, &y));
    }
}

void test_fe_mul(const secp256k1_fe* a, const secp256k1_fe* b, int use_sqr)
{
    secp256k1_fe c, an, bn;
    /* Variables in BE 32-byte format. */
    unsigned char a32[32], b32[32], c32[32];
    /* Variables in LE 16x uint16_t format. */
    uint16_t a16[16], b16[16], c16[16];
    /* Field modulus in LE 16x uint16_t format. */
    static const uint16_t m16[16] = {
        0xfc2f, 0xffff, 0xfffe, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff,
        0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff,
    };
    uint16_t t16[32];
    int i;

    /* Compute C = A * B in fe format. */
    c = *a;
    if (use_sqr) {
        secp256k1_fe_sqr(&c, &c);
    } else {
        secp256k1_fe_mul(&c, &c, b);
    }

    /* Convert A, B, C into LE 16x uint16_t format. */
    an = *a;
    bn = *b;
    secp256k1_fe_normalize_var(&c);
    secp256k1_fe_normalize_var(&an);
    secp256k1_fe_normalize_var(&bn);
    secp256k1_fe_get_b32(a32, &an);
    secp256k1_fe_get_b32(b32, &bn);
    secp256k1_fe_get_b32(c32, &c);
    for (i = 0; i < 16; ++i) {
        a16[i] = a32[31 - 2*i] + ((uint16_t)a32[30 - 2*i] << 8);
        b16[i] = b32[31 - 2*i] + ((uint16_t)b32[30 - 2*i] << 8);
        c16[i] = c32[31 - 2*i] + ((uint16_t)c32[30 - 2*i] << 8);
    }
    /* Compute T = A * B in LE 16x uint16_t format. */
    mulmod256(t16, a16, b16, m16);
    /* Compare */
    CHECK(secp256k1_memcmp_var(t16, c16, 32) == 0);
}

void run_fe_mul(void) {
    int i;
    for (i = 0; i < 100 * count; ++i) {
        secp256k1_fe a, b, c, d;
        random_fe(&a);
        random_field_element_magnitude(&a);
        random_fe(&b);
        random_field_element_magnitude(&b);
        random_fe_test(&c);
        random_field_element_magnitude(&c);
        random_fe_test(&d);
        random_field_element_magnitude(&d);
        test_fe_mul(&a, &a, 1);
        test_fe_mul(&c, &c, 1);
        test_fe_mul(&a, &b, 0);
        test_fe_mul(&a, &c, 0);
        test_fe_mul(&c, &b, 0);
        test_fe_mul(&c, &d, 0);
    }
}

void run_sqr(void) {
    secp256k1_fe x, s;

    {
        int i;
        secp256k1_fe_set_int(&x, 1);
        secp256k1_fe_negate(&x, &x, 1);

        for (i = 1; i <= 512; ++i) {
            secp256k1_fe_mul_int(&x, 2);
            secp256k1_fe_normalize(&x);
            secp256k1_fe_sqr(&s, &x);
        }
    }
}

void test_sqrt(const secp256k1_fe *a, const secp256k1_fe *k) {
    secp256k1_fe r1, r2;
    int v = secp256k1_fe_sqrt(&r1, a);
    CHECK((v == 0) == (k == NULL));

    if (k != NULL) {
        /* Check that the returned root is +/- the given known answer */
        secp256k1_fe_negate(&r2, &r1, 1);
        secp256k1_fe_add(&r1, k); secp256k1_fe_add(&r2, k);
        secp256k1_fe_normalize(&r1); secp256k1_fe_normalize(&r2);
        CHECK(secp256k1_fe_is_zero(&r1) || secp256k1_fe_is_zero(&r2));
    }
}

void run_sqrt(void) {
    secp256k1_fe ns, x, s, t;
    int i;

    /* Check sqrt(0) is 0 */
    secp256k1_fe_set_int(&x, 0);
    secp256k1_fe_sqr(&s, &x);
    test_sqrt(&s, &x);

    /* Check sqrt of small squares (and their negatives) */
    for (i = 1; i <= 100; i++) {
        secp256k1_fe_set_int(&x, i);
        secp256k1_fe_sqr(&s, &x);
        test_sqrt(&s, &x);
        secp256k1_fe_negate(&t, &s, 1);
        test_sqrt(&t, NULL);
    }

    /* Consistency checks for large random values */
    for (i = 0; i < 10; i++) {
        int j;
        random_fe_non_square(&ns);
        for (j = 0; j < count; j++) {
            random_fe(&x);
            secp256k1_fe_sqr(&s, &x);
            test_sqrt(&s, &x);
            secp256k1_fe_negate(&t, &s, 1);
            test_sqrt(&t, NULL);
            secp256k1_fe_mul(&t, &s, &ns);
            test_sqrt(&t, NULL);
        }
    }
}

/***** FIELD/SCALAR INVERSE TESTS *****/

static const secp256k1_scalar scalar_minus_one = SECP256K1_SCALAR_CONST(
    0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFE,
    0xBAAEDCE6, 0xAF48A03B, 0xBFD25E8C, 0xD0364140
);

static const secp256k1_fe fe_minus_one = SECP256K1_FE_CONST(
    0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
    0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFE, 0xFFFFFC2E
);

/* These tests test the following identities:
 *
 * for x==0: 1/x == 0
 * for x!=0: x*(1/x) == 1
 * for x!=0 and x!=1: 1/(1/x - 1) + 1 == -1/(x-1)
 */

void test_inverse_scalar(secp256k1_scalar* out, const secp256k1_scalar* x, int var)
{
    secp256k1_scalar l, r, t;

    (var ? secp256k1_scalar_inverse_var : secp256k1_scalar_inverse)(&l, x);  /* l = 1/x */
    if (out) *out = l;
    if (secp256k1_scalar_is_zero(x)) {
        CHECK(secp256k1_scalar_is_zero(&l));
        return;
    }
    secp256k1_scalar_mul(&t, x, &l);                                             /* t = x*(1/x) */
    CHECK(secp256k1_scalar_is_one(&t));                                          /* x*(1/x) == 1 */
    secp256k1_scalar_add(&r, x, &scalar_minus_one);                              /* r = x-1 */
    if (secp256k1_scalar_is_zero(&r)) return;
    (var ? secp256k1_scalar_inverse_var : secp256k1_scalar_inverse)(&r, &r); /* r = 1/(x-1) */
    secp256k1_scalar_add(&l, &scalar_minus_one, &l);                             /* l = 1/x-1 */
    (var ? secp256k1_scalar_inverse_var : secp256k1_scalar_inverse)(&l, &l); /* l = 1/(1/x-1) */
    secp256k1_scalar_add(&l, &l, &secp256k1_scalar_one);                         /* l = 1/(1/x-1)+1 */
    secp256k1_scalar_add(&l, &r, &l);                                            /* l = 1/(1/x-1)+1 + 1/(x-1) */
    CHECK(secp256k1_scalar_is_zero(&l));                                         /* l == 0 */
}

void test_inverse_field(secp256k1_fe* out, const secp256k1_fe* x, int var)
{
    secp256k1_fe l, r, t;

    (var ? secp256k1_fe_inv_var : secp256k1_fe_inv)(&l, x) ;   /* l = 1/x */
    if (out) *out = l;
    t = *x;                                                    /* t = x */
    if (secp256k1_fe_normalizes_to_zero_var(&t)) {
        CHECK(secp256k1_fe_normalizes_to_zero(&l));
        return;
    }
    secp256k1_fe_mul(&t, x, &l);                               /* t = x*(1/x) */
    secp256k1_fe_add(&t, &fe_minus_one);                       /* t = x*(1/x)-1 */
    CHECK(secp256k1_fe_normalizes_to_zero(&t));                /* x*(1/x)-1 == 0 */
    r = *x;                                                    /* r = x */
    secp256k1_fe_add(&r, &fe_minus_one);                       /* r = x-1 */
    if (secp256k1_fe_normalizes_to_zero_var(&r)) return;
    (var ? secp256k1_fe_inv_var : secp256k1_fe_inv)(&r, &r);   /* r = 1/(x-1) */
    secp256k1_fe_add(&l, &fe_minus_one);                       /* l = 1/x-1 */
    (var ? secp256k1_fe_inv_var : secp256k1_fe_inv)(&l, &l);   /* l = 1/(1/x-1) */
    secp256k1_fe_add(&l, &secp256k1_fe_one);                   /* l = 1/(1/x-1)+1 */
    secp256k1_fe_add(&l, &r);                                  /* l = 1/(1/x-1)+1 + 1/(x-1) */
    CHECK(secp256k1_fe_normalizes_to_zero_var(&l));            /* l == 0 */
}

void run_inverse_tests(void)
{
    /* Fixed test cases for field inverses: pairs of (x, 1/x) mod p. */
    static const secp256k1_fe fe_cases[][2] = {
        /* 0 */
        {SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0),
         SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0)},
        /* 1 */
        {SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 1),
         SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 1)},
        /* -1 */
        {SECP256K1_FE_CONST(0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xfffffffe, 0xfffffc2e),
         SECP256K1_FE_CONST(0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xfffffffe, 0xfffffc2e)},
        /* 2 */
        {SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 2),
         SECP256K1_FE_CONST(0x7fffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0x7ffffe18)},
        /* 2**128 */
        {SECP256K1_FE_CONST(0, 0, 0, 1, 0, 0, 0, 0),
         SECP256K1_FE_CONST(0xbcb223fe, 0xdc24a059, 0xd838091d, 0xd2253530, 0xffffffff, 0xffffffff, 0xffffffff, 0x434dd931)},
        /* Input known to need 637 divsteps */
        {SECP256K1_FE_CONST(0xe34e9c95, 0x6bee8a84, 0x0dcb632a, 0xdb8a1320, 0x66885408, 0x06f3f996, 0x7c11ca84, 0x19199ec3),
         SECP256K1_FE_CONST(0xbd2cbd8f, 0x1c536828, 0x9bccda44, 0x2582ac0c, 0x870152b0, 0x8a3f09fb, 0x1aaadf92, 0x19b618e5)},
        /* Input known to need 567 divsteps starting with delta=1/2. */
        {SECP256K1_FE_CONST(0xf6bc3ba3, 0x636451c4, 0x3e46357d, 0x2c21d619, 0x0988e234, 0x15985661, 0x6672982b, 0xa7549bfc),
         SECP256K1_FE_CONST(0xb024fdc7, 0x5547451e, 0x426c585f, 0xbd481425, 0x73df6b75, 0xeef6d9d0, 0x389d87d4, 0xfbb440ba)},
        /* Input known to need 566 divsteps starting with delta=1/2. */
        {SECP256K1_FE_CONST(0xb595d81b, 0x2e3c1e2f, 0x482dbc65, 0xe4865af7, 0x9a0a50aa, 0x29f9e618, 0x6f87d7a5, 0x8d1063ae),
         SECP256K1_FE_CONST(0xc983337c, 0x5d5c74e1, 0x49918330, 0x0b53afb5, 0xa0428a0b, 0xce6eef86, 0x059bd8ef, 0xe5b908de)},
        /* Set of 10 inputs accessing all 128 entries in the modinv32 divsteps_var table */
        {SECP256K1_FE_CONST(0x00000000, 0x00000000, 0xe0ff1f80, 0x1f000000, 0x00000000, 0x00000000, 0xfeff0100, 0x00000000),
         SECP256K1_FE_CONST(0x9faf9316, 0x77e5049d, 0x0b5e7a1b, 0xef70b893, 0x18c9e30c, 0x045e7fd7, 0x29eddf8c, 0xd62e9e3d)},
        {SECP256K1_FE_CONST(0x621a538d, 0x511b2780, 0x35688252, 0x53f889a4, 0x6317c3ac, 0x32ba0a46, 0x6277c0d1, 0xccd31192),
         SECP256K1_FE_CONST(0x38513b0c, 0x5eba856f, 0xe29e882e, 0x9b394d8c, 0x34bda011, 0xeaa66943, 0x6a841a4c, 0x6ae8bcff)},
        {SECP256K1_FE_CONST(0x00000200, 0xf0ffff1f, 0x00000000, 0x0000e0ff, 0xffffffff, 0xfffcffff, 0xffffffff, 0xffff0100),
         SECP256K1_FE_CONST(0x5da42a52, 0x3640de9e, 0x13e64343, 0x0c7591b7, 0x6c1e3519, 0xf048c5b6, 0x0484217c, 0xedbf8b2f)},
        {SECP256K1_FE_CONST(0xd1343ef9, 0x4b952621, 0x7c52a2ee, 0x4ea1281b, 0x4ab46410, 0x9f26998d, 0xa686a8ff, 0x9f2103e8),
         SECP256K1_FE_CONST(0x84044385, 0x9a4619bf, 0x74e35b6d, 0xa47e0c46, 0x6b7fb47d, 0x9ffab128, 0xb0775aa3, 0xcb318bd1)},
        {SECP256K1_FE_CONST(0xb27235d2, 0xc56a52be, 0x210db37a, 0xd50d23a4, 0xbe621bdd, 0x5df22c6a, 0xe926ba62, 0xd2e4e440),
         SECP256K1_FE_CONST(0x67a26e54, 0x483a9d3c, 0xa568469e, 0xd258ab3d, 0xb9ec9981, 0xdca9b1bd, 0x8d2775fe, 0x53ae429b)},
        {SECP256K1_FE_CONST(0x00000000, 0x00000000, 0x00e0ffff, 0xffffff83, 0xffffffff, 0x3f00f00f, 0x000000e0, 0xffffffff),
         SECP256K1_FE_CONST(0x310e10f8, 0x23bbfab0, 0xac94907d, 0x076c9a45, 0x8d357d7f, 0xc763bcee, 0x00d0e615, 0x5a6acef6)},
        {SECP256K1_FE_CONST(0xfeff0300, 0x001c0000, 0xf80700c0, 0x0ff0ffff, 0xffffffff, 0x0fffffff, 0xffff0100, 0x7f0000fe),
         SECP256K1_FE_CONST(0x28e2fdb4, 0x0709168b, 0x86f598b0, 0x3453a370, 0x530cf21f, 0x32f978d5, 0x1d527a71, 0x59269b0c)},
        {SECP256K1_FE_CONST(0xc2591afa, 0x7bb98ef7, 0x090bb273, 0x85c14f87, 0xbb0b28e0, 0x54d3c453, 0x85c66753, 0xd5574d2f),
         SECP256K1_FE_CONST(0xfdca70a2, 0x70ce627c, 0x95e66fae, 0x848a6dbb, 0x07ffb15c, 0x5f63a058, 0xba4140ed, 0x6113b503)},
        {SECP256K1_FE_CONST(0xf5475db3, 0xedc7b5a3, 0x411c047e, 0xeaeb452f, 0xc625828e, 0x1cf5ad27, 0x8eec1060, 0xc7d3e690),
         SECP256K1_FE_CONST(0x5eb756c0, 0xf963f4b9, 0xdc6a215e, 0xec8cc2d8, 0x2e9dec01, 0xde5eb88d, 0x6aba7164, 0xaecb2c5a)},
        {SECP256K1_FE_CONST(0x00000000, 0x00f8ffff, 0xffffffff, 0x01000000, 0xe0ff1f00, 0x00000000, 0xffffff7f, 0x00000000),
         SECP256K1_FE_CONST(0xe0d2e3d8, 0x49b6157d, 0xe54e88c2, 0x1a7f02ca, 0x7dd28167, 0xf1125d81, 0x7bfa444e, 0xbe110037)},
        /* Selection of randomly generated inputs that reach high/low d/e values in various configurations. */
        {SECP256K1_FE_CONST(0x13cc08a4, 0xd8c41f0f, 0x179c3e67, 0x54c46c67, 0xc4109221, 0x09ab3b13, 0xe24d9be1, 0xffffe950),
         SECP256K1_FE_CONST(0xb80c8006, 0xd16abaa7, 0xcabd71e5, 0xcf6714f4, 0x966dd3d0, 0x64767a2d, 0xe92c4441, 0x51008cd1)},
        {SECP256K1_FE_CONST(0xaa6db990, 0x95efbca1, 0x3cc6ff71, 0x0602e24a, 0xf49ff938, 0x99fffc16, 0x46f40993, 0xc6e72057),
         SECP256K1_FE_CONST(0xd5d3dd69, 0xb0c195e5, 0x285f1d49, 0xe639e48c, 0x9223f8a9, 0xca1d731d, 0x9ca482f9, 0xa5b93e06)},
        {SECP256K1_FE_CONST(0x1c680eac, 0xaeabffd8, 0x9bdc4aee, 0x1781e3de, 0xa3b08108, 0x0015f2e0, 0x94449e1b, 0x2f67a058),
         SECP256K1_FE_CONST(0x7f083f8d, 0x31254f29, 0x6510f475, 0x245c373d, 0xc5622590, 0x4b323393, 0x32ed1719, 0xc127444b)},
        {SECP256K1_FE_CONST(0x147d44b3, 0x012d83f8, 0xc160d386, 0x1a44a870, 0x9ba6be96, 0x8b962707, 0x267cbc1a, 0xb65b2f0a),
         SECP256K1_FE_CONST(0x555554ff, 0x170aef1e, 0x50a43002, 0xe51fbd36, 0xafadb458, 0x7a8aded1, 0x0ca6cd33, 0x6ed9087c)},
        {SECP256K1_FE_CONST(0x12423796, 0x22f0fe61, 0xf9ca017c, 0x5384d107, 0xa1fbf3b2, 0x3b018013, 0x916a3c37, 0x4000b98c),
         SECP256K1_FE_CONST(0x20257700, 0x08668f94, 0x1177e306, 0x136c01f5, 0x8ed1fbd2, 0x95ec4589, 0xae38edb9, 0xfd19b6d7)},
        {SECP256K1_FE_CONST(0xdcf2d030, 0x9ab42cb4, 0x93ffa181, 0xdcd23619, 0x39699b52, 0x08909a20, 0xb5a17695, 0x3a9dcf21),
         SECP256K1_FE_CONST(0x1f701dea, 0xe211fb1f, 0x4f37180d, 0x63a0f51c, 0x29fe1e40, 0xa40b6142, 0x2e7b12eb, 0x982b06b6)},
        {SECP256K1_FE_CONST(0x79a851f6, 0xa6314ed3, 0xb35a55e6, 0xca1c7d7f, 0xe32369ea, 0xf902432e, 0x375308c5, 0xdfd5b600),
         SECP256K1_FE_CONST(0xcaae00c5, 0xe6b43851, 0x9dabb737, 0x38cba42c, 0xa02c8549, 0x7895dcbf, 0xbd183d71, 0xafe4476a)},
        {SECP256K1_FE_CONST(0xede78fdd, 0xcfc92bf1, 0x4fec6c6c, 0xdb8d37e2, 0xfb66bc7b, 0x28701870, 0x7fa27c9a, 0x307196ec),
         SECP256K1_FE_CONST(0x68193a6c, 0x9a8b87a7, 0x2a760c64, 0x13e473f6, 0x23ae7bed, 0x1de05422, 0x88865427, 0xa3418265)},
        {SECP256K1_FE_CONST(0xa40b2079, 0xb8f88e89, 0xa7617997, 0x89baf5ae, 0x174df343, 0x75138eae, 0x2711595d, 0x3fc3e66c),
         SECP256K1_FE_CONST(0x9f99c6a5, 0x6d685267, 0xd4b87c37, 0x9d9c4576, 0x358c692b, 0x6bbae0ed, 0x3389c93d, 0x7fdd2655)},
        {SECP256K1_FE_CONST(0x7c74c6b6, 0xe98d9151, 0x72645cf1, 0x7f06e321, 0xcefee074, 0x15b2113a, 0x10a9be07, 0x08a45696),
         SECP256K1_FE_CONST(0x8c919a88, 0x898bc1e0, 0x77f26f97, 0x12e655b7, 0x9ba0ac40, 0xe15bb19e, 0x8364cc3b, 0xe227a8ee)},
        {SECP256K1_FE_CONST(0x109ba1ce, 0xdafa6d4a, 0xa1cec2b2, 0xeb1069f4, 0xb7a79e5b, 0xec6eb99b, 0xaec5f643, 0xee0e723e),
         SECP256K1_FE_CONST(0x93d13eb8, 0x4bb0bcf9, 0xe64f5a71, 0xdbe9f359, 0x7191401c, 0x6f057a4a, 0xa407fe1b, 0x7ecb65cc)},
        {SECP256K1_FE_CONST(0x3db076cd, 0xec74a5c9, 0xf61dd138, 0x90e23e06, 0xeeedd2d0, 0x74cbc4e0, 0x3dbe1e91, 0xded36a78),
         SECP256K1_FE_CONST(0x3f07f966, 0x8e2a1e09, 0x706c71df, 0x02b5e9d5, 0xcb92ddbf, 0xcdd53010, 0x16545564, 0xe660b107)},
        {SECP256K1_FE_CONST(0xe31c73ed, 0xb4c4b82c, 0x02ae35f7, 0x4cdec153, 0x98b522fd, 0xf7d2460c, 0x6bf7c0f8, 0x4cf67b0d),
         SECP256K1_FE_CONST(0x4b8f1faf, 0x94e8b070, 0x19af0ff6, 0xa319cd31, 0xdf0a7ffb, 0xefaba629, 0x59c50666, 0x1fe5b843)},
        {SECP256K1_FE_CONST(0x4c8b0e6e, 0x83392ab6, 0xc0e3e9f1, 0xbbd85497, 0x16698897, 0xf552d50d, 0x79652ddb, 0x12f99870),
         SECP256K1_FE_CONST(0x56d5101f, 0xd23b7949, 0x17dc38d6, 0xf24022ef, 0xcf18e70a, 0x5cc34424, 0x438544c3, 0x62da4bca)},
        {SECP256K1_FE_CONST(0xb0e040e2, 0x40cc35da, 0x7dd5c611, 0x7fccb178, 0x28888137, 0xbc930358, 0xea2cbc90, 0x775417dc),
         SECP256K1_FE_CONST(0xca37f0d4, 0x016dd7c8, 0xab3ae576, 0x96e08d69, 0x68ed9155, 0xa9b44270, 0x900ae35d, 0x7c7800cd)},
        {SECP256K1_FE_CONST(0x8a32ea49, 0x7fbb0bae, 0x69724a9d, 0x8e2105b2, 0xbdf69178, 0x862577ef, 0x35055590, 0x667ddaef),
         SECP256K1_FE_CONST(0xd02d7ead, 0xc5e190f0, 0x559c9d72, 0xdaef1ffc, 0x64f9f425, 0xf43645ea, 0x7341e08d, 0x11768e96)},
        {SECP256K1_FE_CONST(0xa3592d98, 0x9abe289d, 0x579ebea6, 0xbb0857a8, 0xe242ab73, 0x85f9a2ce, 0xb6998f0f, 0xbfffbfc6),
         SECP256K1_FE_CONST(0x093c1533, 0x32032efa, 0x6aa46070, 0x0039599e, 0x589c35f4, 0xff525430, 0x7fe3777a, 0x44b43ddc)},
        {SECP256K1_FE_CONST(0x647178a3, 0x229e607b, 0xcc98521a, 0xcce3fdd9, 0x1e1bc9c9, 0x97fb7c6a, 0x61b961e0, 0x99b10709),
         SECP256K1_FE_CONST(0x98217c13, 0xd51ddf78, 0x96310e77, 0xdaebd908, 0x602ca683, 0xcb46d07a, 0xa1fcf17e, 0xc8e2feb3)},
        {SECP256K1_FE_CONST(0x7334627c, 0x73f98968, 0x99464b4b, 0xf5964958, 0x1b95870d, 0xc658227e, 0x5e3235d8, 0xdcab5787),
         SECP256K1_FE_CONST(0x000006fd, 0xc7e9dd94, 0x40ae367a, 0xe51d495c, 0x07603b9b, 0x2d088418, 0x6cc5c74c, 0x98514307)},
        {SECP256K1_FE_CONST(0x82e83876, 0x96c28938, 0xa50dd1c5, 0x605c3ad1, 0xc048637d, 0x7a50825f, 0x335ed01a, 0x00005760),
         SECP256K1_FE_CONST(0xb0393f9f, 0x9f2aa55e, 0xf5607e2e, 0x5287d961, 0x60b3e704, 0xf3e16e80, 0xb4f9a3ea, 0xfec7f02d)},
        {SECP256K1_FE_CONST(0xc97b6cec, 0x3ee6b8dc, 0x98d24b58, 0x3c1970a1, 0xfe06297a, 0xae813529, 0xe76bb6bd, 0x771ae51d),
         SECP256K1_FE_CONST(0x0507c702, 0xd407d097, 0x47ddeb06, 0xf6625419, 0x79f48f79, 0x7bf80d0b, 0xfc34b364, 0x253a5db1)},
        {SECP256K1_FE_CONST(0xd559af63, 0x77ea9bc4, 0x3cf1ad14, 0x5c7a4bbb, 0x10e7d18b, 0x7ce0dfac, 0x380bb19d, 0x0bb99bd3),
         SECP256K1_FE_CONST(0x00196119, 0xb9b00d92, 0x34edfdb5, 0xbbdc42fc, 0xd2daa33a, 0x163356ca, 0xaa8754c8, 0xb0ec8b0b)},
        {SECP256K1_FE_CONST(0x8ddfa3dc, 0x52918da0, 0x640519dc, 0x0af8512a, 0xca2d33b2, 0xbde52514, 0xda9c0afc, 0xcb29fce4),
         SECP256K1_FE_CONST(0xb3e4878d, 0x5cb69148, 0xcd54388b, 0xc23acce0, 0x62518ba8, 0xf09def92, 0x7b31e6aa, 0x6ba35b02)},
        {SECP256K1_FE_CONST(0xf8207492, 0xe3049f0a, 0x65285f2b, 0x0bfff996, 0x00ca112e, 0xc05da837, 0x546d41f9, 0x5194fb91),
         SECP256K1_FE_CONST(0x7b7ee50b, 0xa8ed4bbd, 0xf6469930, 0x81419a5c, 0x071441c7, 0x290d046e, 0x3b82ea41, 0x611c5f95)},
        {SECP256K1_FE_CONST(0x050f7c80, 0x5bcd3c6b, 0x823cb724, 0x5ce74db7, 0xa4e39f5c, 0xbd8828d7, 0xfd4d3e07, 0x3ec2926a),
         SECP256K1_FE_CONST(0x000d6730, 0xb0171314, 0x4764053d, 0xee157117, 0x48fd61da, 0xdea0b9db, 0x1d5e91c6, 0xbdc3f59e)},
        {SECP256K1_FE_CONST(0x3e3ea8eb, 0x05d760cf, 0x23009263, 0xb3cb3ac9, 0x088f6f0d, 0x3fc182a3, 0xbd57087c, 0xe67c62f9),
         SECP256K1_FE_CONST(0xbe988716, 0xa29c1bf6, 0x4456aed6, 0xab1e4720, 0x49929305, 0x51043bf4, 0xebd833dd, 0xdd511e8b)},
        {SECP256K1_FE_CONST(0x6964d2a9, 0xa7fa6501, 0xa5959249, 0x142f4029, 0xea0c1b5f, 0x2f487ef6, 0x301ac80a, 0x768be5cd),
         SECP256K1_FE_CONST(0x3918ffe4, 0x07492543, 0xed24d0b7, 0x3df95f8f, 0xaffd7cb4, 0x0de2191c, 0x9ec2f2ad, 0x2c0cb3c6)},
        {SECP256K1_FE_CONST(0x37c93520, 0xf6ddca57, 0x2b42fd5e, 0xb5c7e4de, 0x11b5b81c, 0xb95e91f3, 0x95c4d156, 0x39877ccb),
         SECP256K1_FE_CONST(0x9a94b9b5, 0x57eb71ee, 0x4c975b8b, 0xac5262a8, 0x077b0595, 0xe12a6b1f, 0xd728edef, 0x1a6bf956)}
    };
    /* Fixed test cases for scalar inverses: pairs of (x, 1/x) mod n. */
    static const secp256k1_scalar scalar_cases[][2] = {
        /* 0 */
        {SECP256K1_SCALAR_CONST(0, 0, 0, 0, 0, 0, 0, 0),
         SECP256K1_SCALAR_CONST(0, 0, 0, 0, 0, 0, 0, 0)},
        /* 1 */
        {SECP256K1_SCALAR_CONST(0, 0, 0, 0, 0, 0, 0, 1),
         SECP256K1_SCALAR_CONST(0, 0, 0, 0, 0, 0, 0, 1)},
        /* -1 */
        {SECP256K1_SCALAR_CONST(0xffffffff, 0xffffffff, 0xffffffff, 0xfffffffe, 0xbaaedce6, 0xaf48a03b, 0xbfd25e8c, 0xd0364140),
         SECP256K1_SCALAR_CONST(0xffffffff, 0xffffffff, 0xffffffff, 0xfffffffe, 0xbaaedce6, 0xaf48a03b, 0xbfd25e8c, 0xd0364140)},
        /* 2 */
        {SECP256K1_SCALAR_CONST(0, 0, 0, 0, 0, 0, 0, 2),
         SECP256K1_SCALAR_CONST(0x7fffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0x5d576e73, 0x57a4501d, 0xdfe92f46, 0x681b20a1)},
        /* 2**128 */
        {SECP256K1_SCALAR_CONST(0, 0, 0, 1, 0, 0, 0, 0),
         SECP256K1_SCALAR_CONST(0x50a51ac8, 0x34b9ec24, 0x4b0dff66, 0x5588b13e, 0x9984d5b3, 0xcf80ef0f, 0xd6a23766, 0xa3ee9f22)},
        /* Input known to need 635 divsteps */
        {SECP256K1_SCALAR_CONST(0xcb9f1d35, 0xdd4416c2, 0xcd71bf3f, 0x6365da66, 0x3c9b3376, 0x8feb7ae9, 0x32a5ef60, 0x19199ec3),
         SECP256K1_SCALAR_CONST(0x1d7c7bba, 0xf1893d53, 0xb834bd09, 0x36b411dc, 0x42c2e42f, 0xec72c428, 0x5e189791, 0x8e9bc708)},
        /* Input known to need 566 divsteps starting with delta=1/2. */
        {SECP256K1_SCALAR_CONST(0x7e3c993d, 0xa4272488, 0xbc015b49, 0x2db54174, 0xd382083a, 0xebe6db35, 0x80f82eff, 0xcd132c72),
         SECP256K1_SCALAR_CONST(0x086f34a0, 0x3e631f76, 0x77418f28, 0xcc84ac95, 0x6304439d, 0x365db268, 0x312c6ded, 0xd0b934f8)},
        /* Input known to need 565 divsteps starting with delta=1/2. */
        {SECP256K1_SCALAR_CONST(0xbad7e587, 0x3f307859, 0x60d93147, 0x8a18491e, 0xb38a9fd5, 0x254350d3, 0x4b1f0e4b, 0x7dd6edc4),
         SECP256K1_SCALAR_CONST(0x89f2df26, 0x39e2b041, 0xf19bd876, 0xd039c8ac, 0xc2223add, 0x29c4943e, 0x6632d908, 0x515f467b)},
        /* Selection of randomly generated inputs that reach low/high d/e values in various configurations. */
        {SECP256K1_SCALAR_CONST(0x1950d757, 0xb37a5809, 0x435059bb, 0x0bb8997e, 0x07e1e3c8, 0x5e5d7d2c, 0x6a0ed8e3, 0xdbde180e),
         SECP256K1_SCALAR_CONST(0xbf72af9b, 0x750309e2, 0x8dda230b, 0xfe432b93, 0x7e25e475, 0x4388251e, 0x633d894b, 0x3bcb6f8c)},
        {SECP256K1_SCALAR_CONST(0x9bccf4e7, 0xc5a515e3, 0x50637aa9, 0xbb65a13f, 0x391749a1, 0x62de7d4e, 0xf6d7eabb, 0x3cd10ce0),
         SECP256K1_SCALAR_CONST(0xaf2d5623, 0xb6385a33, 0xcd0365be, 0x5e92a70d, 0x7f09179c, 0x3baaf30f, 0x8f9cc83b, 0x20092f67)},
        {SECP256K1_SCALAR_CONST(0x73a57111, 0xb242952a, 0x5c5dee59, 0xf3be2ace, 0xa30a7659, 0xa46e5f47, 0xd21267b1, 0x39e642c9),
         SECP256K1_SCALAR_CONST(0xa711df07, 0xcbcf13ef, 0xd61cc6be, 0xbcd058ce, 0xb02cf157, 0x272d4a18, 0x86d0feb3, 0xcd5fa004)},
        {SECP256K1_SCALAR_CONST(0x04884963, 0xce0580b1, 0xba547030, 0x3c691db3, 0x9cd2c84f, 0x24c7cebd, 0x97ebfdba, 0x3e785ec2),
         SECP256K1_SCALAR_CONST(0xaaaaaf14, 0xd7c99ba7, 0x517ce2c1, 0x78a28b4c, 0x3769a851, 0xe5c5a03d, 0x4cc28f33, 0x0ec4dc5d)},
        {SECP256K1_SCALAR_CONST(0x1679ed49, 0x21f537b1, 0x815cb8ae, 0x9efc511c, 0x5b9fa037, 0x0b0f275e, 0x6c985281, 0x6c4a9905),
         SECP256K1_SCALAR_CONST(0xb14ac3d5, 0x62b52999, 0xef34ead1, 0xffca4998, 0x0294341a, 0x1f8172aa, 0xea1624f9, 0x302eea62)},
        {SECP256K1_SCALAR_CONST(0x626b37c0, 0xf0057c35, 0xee982f83, 0x452a1fd3, 0xea826506, 0x48b08a9d, 0x1d2c4799, 0x4ad5f6ec),
         SECP256K1_SCALAR_CONST(0xe38643b7, 0x567bfc2f, 0x5d2f1c15, 0xe327239c, 0x07112443, 0x69509283, 0xfd98e77a, 0xdb71c1e8)},
        {SECP256K1_SCALAR_CONST(0x1850a3a7, 0x759efc56, 0x54f287b2, 0x14d1234b, 0xe263bbc9, 0xcf4d8927, 0xd5f85f27, 0x965bd816),
         SECP256K1_SCALAR_CONST(0x3b071831, 0xcac9619a, 0xcceb0596, 0xf614d63b, 0x95d0db2f, 0xc6a00901, 0x8eaa2621, 0xabfa0009)},
        {SECP256K1_SCALAR_CONST(0x94ae5d06, 0xa27dc400, 0x487d72be, 0xaa51ebed, 0xe475b5c0, 0xea675ffc, 0xf4df627a, 0xdca4222f),
         SECP256K1_SCALAR_CONST(0x01b412ed, 0xd7830956, 0x1532537e, 0xe5e3dc99, 0x8fd3930a, 0x54f8d067, 0x32ef5760, 0x594438a5)},
        {SECP256K1_SCALAR_CONST(0x1f24278a, 0xb5bfe374, 0xa328dbbc, 0xebe35f48, 0x6620e009, 0xd58bb1b4, 0xb5a6bf84, 0x8815f63a),
         SECP256K1_SCALAR_CONST(0xfe928416, 0xca5ba2d3, 0xfde513da, 0x903a60c7, 0x9e58ad8a, 0x8783bee4, 0x083a3843, 0xa608c914)},
        {SECP256K1_SCALAR_CONST(0xdc107d58, 0x274f6330, 0x67dba8bc, 0x26093111, 0x5201dfb8, 0x968ce3f5, 0xf34d1bd4, 0xf2146504),
         SECP256K1_SCALAR_CONST(0x660cfa90, 0x13c3d93e, 0x7023b1e5, 0xedd09e71, 0x6d9c9d10, 0x7a3d2cdb, 0xdd08edc3, 0xaa78fcfb)},
        {SECP256K1_SCALAR_CONST(0x7cd1e905, 0xc6f02776, 0x2f551cc7, 0x5da61cff, 0x7da05389, 0x1119d5a4, 0x631c7442, 0x894fd4f7),
         SECP256K1_SCALAR_CONST(0xff20862a, 0x9d3b1a37, 0x1628803b, 0x3004ccae, 0xaa23282a, 0xa89a1109, 0xd94ece5e, 0x181bdc46)},
        {SECP256K1_SCALAR_CONST(0x5b9dade8, 0x23d26c58, 0xcd12d818, 0x25b8ae97, 0x3dea04af, 0xf482c96b, 0xa062f254, 0x9e453640),
         SECP256K1_SCALAR_CONST(0x50c38800, 0x15fa53f4, 0xbe1e5392, 0x5c9b120a, 0x262c22c7, 0x18fa0816, 0x5f2baab4, 0x8cb5db46)},
        {SECP256K1_SCALAR_CONST(0x11cdaeda, 0x969c464b, 0xef1f4ab0, 0x5b01d22e, 0x656fd098, 0x882bea84, 0x65cdbe7a, 0x0c19ff03),
         SECP256K1_SCALAR_CONST(0x1968d0fa, 0xac46f103, 0xb55f1f72, 0xb3820bed, 0xec6b359a, 0x4b1ae0ad, 0x7e38e1fb, 0x295ccdfb)},
        {SECP256K1_SCALAR_CONST(0x2c351aa1, 0x26e91589, 0x194f8a1e, 0x06561f66, 0x0cb97b7f, 0x10914454, 0x134d1c03, 0x157266b4),
         SECP256K1_SCALAR_CONST(0xbe49ada6, 0x92bd8711, 0x41b176c4, 0xa478ba95, 0x14883434, 0x9d1cd6f3, 0xcc4b847d, 0x22af80f5)},
        {SECP256K1_SCALAR_CONST(0x6ba07c6e, 0x13a60edb, 0x6247f5c3, 0x84b5fa56, 0x76fe3ec5, 0x80426395, 0xf65ec2ae, 0x623ba730),
         SECP256K1_SCALAR_CONST(0x25ac23f7, 0x418cd747, 0x98376f9d, 0x4a11c7bf, 0x24c8ebfe, 0x4c8a8655, 0x345f4f52, 0x1c515595)},
        {SECP256K1_SCALAR_CONST(0x9397a712, 0x8abb6951, 0x2d4a3d54, 0x703b1c2a, 0x0661dca8, 0xd75c9b31, 0xaed4d24b, 0xd2ab2948),
         SECP256K1_SCALAR_CONST(0xc52e8bef, 0xd55ce3eb, 0x1c897739, 0xeb9fb606, 0x36b9cd57, 0x18c51cc2, 0x6a87489e, 0xffd0dcf3)},
        {SECP256K1_SCALAR_CONST(0xe6a808cc, 0xeb437888, 0xe97798df, 0x4e224e44, 0x7e3b380a, 0x207c1653, 0x889f3212, 0xc6738b6f),
         SECP256K1_SCALAR_CONST(0x31f9ae13, 0xd1e08b20, 0x757a2e5e, 0x5243a0eb, 0x8ae35f73, 0x19bb6122, 0xb910f26b, 0xda70aa55)},
        {SECP256K1_SCALAR_CONST(0xd0320548, 0xab0effe7, 0xa70779e0, 0x61a347a6, 0xb8c1e010, 0x9d5281f8, 0x2ee588a6, 0x80000000),
         SECP256K1_SCALAR_CONST(0x1541897e, 0x78195c90, 0x7583dd9e, 0x728b6100, 0xbce8bc6d, 0x7a53b471, 0x5dcd9e45, 0x4425fcaf)},
        {SECP256K1_SCALAR_CONST(0x93d623f1, 0xd45b50b0, 0x796e9186, 0x9eac9407, 0xd30edc20, 0xef6304cf, 0x250494e7, 0xba503de9),
         SECP256K1_SCALAR_CONST(0x7026d638, 0x1178b548, 0x92043952, 0x3c7fb47c, 0xcd3ea236, 0x31d82b01, 0x612fc387, 0x80b9b957)},
        {SECP256K1_SCALAR_CONST(0xf860ab39, 0x55f5d412, 0xa4d73bcc, 0x3b48bd90, 0xc248ffd3, 0x13ca10be, 0x8fba84cc, 0xdd28d6a3),
         SECP256K1_SCALAR_CONST(0x5c32fc70, 0xe0b15d67, 0x76694700, 0xfe62be4d, 0xeacdb229, 0x7a4433d9, 0x52155cd0, 0x7649ab59)},
        {SECP256K1_SCALAR_CONST(0x4e41311c, 0x0800af58, 0x7a690a8e, 0xe175c9ba, 0x6981ab73, 0xac532ea8, 0x5c1f5e63, 0x6ac1f189),
         SECP256K1_SCALAR_CONST(0xfffffff9, 0xd075982c, 0x7fbd3825, 0xc05038a2, 0x4533b91f, 0x94ec5f45, 0xb280b28f, 0x842324dc)},
        {SECP256K1_SCALAR_CONST(0x48e473bf, 0x3555eade, 0xad5d7089, 0x2424c4e4, 0x0a99397c, 0x2dc796d8, 0xb7a43a69, 0xd0364141),
         SECP256K1_SCALAR_CONST(0x634976b2, 0xa0e47895, 0x1ec38593, 0x266d6fd0, 0x6f602644, 0x9bb762f1, 0x7180c704, 0xe23a4daa)},
        {SECP256K1_SCALAR_CONST(0xbe83878d, 0x3292fc54, 0x26e71c62, 0x556ccedc, 0x7cbb8810, 0x4032a720, 0x34ead589, 0xe4d6bd13),
         SECP256K1_SCALAR_CONST(0x6cd150ad, 0x25e59d0f, 0x74cbae3d, 0x6377534a, 0x1e6562e8, 0xb71b9d18, 0xe1e5d712, 0x8480abb3)},
        {SECP256K1_SCALAR_CONST(0xcdddf2e5, 0xefc15f88, 0xc9ee06de, 0x8a846ca9, 0x28561581, 0x68daa5fb, 0xd1cf3451, 0xeb1782d0),
         SECP256K1_SCALAR_CONST(0xffffffd9, 0xed8d2af4, 0x993c865a, 0x23e9681a, 0x3ca3a3dc, 0xe6d5a46e, 0xbd86bd87, 0x61b55c70)},
        {SECP256K1_SCALAR_CONST(0xb6a18f1f, 0x04872df9, 0x08165ec4, 0x319ca19c, 0x6c0359ab, 0x1f7118fb, 0xc2ef8082, 0xca8b7785),
         SECP256K1_SCALAR_CONST(0xff55b19b, 0x0f1ac78c, 0x0f0c88c2, 0x2358d5ad, 0x5f455e4e, 0x3330b72f, 0x274dc153, 0xffbf272b)},
        {SECP256K1_SCALAR_CONST(0xea4898e5, 0x30eba3e8, 0xcf0e5c3d, 0x06ec6844, 0x01e26fb6, 0x75636225, 0xc5d08f4c, 0x1decafa0),
         SECP256K1_SCALAR_CONST(0xe5a014a8, 0xe3c4ec1e, 0xea4f9b32, 0xcfc7b386, 0x00630806, 0x12c08d02, 0x6407ccc2, 0xb067d90e)},
        {SECP256K1_SCALAR_CONST(0x70e9aea9, 0x7e933af0, 0x8a23bfab, 0x23e4b772, 0xff951863, 0x5ffcf47d, 0x6bebc918, 0x2ca58265),
         SECP256K1_SCALAR_CONST(0xf4e00006, 0x81bc6441, 0x4eb6ec02, 0xc194a859, 0x80ad7c48, 0xba4e9afb, 0x8b6bdbe0, 0x989d8f77)},
        {SECP256K1_SCALAR_CONST(0x3c56c774, 0x46efe6f0, 0xe93618b8, 0xf9b5a846, 0xd247df61, 0x83b1e215, 0x06dc8bcc, 0xeefc1bf5),
         SECP256K1_SCALAR_CONST(0xfff8937a, 0x2cd9586b, 0x43c25e57, 0xd1cefa7a, 0x9fb91ed3, 0x95b6533d, 0x8ad0de5b, 0xafb93f00)},
        {SECP256K1_SCALAR_CONST(0xfb5c2772, 0x5cb30e83, 0xe38264df, 0xe4e3ebf3, 0x392aa92e, 0xa68756a1, 0x51279ac5, 0xb50711a8),
         SECP256K1_SCALAR_CONST(0x000013af, 0x1105bfe7, 0xa6bbd7fb, 0x3d638f99, 0x3b266b02, 0x072fb8bc, 0x39251130, 0x2e0fd0ea)}
    };
    int i, var, testrand;
    unsigned char b32[32];
    secp256k1_fe x_fe;
    secp256k1_scalar x_scalar;
    memset(b32, 0, sizeof(b32));
    /* Test fixed test cases through test_inverse_{scalar,field}, both ways. */
    for (i = 0; (size_t)i < sizeof(fe_cases)/sizeof(fe_cases[0]); ++i) {
        for (var = 0; var <= 1; ++var) {
            test_inverse_field(&x_fe, &fe_cases[i][0], var);
            check_fe_equal(&x_fe, &fe_cases[i][1]);
            test_inverse_field(&x_fe, &fe_cases[i][1], var);
            check_fe_equal(&x_fe, &fe_cases[i][0]);
        }
    }
    for (i = 0; (size_t)i < sizeof(scalar_cases)/sizeof(scalar_cases[0]); ++i) {
        for (var = 0; var <= 1; ++var) {
            test_inverse_scalar(&x_scalar, &scalar_cases[i][0], var);
            CHECK(secp256k1_scalar_eq(&x_scalar, &scalar_cases[i][1]));
            test_inverse_scalar(&x_scalar, &scalar_cases[i][1], var);
            CHECK(secp256k1_scalar_eq(&x_scalar, &scalar_cases[i][0]));
        }
    }
    /* Test inputs 0..999 and their respective negations. */
    for (i = 0; i < 1000; ++i) {
        b32[31] = i & 0xff;
        b32[30] = (i >> 8) & 0xff;
        secp256k1_scalar_set_b32(&x_scalar, b32, NULL);
        secp256k1_fe_set_b32(&x_fe, b32);
        for (var = 0; var <= 1; ++var) {
            test_inverse_scalar(NULL, &x_scalar, var);
            test_inverse_field(NULL, &x_fe, var);
        }
        secp256k1_scalar_negate(&x_scalar, &x_scalar);
        secp256k1_fe_negate(&x_fe, &x_fe, 1);
        for (var = 0; var <= 1; ++var) {
            test_inverse_scalar(NULL, &x_scalar, var);
            test_inverse_field(NULL, &x_fe, var);
        }
    }
    /* test 128*count random inputs; half with testrand256_test, half with testrand256 */
    for (testrand = 0; testrand <= 1; ++testrand) {
        for (i = 0; i < 64 * count; ++i) {
            (testrand ? secp256k1_testrand256_test : secp256k1_testrand256)(b32);
            secp256k1_scalar_set_b32(&x_scalar, b32, NULL);
            secp256k1_fe_set_b32(&x_fe, b32);
            for (var = 0; var <= 1; ++var) {
                test_inverse_scalar(NULL, &x_scalar, var);
                test_inverse_field(NULL, &x_fe, var);
            }
        }
    }
}


int main(int argc, char **argv) {
    /* Disable buffering for stdout to improve reliability of getting
     * diagnostic information. Happens right at the start of main because
     * setbuf must be used before any other operation on the stream. */
    setbuf(stdout, NULL);
    /* Also disable buffering for stderr because it's not guaranteed that it's
     * unbuffered on all systems. */
    setbuf(stderr, NULL);

    /* find iteration count */
    if (argc > 1) {
        count = strtol(argv[1], NULL, 0);
    } else {
        const char* env = getenv("SECP256K1_TEST_ITERS");
        if (env && strlen(env) > 0) {
            count = strtol(env, NULL, 0);
        }
    }
    if (count <= 0) {
        fputs("An iteration count of 0 or less is not allowed.\n", stderr);
        return EXIT_FAILURE;
    }
    printf("test count = %i\n", count);

    /* find random seed */
    secp256k1_testrand_init(argc > 2 ? argv[2] : NULL);

    /* initialize */
    ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    if (secp256k1_testrand_bits(1)) {
        unsigned char rand32[32];
        secp256k1_testrand256(rand32);
        CHECK(secp256k1_context_randomize(ctx, secp256k1_testrand_bits(1) ? rand32 : NULL));
    }

    /* field tests */
    run_field_misc();
    // run_field_convert();
    // run_fe_mul();
    // run_sqr();
    // run_sqrt();

    /* shutdown */
    secp256k1_context_destroy(ctx);

    printf("no problems found\n");
    return 0;
}
