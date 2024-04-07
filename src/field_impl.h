/***********************************************************************
 * Copyright (c) 2013, 2014 Pieter Wuille                              *
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

#ifndef SECP256K1_FIELD_IMPL_H
#define SECP256K1_FIELD_IMPL_H

#if defined HAVE_CONFIG_H
#include "libsecp256k1-config.h"
#endif

#include "util.h"

#if defined(SECP256K1_WIDEMUL_INT128)
#include "field_5x52_impl.h"
#elif defined(SECP256K1_WIDEMUL_INT64)
#include "field_10x26_impl.h"
#else
#error "Please select wide multiplication implementation"
#endif

SECP256K1_INLINE static int secp256k1_fe_equal(const secp256k1_fe *a, const secp256k1_fe *b) {
    secp256k1_fe na;
    secp256k1_fe_negate(&na, a, 1);
    secp256k1_fe_add(&na, b);
    return secp256k1_fe_normalizes_to_zero(&na);
}

SECP256K1_INLINE static int secp256k1_fe_equal_var(const secp256k1_fe *a, const secp256k1_fe *b) {
    secp256k1_fe na;

#if 0
    secp256k1_fe a_t, b_t;
    a_t.n[4] = 0x642571a8b2dcULL;
    a_t.n[3] = 0x2900000001340ULL;
    a_t.n[2] = 0x3614d61875b90ULL;
    a_t.n[1] = 0x540ff8b541646ULL;
    a_t.n[0] = 0xc458af3a0b2fcULL;

    b_t.n[4] = 0x642571a8b2dcULL;
    b_t.n[3] = 0x2900000001340ULL;
    b_t.n[2] = 0x3614d61875b90ULL;
    b_t.n[1] = 0x540ff8b541646ULL;
    b_t.n[0] = 0xc458af3a0b2fcULL;

    secp256k1_fe_negate(&na, &a_t, 1);
    secp256k1_fe_print("a", &a_t);
    secp256k1_fe_print("b", &b_t);

    secp256k1_fe_print("na", &na);
    
    secp256k1_fe_add(&na, &b_t);
    
    secp256k1_fe_print("na+b", &na);

    return 0;
#endif

    // a: 
    // 4, 642571a8b2dc
    // 3, 2900000001340
    // 2, 3614d61875b90
    // 1, 540ff8b541646
    // 0, c458af3a0b2fc

    // b: 
    // 4, 642571a8b2dc
    // 3, 2900000001340
    // 2, 3614d61875b90
    // 1, 540ff8b541646
    // 0, c458af3a0b2fc


    secp256k1_fe_negate(&na, a, 1);
    // secp256k1_fe_print("a", a);
    // secp256k1_fe_print("b", b);

    // secp256k1_fe_print("na", &na);
    
    secp256k1_fe_add(&na, b);
    
    // secp256k1_fe_print("na+b", &na);

    int res = secp256k1_fe_normalizes_to_zero_var(&na);
    printf("res = %d\n", res);
    return res;
}

static int secp256k1_fe_sqrt(secp256k1_fe *r, const secp256k1_fe *a) {
    /** Given that p is congruent to 3 mod 4, we can compute the square root of
     *  a mod p as the (p+1)/4'th power of a.
     *
     *  As (p+1)/4 is an even number, it will have the same result for a and for
     *  (-a). Only one of these two numbers actually has a square root however,
     *  so we test at the end by squaring and comparing to the input.
     *  Also because (p+1)/4 is an even number, the computed square root is
     *  itself always a square (a ** ((p+1)/4) is the square of a ** ((p+1)/8)).
     */
    secp256k1_fe x2, x3, x6, x9, x11, x22, x44, x88, x176, x220, x223, t1;
    int j;

    VERIFY_CHECK(r != a);

    /** The binary representation of (p + 1)/4 has 3 blocks of 1s, with lengths in
     *  { 2, 22, 223 }. Use an addition chain to calculate 2^n - 1 for each block:
     *  1, [2], 3, 6, 9, 11, [22], 44, 88, 176, 220, [223]
     */

    secp256k1_fe_sqr(&x2, a);
    secp256k1_fe_mul(&x2, &x2, a);

    secp256k1_fe_sqr(&x3, &x2);
    secp256k1_fe_mul(&x3, &x3, a);

    x6 = x3;
    for (j=0; j<3; j++) {
        secp256k1_fe_sqr(&x6, &x6);
    }
    secp256k1_fe_mul(&x6, &x6, &x3);

    x9 = x6;
    for (j=0; j<3; j++) {
        secp256k1_fe_sqr(&x9, &x9);
    }
    secp256k1_fe_mul(&x9, &x9, &x3);

    x11 = x9;
    for (j=0; j<2; j++) {
        secp256k1_fe_sqr(&x11, &x11);
    }
    secp256k1_fe_mul(&x11, &x11, &x2);

    x22 = x11;
    for (j=0; j<11; j++) {
        secp256k1_fe_sqr(&x22, &x22);
    }
    secp256k1_fe_mul(&x22, &x22, &x11);

    x44 = x22;
    for (j=0; j<22; j++) {
        secp256k1_fe_sqr(&x44, &x44);
    }
    secp256k1_fe_mul(&x44, &x44, &x22);

    x88 = x44;
    for (j=0; j<44; j++) {
        secp256k1_fe_sqr(&x88, &x88);
    }
    secp256k1_fe_mul(&x88, &x88, &x44);

    x176 = x88;
    for (j=0; j<88; j++) {
        secp256k1_fe_sqr(&x176, &x176);
    }
    secp256k1_fe_mul(&x176, &x176, &x88);

    x220 = x176;
    for (j=0; j<44; j++) {
        secp256k1_fe_sqr(&x220, &x220);
    }
    secp256k1_fe_mul(&x220, &x220, &x44);

    x223 = x220;
    for (j=0; j<3; j++) {
        secp256k1_fe_sqr(&x223, &x223);
    }
    secp256k1_fe_mul(&x223, &x223, &x3);

    /* The final result is then assembled using a sliding window over the blocks. */

    t1 = x223;
    for (j=0; j<23; j++) {
        secp256k1_fe_sqr(&t1, &t1);
    }
    secp256k1_fe_mul(&t1, &t1, &x22);
    for (j=0; j<6; j++) {
        secp256k1_fe_sqr(&t1, &t1);
    }
    secp256k1_fe_mul(&t1, &t1, &x2);
    secp256k1_fe_sqr(&t1, &t1);
    secp256k1_fe_sqr(r, &t1);

    /* Check that a square root was actually calculated */

    secp256k1_fe_sqr(&t1, r);
    return secp256k1_fe_equal(&t1, a);
}

static const secp256k1_fe secp256k1_fe_one = SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 1);

#endif /* SECP256K1_FIELD_IMPL_H */
