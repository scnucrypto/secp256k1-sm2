/***********************************************************************
 * Copyright (c) 2013-2015 Pieter Wuille                               *
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

#define SECP256K1_BUILD

#include "../include/secp256k1.h"
#include "../include/secp256k1_preallocated.h"
#include "../include/random.h"

#include "assumptions.h"
#include "util.h"
#include "field_impl.h"
#include "scalar_impl.h"
#include "group_impl.h"
#include "ecmult_impl.h"
#include "ecmult_const_impl.h"
#include "ecmult_gen_impl.h"
#include "ecdsa_impl.h"
#include "sm2_impl.h"
#include "sm3_impl.h"
#include "eckey_impl.h"
#include "hash_impl.h"
#include "scratch_impl.h"
#include "selftest.h"


#if defined(_WIN32)
#include <windows.h>
#include <ntstatus.h>
#include <bcrypt.h>
#elif defined(__linux__) || defined(__APPLE__) || defined(__FreeBSD__)
#include <sys/random.h>
#elif defined(__OpenBSD__)
#include <unistd.h>
#else
#error "Couldn't identify the OS"
#endif

#include <stddef.h>
#include <limits.h>
#include <stdio.h>

#ifdef SECP256K1_NO_BUILD
# error "secp256k1.h processed without SECP256K1_BUILD defined while building secp256k1.c"
#endif

#if defined(VALGRIND)
# include <valgrind/memcheck.h>
#endif

#define ARG_CHECK(cond) do { \
    if (EXPECT(!(cond), 0)) { \
        secp256k1_callback_call(&ctx->illegal_callback, #cond); \
        return 0; \
    } \
} while(0)

#define ARG_CHECK_NO_RETURN(cond) do { \
    if (EXPECT(!(cond), 0)) { \
        secp256k1_callback_call(&ctx->illegal_callback, #cond); \
    } \
} while(0)

struct secp256k1_context_struct {
    secp256k1_ecmult_gen_context ecmult_gen_ctx;
    secp256k1_callback illegal_callback;
    secp256k1_callback error_callback;
    int declassify;
};

static const secp256k1_context secp256k1_context_no_precomp_ = {
    { 0 },
    { secp256k1_default_illegal_callback_fn, 0 },
    { secp256k1_default_error_callback_fn, 0 },
    0
};
const secp256k1_context *secp256k1_context_no_precomp = &secp256k1_context_no_precomp_;

size_t secp256k1_context_preallocated_size(unsigned int flags) {
    size_t ret = sizeof(secp256k1_context);
    /* A return value of 0 is reserved as an indicator for errors when we call this function internally. */
    VERIFY_CHECK(ret != 0);

    if (EXPECT((flags & SECP256K1_FLAGS_TYPE_MASK) != SECP256K1_FLAGS_TYPE_CONTEXT, 0)) {
            secp256k1_callback_call(&default_illegal_callback,
                                    "Invalid flags");
            return 0;
    }

    return ret;
}

size_t secp256k1_context_preallocated_clone_size(const secp256k1_context* ctx) {
    size_t ret = sizeof(secp256k1_context);
    VERIFY_CHECK(ctx != NULL);
    return ret;
}

secp256k1_context* secp256k1_context_preallocated_create(void* prealloc, unsigned int flags) {
    size_t prealloc_size;
    secp256k1_context* ret;

    if (!secp256k1_selftest()) {
        secp256k1_callback_call(&default_error_callback, "self test failed");
    }

    prealloc_size = secp256k1_context_preallocated_size(flags);
    if (prealloc_size == 0) {
        return NULL;
    }
    VERIFY_CHECK(prealloc != NULL);
    ret = (secp256k1_context*)prealloc;
    ret->illegal_callback = default_illegal_callback;
    ret->error_callback = default_error_callback;

    /* Flags have been checked by secp256k1_context_preallocated_size. */
    VERIFY_CHECK((flags & SECP256K1_FLAGS_TYPE_MASK) == SECP256K1_FLAGS_TYPE_CONTEXT);
    secp256k1_ecmult_gen_context_build(&ret->ecmult_gen_ctx);
    ret->declassify = !!(flags & SECP256K1_FLAGS_BIT_CONTEXT_DECLASSIFY);

    return ret;
}

secp256k1_context* secp256k1_context_create(unsigned int flags) {
    size_t const prealloc_size = secp256k1_context_preallocated_size(flags);
    secp256k1_context* ctx = (secp256k1_context*)checked_malloc(&default_error_callback, prealloc_size);
    if (EXPECT(secp256k1_context_preallocated_create(ctx, flags) == NULL, 0)) {
        free(ctx);
        return NULL;
    }

    return ctx;
}

secp256k1_context* secp256k1_context_preallocated_clone(const secp256k1_context* ctx, void* prealloc) {
    secp256k1_context* ret;
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(prealloc != NULL);

    ret = (secp256k1_context*)prealloc;
    *ret = *ctx;
    return ret;
}

secp256k1_context* secp256k1_context_clone(const secp256k1_context* ctx) {
    secp256k1_context* ret;
    size_t prealloc_size;

    VERIFY_CHECK(ctx != NULL);
    prealloc_size = secp256k1_context_preallocated_clone_size(ctx);
    ret = (secp256k1_context*)checked_malloc(&ctx->error_callback, prealloc_size);
    ret = secp256k1_context_preallocated_clone(ctx, ret);
    return ret;
}

void secp256k1_context_preallocated_destroy(secp256k1_context* ctx) {
    ARG_CHECK_NO_RETURN(ctx != secp256k1_context_no_precomp);
    if (ctx != NULL) {
        secp256k1_ecmult_gen_context_clear(&ctx->ecmult_gen_ctx);
    }
}

void secp256k1_context_destroy(secp256k1_context* ctx) {
    if (ctx != NULL) {
        secp256k1_context_preallocated_destroy(ctx);
        free(ctx);
    }
}

void secp256k1_context_set_illegal_callback(secp256k1_context* ctx, void (*fun)(const char* message, void* data), const void* data) {
    ARG_CHECK_NO_RETURN(ctx != secp256k1_context_no_precomp);
    if (fun == NULL) {
        fun = secp256k1_default_illegal_callback_fn;
    }
    ctx->illegal_callback.fn = fun;
    ctx->illegal_callback.data = data;
}

void secp256k1_context_set_error_callback(secp256k1_context* ctx, void (*fun)(const char* message, void* data), const void* data) {
    ARG_CHECK_NO_RETURN(ctx != secp256k1_context_no_precomp);
    if (fun == NULL) {
        fun = secp256k1_default_error_callback_fn;
    }
    ctx->error_callback.fn = fun;
    ctx->error_callback.data = data;
}

secp256k1_scratch_space* secp256k1_scratch_space_create(const secp256k1_context* ctx, size_t max_size) {
    VERIFY_CHECK(ctx != NULL);
    return secp256k1_scratch_create(&ctx->error_callback, max_size);
}

void secp256k1_scratch_space_destroy(const secp256k1_context *ctx, secp256k1_scratch_space* scratch) {
    VERIFY_CHECK(ctx != NULL);
    secp256k1_scratch_destroy(&ctx->error_callback, scratch);
}

/* Mark memory as no-longer-secret for the purpose of analysing constant-time behaviour
 *  of the software. This is setup for use with valgrind but could be substituted with
 *  the appropriate instrumentation for other analysis tools.
 */
static SECP256K1_INLINE void secp256k1_declassify(const secp256k1_context* ctx, const void *p, size_t len) {
#if defined(VALGRIND)
    if (EXPECT(ctx->declassify,0)) VALGRIND_MAKE_MEM_DEFINED(p, len);
#else
    (void)ctx;
    (void)p;
    (void)len;
#endif
}

static int secp256k1_pubkey_load(const secp256k1_context* ctx, secp256k1_ge* ge, const secp256k1_pubkey* pubkey) {
    if (sizeof(secp256k1_ge_storage) == 64) {
        /* When the secp256k1_ge_storage type is exactly 64 byte, use its
         * representation inside secp256k1_pubkey, as conversion is very fast.
         * Note that secp256k1_pubkey_save must use the same representation. */
        secp256k1_ge_storage s;
        memcpy(&s, &pubkey->data[0], sizeof(s));
        secp256k1_ge_from_storage(ge, &s);
    } else {
        /* Otherwise, fall back to 32-byte big endian for X and Y. */
        secp256k1_fe x, y;
        secp256k1_fe_set_b32(&x, pubkey->data);
        secp256k1_fe_set_b32(&y, pubkey->data + 32);
        secp256k1_ge_set_xy(ge, &x, &y);
    }
    ARG_CHECK(!secp256k1_fe_is_zero(&ge->x));
    return 1;
}

static void secp256k1_pubkey_save(secp256k1_pubkey* pubkey, secp256k1_ge* ge) {
    if (sizeof(secp256k1_ge_storage) == 64) {
        secp256k1_ge_storage s;
        secp256k1_ge_to_storage(&s, ge);
        memcpy(&pubkey->data[0], &s, sizeof(s));
    } else {
        VERIFY_CHECK(!secp256k1_ge_is_infinity(ge));
        secp256k1_fe_normalize_var(&ge->x);
        secp256k1_fe_normalize_var(&ge->y);
        secp256k1_fe_get_b32(pubkey->data, &ge->x);
        secp256k1_fe_get_b32(pubkey->data + 32, &ge->y);
    }
}

int secp256k1_ec_pubkey_parse(const secp256k1_context* ctx, secp256k1_pubkey* pubkey, const unsigned char *input, size_t inputlen) {
    secp256k1_ge Q;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(pubkey != NULL);
    memset(pubkey, 0, sizeof(*pubkey));
    ARG_CHECK(input != NULL);
    if (!secp256k1_eckey_pubkey_parse(&Q, input, inputlen)) {
        return 0;
    }
    if (!secp256k1_ge_is_in_correct_subgroup(&Q)) {
        return 0;
    }
    secp256k1_pubkey_save(pubkey, &Q);
    secp256k1_ge_clear(&Q);
    return 1;
}

int secp256k1_ec_pubkey_serialize(const secp256k1_context* ctx, unsigned char *output, size_t *outputlen, const secp256k1_pubkey* pubkey, unsigned int flags) {
    secp256k1_ge Q;
    size_t len;
    int ret = 0;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(outputlen != NULL);
    ARG_CHECK(*outputlen >= ((flags & SECP256K1_FLAGS_BIT_COMPRESSION) ? 33u : 65u));
    len = *outputlen;
    *outputlen = 0;
    ARG_CHECK(output != NULL);
    memset(output, 0, len);
    ARG_CHECK(pubkey != NULL);
    ARG_CHECK((flags & SECP256K1_FLAGS_TYPE_MASK) == SECP256K1_FLAGS_TYPE_COMPRESSION);
    if (secp256k1_pubkey_load(ctx, &Q, pubkey)) {
        ret = secp256k1_eckey_pubkey_serialize(&Q, output, &len, flags & SECP256K1_FLAGS_BIT_COMPRESSION);
        if (ret) {
            *outputlen = len;
        }
    }
    return ret;
}

int secp256k1_ec_pubkey_cmp(const secp256k1_context* ctx, const secp256k1_pubkey* pubkey0, const secp256k1_pubkey* pubkey1) {
    unsigned char out[2][33];
    const secp256k1_pubkey* pk[2];
    int i;

    VERIFY_CHECK(ctx != NULL);
    pk[0] = pubkey0; pk[1] = pubkey1;
    for (i = 0; i < 2; i++) {
        size_t out_size = sizeof(out[i]);
        /* If the public key is NULL or invalid, ec_pubkey_serialize will call
         * the illegal_callback and return 0. In that case we will serialize the
         * key as all zeros which is less than any valid public key. This
         * results in consistent comparisons even if NULL or invalid pubkeys are
         * involved and prevents edge cases such as sorting algorithms that use
         * this function and do not terminate as a result. */
        if (!secp256k1_ec_pubkey_serialize(ctx, out[i], &out_size, pk[i], SECP256K1_EC_COMPRESSED)) {
            /* Note that ec_pubkey_serialize should already set the output to
             * zero in that case, but it's not guaranteed by the API, we can't
             * test it and writing a VERIFY_CHECK is more complex than
             * explicitly memsetting (again). */
            memset(out[i], 0, sizeof(out[i]));
        }
    }
    return secp256k1_memcmp_var(out[0], out[1], sizeof(out[0]));
}

static void secp256k1_ecdsa_signature_load(const secp256k1_context* ctx, secp256k1_scalar* r, secp256k1_scalar* s, const secp256k1_ecdsa_signature* sig) {
    (void)ctx;
    if (sizeof(secp256k1_scalar) == 32) {
        /* When the secp256k1_scalar type is exactly 32 byte, use its
         * representation inside secp256k1_ecdsa_signature, as conversion is very fast.
         * Note that secp256k1_ecdsa_signature_save must use the same representation. */
        memcpy(r, &sig->data[0], 32);
        memcpy(s, &sig->data[32], 32);
    } else {
        secp256k1_scalar_set_b32(r, &sig->data[0], NULL);
        secp256k1_scalar_set_b32(s, &sig->data[32], NULL);
    }
}

static void secp256k1_ecdsa_signature_save(secp256k1_ecdsa_signature* sig, const secp256k1_scalar* r, const secp256k1_scalar* s) {
    if (sizeof(secp256k1_scalar) == 32) {
        memcpy(&sig->data[0], r, 32);
        memcpy(&sig->data[32], s, 32);
    } else {
        secp256k1_scalar_get_b32(&sig->data[0], r);
        secp256k1_scalar_get_b32(&sig->data[32], s);
    }
}

int secp256k1_ecdsa_signature_parse_der(const secp256k1_context* ctx, secp256k1_ecdsa_signature* sig, const unsigned char *input, size_t inputlen) {
    secp256k1_scalar r, s;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(sig != NULL);
    ARG_CHECK(input != NULL);

    if (secp256k1_ecdsa_sig_parse(&r, &s, input, inputlen)) {
        secp256k1_ecdsa_signature_save(sig, &r, &s);
        return 1;
    } else {
        memset(sig, 0, sizeof(*sig));
        return 0;
    }
}

int secp256k1_ecdsa_signature_parse_compact(const secp256k1_context* ctx, secp256k1_ecdsa_signature* sig, const unsigned char *input64) {
    secp256k1_scalar r, s;
    int ret = 1;
    int overflow = 0;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(sig != NULL);
    ARG_CHECK(input64 != NULL);

    secp256k1_scalar_set_b32(&r, &input64[0], &overflow);
    ret &= !overflow;
    secp256k1_scalar_set_b32(&s, &input64[32], &overflow);
    ret &= !overflow;
    if (ret) {
        secp256k1_ecdsa_signature_save(sig, &r, &s);
    } else {
        memset(sig, 0, sizeof(*sig));
    }
    return ret;
}

int secp256k1_ecdsa_signature_serialize_der(const secp256k1_context* ctx, unsigned char *output, size_t *outputlen, const secp256k1_ecdsa_signature* sig) {
    secp256k1_scalar r, s;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(output != NULL);
    ARG_CHECK(outputlen != NULL);
    ARG_CHECK(sig != NULL);

    secp256k1_ecdsa_signature_load(ctx, &r, &s, sig);
    return secp256k1_ecdsa_sig_serialize(output, outputlen, &r, &s);
}

int secp256k1_ecdsa_signature_serialize_compact(const secp256k1_context* ctx, unsigned char *output64, const secp256k1_ecdsa_signature* sig) {
    secp256k1_scalar r, s;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(output64 != NULL);
    ARG_CHECK(sig != NULL);

    secp256k1_ecdsa_signature_load(ctx, &r, &s, sig);
    secp256k1_scalar_get_b32(&output64[0], &r);
    secp256k1_scalar_get_b32(&output64[32], &s);
    return 1;
}

int secp256k1_ecdsa_signature_normalize(const secp256k1_context* ctx, secp256k1_ecdsa_signature *sigout, const secp256k1_ecdsa_signature *sigin) {
    secp256k1_scalar r, s;
    int ret = 0;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(sigin != NULL);

    secp256k1_ecdsa_signature_load(ctx, &r, &s, sigin);
    ret = secp256k1_scalar_is_high(&s);
    if (sigout != NULL) {
        if (ret) {
            secp256k1_scalar_negate(&s, &s);
        }
        secp256k1_ecdsa_signature_save(sigout, &r, &s);
    }

    return ret;
}

int secp256k1_ecdsa_verify(const secp256k1_context* ctx, const secp256k1_ecdsa_signature *sig, const unsigned char *msghash32, const secp256k1_pubkey *pubkey) {
    secp256k1_ge q;
    secp256k1_scalar r, s;
    secp256k1_scalar m;
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(msghash32 != NULL);
    ARG_CHECK(sig != NULL);
    ARG_CHECK(pubkey != NULL);

    secp256k1_scalar_set_b32(&m, msghash32, NULL);
    secp256k1_ecdsa_signature_load(ctx, &r, &s, sig);
    return (!secp256k1_scalar_is_high(&s) &&
            secp256k1_pubkey_load(ctx, &q, pubkey) &&
            secp256k1_ecdsa_sig_verify(&r, &s, &q, &m));
}

int secp256k1_sm2_verify(const secp256k1_context* ctx, const secp256k1_ecdsa_signature *sig, const unsigned char *msghash32, const secp256k1_pubkey *pubkey) {
    secp256k1_ge q;
    secp256k1_scalar r, s;
    secp256k1_scalar m;
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(msghash32 != NULL);
    ARG_CHECK(sig != NULL);
    ARG_CHECK(pubkey != NULL);

    secp256k1_scalar_set_b32(&m, msghash32, NULL);
    secp256k1_ecdsa_signature_load(ctx, &r, &s, sig);
    return (secp256k1_pubkey_load(ctx, &q, pubkey) &&
            secp256k1_sm2_sig_verify(&r, &s, &q, &m));
}


static SECP256K1_INLINE void buffer_append(unsigned char *buf, unsigned int *offset, const void *data, unsigned int len) {
    memcpy(buf + *offset, data, len);
    *offset += len;
}

static int nonce_function_rfc6979(unsigned char *nonce32, const unsigned char *msg32, const unsigned char *key32, const unsigned char *algo16, void *data, unsigned int counter) {
   unsigned char keydata[112];
   unsigned int offset = 0;
   secp256k1_rfc6979_hmac_sha256 rng;
   unsigned int i;
   /* We feed a byte array to the PRNG as input, consisting of:
    * - the private key (32 bytes) and message (32 bytes), see RFC 6979 3.2d.
    * - optionally 32 extra bytes of data, see RFC 6979 3.6 Additional Data.
    * - optionally 16 extra bytes with the algorithm name.
    * Because the arguments have distinct fixed lengths it is not possible for
    *  different argument mixtures to emulate each other and result in the same
    *  nonces.
    */
   buffer_append(keydata, &offset, key32, 32);
   buffer_append(keydata, &offset, msg32, 32);
   if (data != NULL) {
       buffer_append(keydata, &offset, data, 32);
   }
   if (algo16 != NULL) {
       buffer_append(keydata, &offset, algo16, 16);
   }
   secp256k1_rfc6979_hmac_sha256_initialize(&rng, keydata, offset);
   memset(keydata, 0, sizeof(keydata));
   for (i = 0; i <= counter; i++) {
       secp256k1_rfc6979_hmac_sha256_generate(&rng, nonce32, 32);
   }
   secp256k1_rfc6979_hmac_sha256_finalize(&rng);
   return 1;
}

const secp256k1_nonce_function secp256k1_nonce_function_rfc6979 = nonce_function_rfc6979;
const secp256k1_nonce_function secp256k1_nonce_function_default = nonce_function_rfc6979;

static int secp256k1_ecdsa_sign_inner(const secp256k1_context* ctx, secp256k1_scalar* r, secp256k1_scalar* s, int* recid, const unsigned char *msg32, const unsigned char *seckey, secp256k1_nonce_function noncefp, const void* noncedata) {
    secp256k1_scalar sec, non, msg;
    int ret = 0;
    int is_sec_valid;
    unsigned char nonce32[32];
    unsigned int count = 0;
    /* Default initialization here is important so we won't pass uninit values to the cmov in the end */
    *r = secp256k1_scalar_zero;
    *s = secp256k1_scalar_zero;
    if (recid) {
        *recid = 0;
    }
    if (noncefp == NULL) {
        noncefp = secp256k1_nonce_function_default;
    }

    /* Fail if the secret key is invalid. */
    is_sec_valid = secp256k1_scalar_set_b32_seckey(&sec, seckey);
    secp256k1_scalar_cmov(&sec, &secp256k1_scalar_one, !is_sec_valid);
    secp256k1_scalar_set_b32(&msg, msg32, NULL);
    while (1) {
        int is_nonce_valid;
        ret = !!noncefp(nonce32, msg32, seckey, NULL, (void*)noncedata, count);
        if (!ret) {
            break;
        }
        is_nonce_valid = secp256k1_scalar_set_b32_seckey(&non, nonce32);
        /* The nonce is still secret here, but it being invalid is is less likely than 1:2^255. */
        secp256k1_declassify(ctx, &is_nonce_valid, sizeof(is_nonce_valid));
        if (is_nonce_valid) {
            ret = secp256k1_ecdsa_sig_sign(&ctx->ecmult_gen_ctx, r, s, &sec, &msg, &non, recid);
            /* The final signature is no longer a secret, nor is the fact that we were successful or not. */
            secp256k1_declassify(ctx, &ret, sizeof(ret));
            if (ret) {
                break;
            }
        }
        count++;
    }
    /* We don't want to declassify is_sec_valid and therefore the range of
     * seckey. As a result is_sec_valid is included in ret only after ret was
     * used as a branching variable. */
    ret &= is_sec_valid;
    memset(nonce32, 0, 32);
    secp256k1_scalar_clear(&msg);
    secp256k1_scalar_clear(&non);
    secp256k1_scalar_clear(&sec);
    secp256k1_scalar_cmov(r, &secp256k1_scalar_zero, !ret);
    secp256k1_scalar_cmov(s, &secp256k1_scalar_zero, !ret);
    if (recid) {
        const int zero = 0;
        secp256k1_int_cmov(recid, &zero, !ret);
    }
    return ret;
}


static int secp256k1_sm2_sign_inner(const secp256k1_context* ctx, secp256k1_scalar* r, secp256k1_scalar* s, int* recid, const unsigned char *msg32, const unsigned char *seckey, const unsigned char *seckeyInv,const unsigned char *seckeyInvSeckey,secp256k1_nonce_function noncefp, const void* noncedata) {
    secp256k1_scalar secInv, secInvSec, non, msg;
    int ret = 0;
    unsigned char nonce32[32];
    unsigned int count = 0;
    /* Default initialization here is important so we won't pass uninit values to the cmov in the end */
    *r = secp256k1_scalar_zero;
    *s = secp256k1_scalar_zero;
    if (recid) {
        *recid = 0;
    }
    if (noncefp == NULL) {
        noncefp = secp256k1_nonce_function_default;  // 生成随机数nonce
    }

    /* Fail if the secret key is invalid. */
    secp256k1_scalar_set_b32(&msg, msg32, NULL);
    secp256k1_scalar_set_b32(&secInv, seckeyInv, NULL);
    secp256k1_scalar_set_b32(&secInvSec, seckeyInvSeckey, NULL);

    while (1) {
        int is_nonce_valid;
        ret = !!noncefp(nonce32, msg32, seckey, NULL, (void*)noncedata, count);
        if (!ret) {
            break;
        }
        
        is_nonce_valid = secp256k1_scalar_set_b32_seckey(&non, nonce32);
        /* The nonce is still secret here, but it being invalid is is less likely than 1:2^255. */
        // 清理敏感数据
//        secp256k1_declassify(ctx, &is_nonce_valid, sizeof(is_nonce_valid));

        if (is_nonce_valid) {
            ret = secp256k1_sm2_sig_sign(&ctx->ecmult_gen_ctx, r, s, &secInv, &secInvSec,&msg, &non);
            /* The final signature is no longer a secret, nor is the fact that we were successful or not. */
//            secp256k1_declassify(ctx, &ret, sizeof(ret));
            if (ret) {
                break;
            }
        }
        count++;
    }
    /* We don't want to declassify is_sec_valid and therefore the range of
     * seckey. As a result is_sec_valid is included in ret only after ret was
     * used as a branching variable. */
    memset(nonce32, 0, 32);
    secp256k1_scalar_clear(&msg);
    secp256k1_scalar_clear(&non);
    secp256k1_scalar_clear(&secInv);
    secp256k1_scalar_clear(&secInvSec);
    secp256k1_scalar_cmov(r, &secp256k1_scalar_zero, !ret);
    secp256k1_scalar_cmov(s, &secp256k1_scalar_zero, !ret);
    if (recid) {
        const int zero = 0;
        secp256k1_int_cmov(recid, &zero, !ret);
    }
    return ret;
}

int secp256k1_sm2_precomputed(const secp256k1_context* ctx, const unsigned char *seckey, unsigned char *seckeyInv, unsigned char *seckeyInvSeckey){
    secp256k1_scalar sec, tmp;
    int is_sec_valid;
    unsigned char c[32];
    is_sec_valid = secp256k1_scalar_set_b32_seckey(&sec, seckey);
    secp256k1_scalar_get_b32(c, &sec);
    secp256k1_scalar_cmov(&sec, &secp256k1_scalar_one, !is_sec_valid);
    secp256k1_declassify(ctx, &is_sec_valid, sizeof(is_sec_valid));

    secp256k1_scalar_add(&tmp, &secp256k1_scalar_one, &sec);
    secp256k1_scalar_get_b32(c, &tmp);
    secp256k1_scalar_inverse(&tmp, &tmp);

    secp256k1_scalar_get_b32(seckeyInv, &tmp);
    
    secp256k1_scalar_mul(&tmp, &tmp, &sec);
    secp256k1_scalar_get_b32(seckeyInvSeckey, &tmp);
    return is_sec_valid;
}

int secp256k1_ecdsa_sign(const secp256k1_context* ctx, secp256k1_ecdsa_signature *signature, const unsigned char *msghash32, const unsigned char *seckey, secp256k1_nonce_function noncefp, const void* noncedata) {
    secp256k1_scalar r, s;
    int ret;
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(secp256k1_ecmult_gen_context_is_built(&ctx->ecmult_gen_ctx));
    ARG_CHECK(msghash32 != NULL);
    ARG_CHECK(signature != NULL);
    ARG_CHECK(seckey != NULL);

    ret = secp256k1_ecdsa_sign_inner(ctx, &r, &s, NULL, msghash32, seckey, noncefp, noncedata);
    secp256k1_ecdsa_signature_save(signature, &r, &s);
    return ret;
}

static int secp256k1_sm2_encrytion_inner(const secp256k1_context* ctx, const unsigned char *msg, const unsigned char kLen, const secp256k1_ge *pubkey, secp256k1_nonce_function noncefp, const void* noncedata, unsigned char *cip){
    secp256k1_scalar non;
    unsigned char nonce32[32];
    unsigned int count = 0;
    int ret = 0;
    
    if (noncefp == NULL) {
        noncefp = secp256k1_nonce_function_default;
    }

    while (1) {
        int is_nonce_valid;
        ret = !!noncefp(nonce32, msg, cip, NULL, (void*)noncedata, count);
        if (!ret) {
            break;
        }
        is_nonce_valid = secp256k1_scalar_set_b32_seckey(&non, nonce32);
        secp256k1_declassify(ctx, &is_nonce_valid, sizeof(is_nonce_valid));
        if (is_nonce_valid) {
            ret = secp256k1_sm2_do_encrypt(&ctx->ecmult_gen_ctx, pubkey, msg, kLen, &non, cip);
            secp256k1_declassify(ctx, &ret, sizeof(ret));
            if (ret) {
                break;
            }
        }
        count++;
    }
    memset(nonce32, 0, 32);
    secp256k1_scalar_clear(&non);
    return ret;
}

int secp256k1_sm2_encryption(const secp256k1_context* ctx, const unsigned char *msg, const unsigned char kLen, const secp256k1_pubkey *pubkey, secp256k1_nonce_function noncefp, const void* noncedata, unsigned char *cip){
    secp256k1_ge q;
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(msg != NULL);
    ARG_CHECK(pubkey != NULL);

    return secp256k1_pubkey_load(ctx, &q, pubkey) && secp256k1_sm2_encrytion_inner(ctx, msg, kLen, &q, noncefp, noncedata, cip);
}

int secp256k1_sm2_decryption(const unsigned char *cip, const unsigned char kLen, unsigned char *msg, const unsigned char *seckey){
    secp256k1_scalar sec;
    secp256k1_scalar_set_b32(&sec, seckey, NULL);
    return secp256k1_sm2_do_decrypt(cip, kLen, msg, &sec);
}
int secp256k1_sm2_sign(const secp256k1_context* ctx, secp256k1_ecdsa_signature *signature, const unsigned char *msghash32, const unsigned char *seckey, const unsigned char *seckeyInv, const unsigned char *seckeyInvSeckey, secp256k1_nonce_function noncefp, const void* noncedata) {
    secp256k1_scalar r, s;
    int ret;
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(secp256k1_ecmult_gen_context_is_built(&ctx->ecmult_gen_ctx));
    ARG_CHECK(msghash32 != NULL);
    ARG_CHECK(signature != NULL);
    ARG_CHECK(seckey != NULL);
    ARG_CHECK(seckeyInv != NULL);
    ARG_CHECK(seckeyInvSeckey != NULL);

    ret = secp256k1_sm2_sign_inner(ctx, &r, &s, NULL, msghash32, seckey, seckeyInv, seckeyInvSeckey,noncefp, noncedata);
    secp256k1_ecdsa_signature_save(signature, &r, &s);
    return ret;
}
static void ge_set_b64(secp256k1_ge *ge, const unsigned char *ge_b64){
    secp256k1_fe ge_x, ge_y;
    secp256k1_fe_set_b32(&ge_x, ge_b64);
    secp256k1_fe_set_b32(&ge_y, ge_b64 + 32);
    secp256k1_ge_set_xy(ge, &ge_x, &ge_y);
}

static void ge_get_b64(unsigned char *ge_b64, const secp256k1_ge *ge){
    secp256k1_fe_get_b32(ge_b64, &ge->x);
    secp256k1_fe_get_b32(ge_b64 + 32, &ge->y);
}

static void hex_dump(char prefix[], unsigned char bytes[], size_t bytes_len){
    // 输出阶的字节数组
    printf("%s: ", prefix);
    for (int i = 0; i < bytes_len; ++i) {
        printf("%02x", bytes[i]);
    }
    printf("\n");
}

// 输入输出均为ge
static void ecmult_t(secp256k1_ge *r, const secp256k1_ge *a, const secp256k1_scalar *na, const secp256k1_scalar *ng){
    secp256k1_gej aj, pubkeyj;

    secp256k1_gej_set_ge(&aj, a);
    secp256k1_ecmult(&pubkeyj, &aj, na, ng);
    secp256k1_ge_set_gej(r, &pubkeyj);
    secp256k1_fe_normalize(&r->x);
    secp256k1_fe_normalize(&r->y);
}

void rand_seckey(const secp256k1_context* ctx, secp256k1_scalar *seckey){
    unsigned char seckey_b32[32];
    // 随机生成seckey_b
    while (1) {
        if (!fill_random(seckey_b32, 32)) {
            printf("Failed to generate randomness\n");
            return 1;
        }
        if (secp256k1_ec_seckey_verify(ctx, seckey_b32)) {
            break;
        }
    }
//    hex_dump("seckey_b32", seckey_b32, 32);
    // 将kS_b32入kS中
    secp256k1_scalar_set_b32(seckey, seckey_b32, NULL);
}

int secp256k1_sm2coop_seckey_create(const secp256k1_context* ctx, unsigned char *hdA_b32, unsigned char *WA_b64){
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(secp256k1_ecmult_gen_context_is_built(&ctx->ecmult_gen_ctx));
    int ret;
    secp256k1_scalar hdA;
    secp256k1_ge WA;
    secp256k1_gej tmp;
    // 随机生成hdA_b32
    while (1) {
        if (!fill_random(hdA_b32, 32)) {
            printf("Failed to generate randomness\n");
            return 1;
        }
        if (secp256k1_ec_seckey_verify(ctx, hdA_b32)) {
            break;
        }
    }
    // 将hd_b32写入hdA中
    secp256k1_scalar_set_b32(&hdA, hdA_b32, NULL);

    // 计算WA = [hdA]G
    secp256k1_ecmult_gen(&ctx->ecmult_gen_ctx, &tmp, &hdA);
    secp256k1_ge_set_gej(&WA, &tmp);
    secp256k1_fe_normalize(&WA.x);
    secp256k1_fe_normalize(&WA.y);

    // 将WA保存在WA_b64
    secp256k1_fe_get_b32(WA_b64, &WA.x);
    secp256k1_fe_get_b32(WA_b64 + 32, &WA.y);
}
int secp256k1_sm2coop_pubkey_create(const secp256k1_context* ctx, unsigned char *pubkey_b64,const unsigned char *hdA_b32, const unsigned char *WS_b64){
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(secp256k1_ecmult_gen_context_is_built(&ctx->ecmult_gen_ctx));
    int ret;
    secp256k1_scalar hdA;
    secp256k1_scalar neg_one;
    secp256k1_ge WS;
    secp256k1_ge pubkey;
    secp256k1_gej pubkeyj;
    secp256k1_gej WSj;

    // neg_one表示-1
    secp256k1_scalar_set_int(&neg_one, 1);
    secp256k1_scalar_negate(&neg_one, &neg_one);

    // 将hdA_b32写入hdA中
    secp256k1_scalar_set_b32(&hdA, hdA_b32, NULL);

    // 将WS_b64写入WS中
    ge_set_b64(&WS, WS_b64);

    if (!secp256k1_ge_is_valid_var(&WS))
    {
        printf("unvalid WS point on secp256k1_sm2coop_pubkey_create\n");
        return 0;
    }

    // 计算Pubkey = [hdA]WS-G
    ecmult_t(&pubkey, &WS, &hdA, &neg_one);

    // 将WA保存在WA_b64
    ge_get_b64(pubkey_b64, &pubkey);
}
int secp256k1_sm2coop_sign_stepA(const secp256k1_context* ctx, unsigned char *kA_b32,unsigned char *QA_b64, const unsigned char *pubkey_b64) {
    secp256k1_ge pubkey;
    secp256k1_ge QA;

    secp256k1_scalar one;
    secp256k1_scalar kA;

    int ret = 1;
//    unsigned char kA_b32[32];

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(secp256k1_ecmult_gen_context_is_built(&ctx->ecmult_gen_ctx));
    ARG_CHECK(pubkey_b64 != NULL);

    // 生成kA
    while (1) {
        if (!fill_random(kA_b32, 32)) {
            printf("Failed to generate randomness\n");
            return 1;
        }
        if (secp256k1_ec_seckey_verify(ctx, kA_b32)) {
            break;
        }
    }

    secp256k1_scalar_set_int(&one, 1);
    ge_set_b64(&pubkey, pubkey_b64);
    secp256k1_scalar_set_b32(&kA, kA_b32, NULL);
    ecmult_t(&QA, &pubkey, &kA, &one);
    ge_get_b64(QA_b64, &QA);
    return ret;
}

int secp256k1_sm2coop_sign_stepB(const secp256k1_context* ctx, unsigned char *r_b32, unsigned char *s1_b32, const unsigned char *QA_b64, const unsigned char *WS_b64, const unsigned char *hdS_inv_b32, const unsigned char *hash_b32) {
    secp256k1_ge WS;
    secp256k1_gej WSj;
    secp256k1_ge QA;

    secp256k1_gej tmpj;
    secp256k1_gej tmpj2;
    secp256k1_ge tmp;

    secp256k1_scalar one;
    secp256k1_scalar kS;
    secp256k1_scalar x;
    secp256k1_scalar tmp_sca;

    secp256k1_scalar hash;
    secp256k1_scalar r;
    secp256k1_scalar s1;
    secp256k1_scalar hdS_inv;

    int ret = 1;
    unsigned char kS_b32[32];
    unsigned char tmp_b32[32];

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(secp256k1_ecmult_gen_context_is_built(&ctx->ecmult_gen_ctx));
    ARG_CHECK(QA_b64);
    ARG_CHECK(WS_b64);
    ARG_CHECK(hdS_inv_b32);
    ARG_CHECK(hash_b32);

    // 生成kS_b32
    while (1) {
        if (!fill_random(kS_b32, 32)) {
            printf("Failed to generate randomness\n");
            return 1;
        }
        if (secp256k1_ec_seckey_verify(ctx, kS_b32)) {
            break;
        }
    }

    // tmpj = [ks]WS
    secp256k1_scalar_set_b32(&kS, kS_b32, NULL);
    ge_set_b64(&WS, WS_b64);
    secp256k1_ecmult(&tmpj, &WSj, &kS, NULL);

    // tmpj2 = [ks]WS + QA
    secp256k1_gej_add_ge(&tmpj2, &tmpj, &QA);

    // r = e+x
    secp256k1_ge_set_gej(&tmp, &tmpj2);
    secp256k1_fe_normalize(&tmp.x);
    secp256k1_fe_get_b32(tmp_b32, &tmp.x);
    secp256k1_scalar_set_b32(&x, tmp_b32, NULL);
    secp256k1_scalar_set_b32(&hash, hash_b32, NULL);
    secp256k1_scalar_add(&r, &hash, &x);
    secp256k1_scalar_get_b32(r_b32, &r);

    // s1 = hdS_inv*r + kS
    secp256k1_scalar_set_b32(&hdS_inv, hdS_inv_b32, NULL);
    secp256k1_scalar_mul(&tmp_sca, &hdS_inv, &r);
    secp256k1_scalar_add(&s1, &tmp_sca, &kS);
    secp256k1_scalar_get_b32(s1_b32, &s1);

    return ret;
}
int secp256k1_sm2coop_sign_stepC(const secp256k1_context* ctx, unsigned char *s_b32, const unsigned char *s1_b32, const unsigned char *r_b32, const unsigned char *kA_b32, const unsigned char *hdA_inv_b32) {
    secp256k1_scalar hdA_inv;
    secp256k1_scalar s1;
    secp256k1_scalar kA;
    secp256k1_scalar r;
    secp256k1_scalar neg_r;
    secp256k1_scalar s;

    int ret = 1;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(secp256k1_ecmult_gen_context_is_built(&ctx->ecmult_gen_ctx));

    secp256k1_scalar_set_b32(&hdA_inv, hdA_inv_b32, NULL);
    secp256k1_scalar_set_b32(&s1, s1_b32, NULL);
    secp256k1_scalar_set_b32(&kA, kA_b32, NULL);
    secp256k1_scalar_set_b32(&r, r_b32, NULL);
    secp256k1_scalar_negate(&neg_r, &r);

    // s = hdA_inv*s1 + kA - r
    secp256k1_scalar_mul(&s, &hdA_inv, &s1);
    secp256k1_scalar_add(&s, &s, &kA);
    secp256k1_scalar_add(&s, &s, &neg_r);

    secp256k1_scalar_get_b32(s_b32, &s);
    return ret;
}
int secp256k1_sm2coop_enc_pubkey_create_stepA(const secp256k1_context* ctx, unsigned char *kA_b32, unsigned char *WA_b64){
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(secp256k1_ecmult_gen_context_is_built(&ctx->ecmult_gen_ctx));
    int ret;
    secp256k1_scalar kA;
    secp256k1_ge WA;
    secp256k1_gej tmp;
    // 随机生成hdA_b32
    while (1) {
        if (!fill_random(kA_b32, 32)) {
            printf("Failed to generate randomness\n");
            return 1;
        }
        if (secp256k1_ec_seckey_verify(ctx, kA_b32)) {
            break;
        }
    }
    // 将hd_b32写入hdA中
    secp256k1_scalar_set_b32(&kA, kA_b32, NULL);

    // 计算WA = [kA]G
    secp256k1_ecmult_gen(&ctx->ecmult_gen_ctx, &tmp, &kA);
    secp256k1_ge_set_gej(&WA, &tmp);
    secp256k1_fe_normalize(&WA.x);
    secp256k1_fe_normalize(&WA.y);

    // 将WA保存在WA_b64
    ge_get_b64(WA_b64, &WA);
}

int secp256k1_sm2coop_enc_pubkey_create_stepB(const secp256k1_context* ctx, unsigned char *eS_b32,unsigned char *c_b32, unsigned char *WS_b64, unsigned char *pubkey_b64, const unsigned char *WA_b64){
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(secp256k1_ecmult_gen_context_is_built(&ctx->ecmult_gen_ctx));
    int ret;

    unsigned char tmp_b64[64];
    unsigned char tmp_b32[32];
    unsigned char eA_b32[32];

    secp256k1_scalar kS;
    secp256k1_scalar dA;
    secp256k1_scalar eS;
    secp256k1_scalar neg_eS;

    secp256k1_scalar eA;

    secp256k1_ge WA;
    secp256k1_ge WS;
    secp256k1_ge tmp_ge;
    secp256k1_ge pubkey;

    secp256k1_gej tmp_gej;

    rand_seckey(ctx, &kS);
    rand_seckey(ctx, &dA);
    rand_seckey(ctx, &eS);

    // eA = dA - eS
    secp256k1_scalar_negate(&neg_eS, &eS);
    secp256k1_scalar_add(&eA, &dA, &neg_eS);

    // 计算WS = [kS]G
    secp256k1_ecmult_gen(&ctx->ecmult_gen_ctx, &tmp_gej, &kS);
    secp256k1_ge_set_gej(&WS, &tmp_gej);
    secp256k1_fe_normalize(&WS.x);
    secp256k1_fe_normalize(&WS.y);

    // 计算(x, y) = [kS]WA
    ge_set_b64(&WA, WA_b64);
    ecmult_t(&tmp_ge, &WA, &kS, NULL);
    // tmp_b64 = x||y
    ge_get_b64(tmp_b64, &tmp_ge);

    // tmp_32 = kdf(x||y, 32)
    sm2_kdf(tmp_b64, 64, 32, tmp_b32);
    secp256k1_scalar_get_b32(eA_b32, &eA);
    // c = eA^kdf(x||y, 32)
    for (int i = 0; i < 32; ++i){
        c_b32[i] = eA_b32[i]^tmp_b32[i];
    }

    // pubkey = [dA]G
    secp256k1_ecmult_gen(&ctx->ecmult_gen_ctx, &tmp_gej, &dA);
    secp256k1_ge_set_gej(&pubkey, &tmp_gej);
    secp256k1_fe_normalize(&pubkey.x);
    secp256k1_fe_normalize(&pubkey.y);

    secp256k1_scalar_get_b32(eS_b32, &eS);
    ge_get_b64(WS_b64, &WS);
    ge_get_b64(pubkey_b64, &pubkey);
}

int secp256k1_sm2coop_enc_pubkey_create_stepC(const secp256k1_context* ctx, unsigned char *eA_b32, const unsigned char *kA_b32, const unsigned char *c_b32, const unsigned char *WS_b64){
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(secp256k1_ecmult_gen_context_is_built(&ctx->ecmult_gen_ctx));
    int ret;

    unsigned char tmp_b64[64];
    unsigned char tmp_b32[32];
    secp256k1_scalar kA;
    secp256k1_ge WS;
    secp256k1_ge tmp_ge;

    // (x', y') = [kA]WS
    secp256k1_scalar_set_b32(&kA, kA_b32, NULL);
    ge_set_b64(&WS, WS_b64);
    ecmult_t(&tmp_ge, &WS, &kA, NULL);
    // tmp_b64 = x'||y'
    ge_get_b64(tmp_b64, &tmp_ge);

    // tmp_32 = kdf(x'||y', 32)
    sm2_kdf(tmp_b64, 64, 32, tmp_b32);
    // eA = c^kdf(x||y, 32)
    for (int i = 0; i < 32; ++i){
        eA_b32[i] = c_b32[i]^tmp_b32[i];
    }
}
int secp256k1_sm2coop_dec_stepA(const secp256k1_context* ctx, unsigned char *C1_b64, const unsigned char *C_b){
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(secp256k1_ecmult_gen_context_is_built(&ctx->ecmult_gen_ctx));
    int ret;
    memcpy(C1_b64, C_b, 64);
}
int secp256k1_sm2coop_dec_stepB(const secp256k1_context* ctx, unsigned char *CS1_b64, const unsigned char *eS_b32, const unsigned char *C1_b64){
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(secp256k1_ecmult_gen_context_is_built(&ctx->ecmult_gen_ctx));
    int ret;

    secp256k1_scalar eS;

    secp256k1_ge C1;
    secp256k1_ge CS1;

    secp256k1_scalar_set_b32(&eS, eS_b32, NULL);
    ge_set_b64(&C1, C1_b64);
    // CS1 = [eS]C1
    ecmult_t(&CS1, &C1, &eS, NULL);
    ge_get_b64(CS1_b64, &CS1);
}
int secp256k1_sm2coop_dec_stepC(const secp256k1_context* ctx, unsigned char *msg, const size_t klen, const unsigned char *C1_b64, const unsigned char *C2_bklen, const unsigned char *CS1_b64, const unsigned char *eA_b32){
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(secp256k1_ecmult_gen_context_is_built(&ctx->ecmult_gen_ctx));
    int ret;

    unsigned char tmp_b64[64];
    unsigned char tmp_bklen[klen];

    secp256k1_scalar eA;

    secp256k1_ge C1;
    secp256k1_ge CS1;
    secp256k1_ge tmp_ge;

    secp256k1_gej tmp_gej;

    secp256k1_scalar_set_b32(&eA, eA_b32, NULL);
    ge_set_b64(&C1, C1_b64);
    ge_set_b64(&CS1, CS1_b64);
    ge_get_b64(tmp_b64, &CS1);

    // tmp_ge = [eA]C1
    ecmult_t(&tmp_ge, &C1, &eA, NULL);
    // tmp_gej = CS1
    secp256k1_gej_set_ge(&tmp_gej, &CS1);
    // tmp_gej = [eA]C1 + CS1
    secp256k1_gej_add_ge(&tmp_gej, &tmp_gej, &tmp_ge);

    // tmp_b32 = kdf(x1||y1, klen)
    sm2_kdf(tmp_b64, 64, klen, tmp_bklen);
    for (int i = 0; i < klen; ++i) {
        msg[i] = C2_bklen[i] ^ tmp_bklen[i];
    }
}

int secp256k1_ec_seckey_verify(const secp256k1_context* ctx, const unsigned char *seckey) {
    secp256k1_scalar sec;
    int ret;
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(seckey != NULL);

    ret = secp256k1_scalar_set_b32_seckey(&sec, seckey);
    secp256k1_scalar_clear(&sec);
    return ret;
}

static int secp256k1_ec_pubkey_create_helper(const secp256k1_ecmult_gen_context *ecmult_gen_ctx, secp256k1_scalar *seckey_scalar, secp256k1_ge *p, const unsigned char *seckey) {
    secp256k1_gej pj;
    int ret;

    // 成功返回1，否则返回0
    ret = secp256k1_scalar_set_b32_seckey(seckey_scalar, seckey);
    // 如果!ret不为0，将seckey_scalar设置为secp256k1_scalar_one，否则seckey_scalar不变
    secp256k1_scalar_cmov(seckey_scalar, &secp256k1_scalar_one, !ret);
    // 
    secp256k1_ecmult_gen(ecmult_gen_ctx, &pj, seckey_scalar);
    secp256k1_ge_set_gej(p, &pj);
    return ret;
}

int secp256k1_ec_pubkey_create(const secp256k1_context* ctx, secp256k1_pubkey *pubkey, const unsigned char *seckey) {
    printf("[*] debug: start secp256k1_ec_pubkey_create...\n");
    secp256k1_ge p;
    secp256k1_scalar seckey_scalar;
    int ret = 0;
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(pubkey != NULL);
    memset(pubkey, 0, sizeof(*pubkey));
    ARG_CHECK(secp256k1_ecmult_gen_context_is_built(&ctx->ecmult_gen_ctx));
    ARG_CHECK(seckey != NULL);

    ret = secp256k1_ec_pubkey_create_helper(&ctx->ecmult_gen_ctx, &seckey_scalar, &p, seckey);
    secp256k1_pubkey_save(pubkey, &p);
    // 清空中间变量的值
    secp256k1_memczero(pubkey, sizeof(*pubkey), !ret);
    secp256k1_scalar_clear(&seckey_scalar);
    return ret;
}

int secp256k1_ec_seckey_negate(const secp256k1_context* ctx, unsigned char *seckey) {
    secp256k1_scalar sec;
    int ret = 0;
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(seckey != NULL);

    ret = secp256k1_scalar_set_b32_seckey(&sec, seckey);
    secp256k1_scalar_cmov(&sec, &secp256k1_scalar_zero, !ret);
    secp256k1_scalar_negate(&sec, &sec);
    secp256k1_scalar_get_b32(seckey, &sec);

    secp256k1_scalar_clear(&sec);
    return ret;
}

int secp256k1_ec_privkey_negate(const secp256k1_context* ctx, unsigned char *seckey) {
    return secp256k1_ec_seckey_negate(ctx, seckey);
}

int secp256k1_ec_pubkey_negate(const secp256k1_context* ctx, secp256k1_pubkey *pubkey) {
    int ret = 0;
    secp256k1_ge p;
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(pubkey != NULL);

    ret = secp256k1_pubkey_load(ctx, &p, pubkey);
    memset(pubkey, 0, sizeof(*pubkey));
    if (ret) {
        secp256k1_ge_neg(&p, &p);
        secp256k1_pubkey_save(pubkey, &p);
    }
    return ret;
}


static int secp256k1_ec_seckey_tweak_add_helper(secp256k1_scalar *sec, const unsigned char *tweak32) {
    secp256k1_scalar term;
    int overflow = 0;
    int ret = 0;

    secp256k1_scalar_set_b32(&term, tweak32, &overflow);
    ret = (!overflow) & secp256k1_eckey_privkey_tweak_add(sec, &term);
    secp256k1_scalar_clear(&term);
    return ret;
}

int secp256k1_ec_seckey_tweak_add(const secp256k1_context* ctx, unsigned char *seckey, const unsigned char *tweak32) {
    secp256k1_scalar sec;
    int ret = 0;
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(seckey != NULL);
    ARG_CHECK(tweak32 != NULL);

    ret = secp256k1_scalar_set_b32_seckey(&sec, seckey);
    ret &= secp256k1_ec_seckey_tweak_add_helper(&sec, tweak32);
    secp256k1_scalar_cmov(&sec, &secp256k1_scalar_zero, !ret);
    secp256k1_scalar_get_b32(seckey, &sec);

    secp256k1_scalar_clear(&sec);
    return ret;
}

int secp256k1_ec_privkey_tweak_add(const secp256k1_context* ctx, unsigned char *seckey, const unsigned char *tweak32) {
    return secp256k1_ec_seckey_tweak_add(ctx, seckey, tweak32);
}

static int secp256k1_ec_pubkey_tweak_add_helper(secp256k1_ge *p, const unsigned char *tweak32) {
    secp256k1_scalar term;
    int overflow = 0;
    secp256k1_scalar_set_b32(&term, tweak32, &overflow);
    return !overflow && secp256k1_eckey_pubkey_tweak_add(p, &term);
}

int secp256k1_ec_pubkey_tweak_add(const secp256k1_context* ctx, secp256k1_pubkey *pubkey, const unsigned char *tweak32) {
    secp256k1_ge p;
    int ret = 0;
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(pubkey != NULL);
    ARG_CHECK(tweak32 != NULL);

    ret = secp256k1_pubkey_load(ctx, &p, pubkey);
    memset(pubkey, 0, sizeof(*pubkey));
    ret = ret && secp256k1_ec_pubkey_tweak_add_helper(&p, tweak32);
    if (ret) {
        secp256k1_pubkey_save(pubkey, &p);
    }

    return ret;
}

int secp256k1_ec_seckey_tweak_mul(const secp256k1_context* ctx, unsigned char *seckey, const unsigned char *tweak32) {
    secp256k1_scalar factor;
    secp256k1_scalar sec;
    int ret = 0;
    int overflow = 0;
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(seckey != NULL);
    ARG_CHECK(tweak32 != NULL);

    secp256k1_scalar_set_b32(&factor, tweak32, &overflow);
    ret = secp256k1_scalar_set_b32_seckey(&sec, seckey);
    ret &= (!overflow) & secp256k1_eckey_privkey_tweak_mul(&sec, &factor);
    secp256k1_scalar_cmov(&sec, &secp256k1_scalar_zero, !ret);
    secp256k1_scalar_get_b32(seckey, &sec);

    secp256k1_scalar_clear(&sec);
    secp256k1_scalar_clear(&factor);
    return ret;
}

int secp256k1_ec_privkey_tweak_mul(const secp256k1_context* ctx, unsigned char *seckey, const unsigned char *tweak32) {
    return secp256k1_ec_seckey_tweak_mul(ctx, seckey, tweak32);
}

int secp256k1_ec_pubkey_tweak_mul(const secp256k1_context* ctx, secp256k1_pubkey *pubkey, const unsigned char *tweak32) {
    secp256k1_ge p;
    secp256k1_scalar factor;
    int ret = 0;
    int overflow = 0;
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(pubkey != NULL);
    ARG_CHECK(tweak32 != NULL);

    secp256k1_scalar_set_b32(&factor, tweak32, &overflow);
    ret = !overflow && secp256k1_pubkey_load(ctx, &p, pubkey);
    memset(pubkey, 0, sizeof(*pubkey));
    if (ret) {
        if (secp256k1_eckey_pubkey_tweak_mul(&p, &factor)) {
            secp256k1_pubkey_save(pubkey, &p);
        } else {
            ret = 0;
        }
    }

    return ret;
}

int secp256k1_context_randomize(secp256k1_context* ctx, const unsigned char *seed32) {
    VERIFY_CHECK(ctx != NULL);
    if (secp256k1_ecmult_gen_context_is_built(&ctx->ecmult_gen_ctx)) {
        secp256k1_ecmult_gen_blind(&ctx->ecmult_gen_ctx, seed32);
    }
    return 1;
}

int secp256k1_ec_pubkey_combine(const secp256k1_context* ctx, secp256k1_pubkey *pubnonce, const secp256k1_pubkey * const *pubnonces, size_t n) {
    size_t i;
    secp256k1_gej Qj;
    secp256k1_ge Q;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(pubnonce != NULL);
    memset(pubnonce, 0, sizeof(*pubnonce));
    ARG_CHECK(n >= 1);
    ARG_CHECK(pubnonces != NULL);

    secp256k1_gej_set_infinity(&Qj);

    for (i = 0; i < n; i++) {
        ARG_CHECK(pubnonces[i] != NULL);
        secp256k1_pubkey_load(ctx, &Q, pubnonces[i]);
        secp256k1_gej_add_ge(&Qj, &Qj, &Q);
    }
    if (secp256k1_gej_is_infinity(&Qj)) {
        return 0;
    }
    secp256k1_ge_set_gej(&Q, &Qj);
    secp256k1_pubkey_save(pubnonce, &Q);
    return 1;
}

int secp256k1_tagged_sha256(const secp256k1_context* ctx, unsigned char *hash32, const unsigned char *tag, size_t taglen, const unsigned char *msg, size_t msglen) {
    secp256k1_sha256 sha;
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(hash32 != NULL);
    ARG_CHECK(tag != NULL);
    ARG_CHECK(msg != NULL);

    secp256k1_sha256_initialize_tagged(&sha, tag, taglen);
    secp256k1_sha256_write(&sha, msg, msglen);
    secp256k1_sha256_finalize(&sha, hash32);
    return 1;
}

#ifdef ENABLE_MODULE_ECDH
# include "modules/ecdh/main_impl.h"
#endif

#ifdef ENABLE_MODULE_RECOVERY
# include "modules/recovery/main_impl.h"
#endif

#ifdef ENABLE_MODULE_EXTRAKEYS
# include "modules/extrakeys/main_impl.h"
#endif

#ifdef ENABLE_MODULE_SCHNORRSIG
# include "modules/schnorrsig/main_impl.h"
#endif
