#ifndef SECP256K1_SM2_IMPL_H
#define SECP256K1_SM2_IMPL_H

#include "eckey.h"

#include "scalar.h"
#include "field.h"
#include "group.h"
#include "ecmult_gen.h"
#include "sm3.h"
#include "endian.h"
#include "sm2.h"
#if 0
#include <random.h>
#endif
int sm2_kdf(const uint8_t *in, size_t inlen, size_t outlen, uint8_t *out)
{
    SM3_CTX ctx;
    uint8_t counter_be[4];
    uint8_t dgst[SM3_DIGEST_SIZE];
    uint32_t counter = 1;
    size_t len;

    /*
    size_t i; fprintf(stderr, "kdf input : ");
    for (i = 0; i < inlen; i++) fprintf(stderr, "%02x", in[i]); fprintf(stderr, "\n");
    */

    while (outlen)
    {
        PUTU32(counter_be, counter);
        counter++;

        sm3_init(&ctx);
        sm3_update(&ctx, in, inlen);
        sm3_update(&ctx, counter_be, sizeof(counter_be));
        sm3_finish(&ctx, dgst);

        len = outlen < SM3_DIGEST_SIZE ? outlen : SM3_DIGEST_SIZE;
        memcpy(out, dgst, len);
        out += len;
        outlen -= len;
    }

    memset(&ctx, 0, sizeof(SM3_CTX));
    memset(dgst, 0, sizeof(dgst));
    return 1;
}

static int secp256k1_sm2_sig_sign(const secp256k1_ecmult_gen_context *ctx, secp256k1_scalar *sigr, secp256k1_scalar *sigs, const secp256k1_scalar *seckeyInv, const secp256k1_scalar *seckeyInvSeckey, const secp256k1_scalar *message, const secp256k1_scalar *nonce)
{
    unsigned char b[32];
    secp256k1_gej rp;
    secp256k1_ge r;
    secp256k1_scalar tmp;

    secp256k1_ecmult_gen(ctx, &rp, nonce);
    secp256k1_ge_set_gej(&r, &rp);
    secp256k1_fe_normalize(&r.x);
    secp256k1_fe_get_b32(b, &r.x);
    secp256k1_scalar_set_b32(sigr, b, NULL);

    secp256k1_scalar_add(sigr, sigr, message);
    secp256k1_scalar_add(&tmp, sigr, nonce);

    if (secp256k1_scalar_is_zero(&tmp) || secp256k1_scalar_is_zero(sigr))
        return 0;

    secp256k1_scalar_mul(&tmp, sigr, seckeyInvSeckey);
    secp256k1_scalar_negate(&tmp, &tmp);
    secp256k1_scalar_mul(sigs, nonce, seckeyInv);
    secp256k1_scalar_add(sigs, sigs, &tmp);

    secp256k1_scalar_clear(&tmp);
    secp256k1_ge_clear(&r);
    secp256k1_gej_clear(&rp);

    return (int)(!secp256k1_scalar_is_zero(sigs));
}

static int secp256k1_sm2_sig_verify(const secp256k1_scalar *sigr, const secp256k1_scalar *sigs, const secp256k1_ge *pubkey, const secp256k1_scalar *message)
{
    unsigned char c[32];
    secp256k1_scalar t, computed_r;
    secp256k1_gej pubkeyj, pr;
    secp256k1_ge pr_ge;

    if (secp256k1_scalar_is_zero(sigr) || secp256k1_scalar_is_zero(sigs))
    {
        printf("sigr || sigs is zero!\n");
        return 0;
    }

    secp256k1_scalar_add(&t, sigr, sigs);
    secp256k1_gej_set_ge(&pubkeyj, pubkey);
    secp256k1_ecmult(&pr, &pubkeyj, &t, sigs);
    if (secp256k1_gej_is_infinity(&pr))
    {
        printf("pr is infinity!\n");
        return 0;
    }

    secp256k1_ge_set_gej(&pr_ge, &pr);
    secp256k1_fe_normalize(&pr_ge.x);
    secp256k1_fe_get_b32(c, &pr_ge.x);
    secp256k1_scalar_set_b32(&computed_r, c, NULL);
    secp256k1_scalar_add(&computed_r, &computed_r, message);
    return secp256k1_scalar_eq(sigr, &computed_r);
}

int secp256k1_sm2_do_encrypt(const secp256k1_ecmult_gen_context *ctx, const secp256k1_ge *pubkey, const unsigned char *message, const unsigned char kLen, const secp256k1_scalar *nonce, unsigned char *C)
{
    secp256k1_gej rp, pubkeyj;
    secp256k1_ge C1, xy;
    SM3_CTX sm3_ctx;
    int i;
    unsigned char b[64];
    unsigned char C3[32];
    unsigned char C2[kLen];
    /*
        compute rp = [k]G
    */
    secp256k1_ecmult_gen(ctx, &rp, nonce);
    secp256k1_ge_set_gej(&C1, &rp);
    secp256k1_fe_normalize(&C1.x);
    secp256k1_fe_normalize(&C1.y);
    /*
        compute rp = [k]P
    */
    secp256k1_gej_set_ge(&pubkeyj, pubkey);
    secp256k1_ecmult(&rp, &pubkeyj, nonce, NULL);
    secp256k1_ge_set_gej(&xy, &rp);
    secp256k1_fe_normalize(&xy.x);
    secp256k1_fe_normalize(&xy.y);

    /*
        set b = x_2 || y_2
    */
    secp256k1_fe_get_b32(b, &xy.x);
    secp256k1_fe_get_b32(b + 32, &xy.y);
    /*
    printf("In encryption, C1||C2 is :");
    print_hex(b,sizeof(b));
    */
    /*
        compute C2 = kdf(b, klen)
    */
    sm2_kdf(b, sizeof(b), kLen, C2);

    /*
        compute C2 = M xor t
    */
    for (i = 0; i < kLen; i++)
    {
        C2[i] ^= message[i];
    }
    /*
    printf("In encryption, C2 is :");
    print_hex(C2,sizeof(C2));
    */
    /*
        compute C3 = Hash(x_2 || M || y_2)
    */
    sm3_init(&sm3_ctx);
    sm3_update(&sm3_ctx, b, 32);
    sm3_update(&sm3_ctx, message, kLen);
    sm3_update(&sm3_ctx, b + 32, 32);
    sm3_finish(&sm3_ctx, C3);
    /*
    printf("In encryption, C3 is :");
    print_hex(C3,sizeof(C3));
    */
    /*
        compute C = C1 || C2 || C3
    */
    secp256k1_fe_get_b32(C, &xy.x);
    secp256k1_fe_get_b32(C + 32, &xy.y);

    memcpy(C + 64, C2, sizeof(C2));
    memcpy(C + 64 + kLen, C3, sizeof(C3));
    return 1;
}

int secp256k1_sm2_do_decrypt(const unsigned char *cip, const unsigned char kLen,unsigned char *messsage, const secp256k1_scalar sec)
{
    int i;
    int valid = -1;
    unsigned char C1[64];
    unsigned char C2[kLen];
    unsigned char C3[32];
    unsigned char b[32];
    unsigned char t[32];
    unsigned char M[32];
    unsigned char u[32];
    secp256k1_gej c1r, c1;
    secp256k1_ge point;
    secp256k1_fe x, y;
    SM3_CTX sm3_ctx;
    /*
        convert C1||C2||C3 to C1,C2,C3
    */
    for (i = 0; i < 64; i++)
    {
        C1[i] = cip[i];
    }
    memcpy(C1, cip, 64);
    memcpy(C2, cip + 64, kLen);
    memcpy(C3, cip + 64 + kLen, 32);
    /*
    printf("In decryption, C1 is :");
    print_hex(C1,sizeof(C1));
    printf("In decryption, C2 is :");
    print_hex(C2,sizeof(C2));
    printf("In decryption, C3 is :");
    print_hex(C3,sizeof(C3));
    */

    /*
        check C1 whether on Curve
    */
    secp256k1_fe_set_b32(&x, C1);
    secp256k1_fe_set_b32(&y, C1 + 32);
    secp256k1_ge_set_xy(&point, &x, &y);
    if (!secp256k1_ge_is_valid_var(&point))
    {
        printf("unvalid point on secp256k1_sm2_do_decrypt\n");
        return valid;
    }

    /*
        compute point = [d]C1
    */
    secp256k1_gej_set_ge(&c1r, &point);
    secp256k1_ecmult(&c1, &c1r, &sec, NULL);
    secp256k1_ge_set_gej(&point, &c1);
    secp256k1_fe_normalize(&point.x);
    secp256k1_fe_normalize(&point.y);

    /*
        set b = x_2 || y_2
    */
    secp256k1_fe_get_b32(b, &point.x);
    secp256k1_fe_get_b32(b + 32, &point.y);

    /*
        compute t = kdf(b, klen)
    */
    sm2_kdf(b, sizeof(b), kLen, t);

    /*
        compute M = C2 xor t
    */
    for (i = 0; i < kLen; i++)
    {
        M[i] = C2[i] ^ t[i];
    }

    /*
        compute u = Hash(x_2 || M || y_2)
    */
    sm3_init(&sm3_ctx);
    sm3_update(&sm3_ctx, b, 32);
    sm3_update(&sm3_ctx, M, kLen);
    sm3_update(&sm3_ctx, b + 32, 32);
    sm3_finish(&sm3_ctx, u);

    if (memcmp(C2,u,32) == 0){
        memcpy(messsage, M, sizeof(M));
        valid = 1;
    }
    return valid;
}

#endif /* SECP256K1_SM2_IMPL_H */
