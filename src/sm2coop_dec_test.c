/*************************************************************************
 * Written in 2020-2022 by Elichai Turkel                                *
 * To the extent possible under law, the author(s) have dedicated all    *
 * copyright and related and neighboring rights to the software in this  *
 * file to the public domain worldwide. This software is distributed     *
 * without any warranty. For the CC0 Public Domain Dedication, see       *
 * EXAMPLES_COPYING or https://creativecommons.org/publicdomain/zero/1.0 *
 *************************************************************************/

#include <stdio.h>
#include <assert.h>
#include <string.h>

#include <secp256k1.h>

#include <random.h>
#include <time.h>

#include <omp.h>

static void hex_dump(char prefix[], unsigned char bytes[], size_t bytes_len){
    // 输出阶的字节数组
    printf("%s: ", prefix);
    for (int i = 0; i < bytes_len; ++i) {
        printf("%02x", bytes[i]);
    }
    printf("\n");
}

int run(int thread_num) {
    unsigned char msg[32] = {
            0x31, 0x5F, 0x5B, 0xDB, 0x76, 0xD0, 0x78, 0xC4,
            0x3B, 0x8A, 0xC0, 0x06, 0x4E, 0x4A, 0x01, 0x64,
            0x61, 0x2B, 0x1F, 0xCE, 0x77, 0xC8, 0x69, 0x34,
            0x5B, 0xFC, 0x94, 0xC7, 0x58, 0x94, 0xED, 0xD3,
    };
    size_t klen = 32;
    size_t Clen = 64+klen+32;
    unsigned char C_b[Clen];
    unsigned char C2_bklen[klen];

    unsigned char C1_b64[64];
    unsigned char CS1_b64[64];
    unsigned char msg_out[klen];

    unsigned char kA_b32[32];
    unsigned char WA_b64[64];
    unsigned char eA_b32[32];
    unsigned char eS_b32[32];
    unsigned char c_b32[32];
    unsigned char WS_b64[64];
    unsigned char pubkey_b64[64];


    unsigned char randomize[32];
    int return_val;

    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    if (!fill_random(randomize, sizeof(randomize))) {
        printf("Failed to generate randomness\n");
        return 1;
    }
    return_val = secp256k1_context_randomize(ctx, randomize);
    assert(return_val);

    // 生成公钥
    secp256k1_sm2coop_enc_pubkey_create_stepA(ctx, kA_b32, WA_b64);
//    hex_dump("kA_b32", kA_b32, 32);
//    hex_dump("WA_b64", WA_b64, 64);
    secp256k1_sm2coop_enc_pubkey_create_stepB(ctx, eS_b32, c_b32, WS_b64, pubkey_b64, WA_b64);
//    hex_dump("eS_b32", eS_b32, 32);
//    hex_dump("c_b32", c_b32, 32);
//    hex_dump("WS_b64", WS_b64, 64);
//    hex_dump("pubkey_b64", pubkey_b64, 64);
    secp256k1_sm2coop_enc_pubkey_create_stepC(ctx, eA_b32, kA_b32, c_b32, WS_b64);
//    hex_dump("eA_b32", eA_b32, 32);

    // 生成随机密文
    if (!fill_random(C_b, Clen)) {
        printf("Failed to generate randomness\n");
        return 1;
    }
#if 0
    // 正确性验证
    hex_dump("C", C_b, Clen);
    secp256k1_sm2coop_dec_stepA(ctx, C1_b64, C_b);
    hex_dump("C1_b64", C1_b64, 64);
    secp256k1_sm2coop_dec_stepB(ctx, CS1_b64, eS_b32, C1_b64);
    hex_dump("CS1_b64", CS1_b64, 64);
    secp256k1_sm2coop_dec_stepC(ctx, msg_out, klen, C1_b64, C2_bklen, CS1_b64, eA_b32);
    hex_dump("msg_out", msg_out, klen);

#endif
#if 1
    // 多线程测试
    double begin,end;
    size_t count = 1000000;

    // 协同解密性能测试
    begin = omp_get_wtime();
    #pragma omp parallel for num_threads(thread_num)
    for(int i = 0; i < count;i++){
        secp256k1_sm2coop_dec_stepA(ctx, C1_b64, C_b);
        secp256k1_sm2coop_dec_stepB(ctx, CS1_b64, eS_b32, C1_b64);
        secp256k1_sm2coop_dec_stepC(ctx, msg_out, klen, C1_b64, C2_bklen, CS1_b64, eA_b32);
    }
    end = omp_get_wtime();
    printf("sm2coop_dec - %d threads: run %d times, total time: %f s, per second run %f tims\n", \
			thread_num, count, (end-begin), count/(end-begin));
    assert(return_val);
#endif
    /* This will clear everything from the context and free the memory */
    secp256k1_context_destroy(ctx);
    return 0;
}

int main(){
    run(1);
    run(2);
    run(4);
    run(8);
    run(12);
    run(32);
    return 0;

}