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
    unsigned char msg_hash[32] = {
            0x31, 0x5F, 0x5B, 0xDB, 0x76, 0xD0, 0x78, 0xC4,
            0x3B, 0x8A, 0xC0, 0x06, 0x4E, 0x4A, 0x01, 0x64,
            0x61, 0x2B, 0x1F, 0xCE, 0x77, 0xC8, 0x69, 0x34,
            0x5B, 0xFC, 0x94, 0xC7, 0x58, 0x94, 0xED, 0xD3,
    };

    unsigned char hash_b32[32];
    unsigned char hdA_b32[32];
    unsigned char WA_b64[64];
    unsigned char hdS_b32[32];
    unsigned char WS_b64[64];
    unsigned char pubkey_b64[64];
    unsigned char QA_b64[64];
    unsigned char r_b32[32];
    unsigned char s1_b32[32];
    unsigned char kA_b32[32];
    unsigned char s_b32[32];

    unsigned char randomize[32];
    int return_val;

    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    if (!fill_random(randomize, sizeof(randomize))) {
        printf("Failed to generate randomness\n");
        return 1;
    }
    return_val = secp256k1_context_randomize(ctx, randomize);
    assert(return_val);

    // 生成私钥
    secp256k1_sm2coop_seckey_create(ctx, hdA_b32, WA_b64);
//    hex_dump("hdA_b32", hdA_b32, 32);
//    hex_dump("WA_b64", WA_b64, 64);
    secp256k1_sm2coop_seckey_create(ctx, hdS_b32, WS_b64);
//    hex_dump("hdS_b32", hdS_b32, 32);
//    hex_dump("WS_b64", WS_b64, 64);
    // 生成公钥
    secp256k1_sm2coop_pubkey_create(ctx, pubkey_b64, hdA_b32, WS_b64);
//    hex_dump("pubkey_b64", pubkey_b64, 64);
#if 0
    // 正确性验证
    // stepA
    secp256k1_sm2coop_sign_stepA(ctx, kA_b32, QA_b64, pubkey_b64);
    hex_dump("kA_b32", kA_b32, 64);
    hex_dump("QA_b64", QA_b64, 64);

    // stepB
    secp256k1_sm2coop_sign_stepB(ctx, r_b32, s1_b32, QA_b64, WS_b64, hdS_b32, hash_b32);  // hdS_inv_b32
    hex_dump("r_b32", r_b32, 32);
    hex_dump("s1_b32", s1_b32, 32);

    // stepC
    secp256k1_sm2coop_sign_stepC(ctx, s_b32, s1_b32, r_b32, kA_b32, hdA_b32);  // hdA_inv_b32
    hex_dump("s_b32", s_b32, 32);
#endif
#if 1
    // 多线程测试
    double begin,end;
    size_t count = 1000000;

    // 签名性能测试
    begin = omp_get_wtime();
#pragma omp parallel for num_threads(thread_num)
    for(int i = 0; i < count;i++){
        // stepA
        secp256k1_sm2coop_sign_stepA(ctx, kA_b32, QA_b64, pubkey_b64);
        // stepB
        secp256k1_sm2coop_sign_stepB(ctx, r_b32, s1_b32, QA_b64, WS_b64, hdS_b32, hash_b32);  // hdS_inv_b32
        // stepC
        secp256k1_sm2coop_sign_stepC(ctx, s_b32, s1_b32, r_b32, kA_b32, hdA_b32);  // hdA_inv_b32
    }
    end = omp_get_wtime();
    printf("sign - %d threads: run %d times, , total time: %f s, per second run %f tims\n", \
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