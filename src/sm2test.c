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
    unsigned char seckey[32];
    unsigned char seckeyInv[32];
    unsigned char seckeyInvSeckey[32];
    unsigned char randomize[32];
    unsigned char compressed_pubkey[33];
    unsigned char serialized_signature[64];
    size_t len;
    int is_signature_valid;
    int return_val;
    secp256k1_pubkey pubkey;
    secp256k1_ecdsa_signature sig;

    // 空间分配
    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    if (!fill_random(randomize, sizeof(randomize))) {
        printf("Failed to generate randomness\n");
        return 1;
    }
    // 初始化系统参数
    return_val = secp256k1_context_randomize(ctx, randomize);
    assert(return_val);

    // 生成私钥
    while (1) {
        if (!fill_random(seckey, sizeof(seckey))) {
            printf("Failed to generate randomness\n");
            return 1;
        }
        if (secp256k1_ec_seckey_verify(ctx, seckey)) {
            break;
        }
    }

    // 生成公钥
    return_val = secp256k1_ec_pubkey_create(ctx, &pubkey, seckey);
    assert(return_val);

    // 预计算 (1+d)^-1、(1+d)^-1*d
    secp256k1_sm2_precomputed(ctx, seckey, seckeyInv, seckeyInvSeckey);
#if 1
    // 正确性验证
    return_val = secp256k1_sm2_sign(ctx, &sig, msg_hash, seckey, seckeyInv, seckeyInvSeckey, NULL, NULL);
    if(return_val){
        // sig -> serialized_signature
        return_val = secp256k1_ecdsa_signature_serialize_compact(ctx, serialized_signature, &sig);
        // 以十六进制的形式输出字节数组
        hex_dump("sign", serialized_signature, 64);
        is_signature_valid = secp256k1_sm2_verify(ctx, &sig, msg_hash, &pubkey);
        if(is_signature_valid){
            printf("通过!\n");
        }else{
            printf("验签失败!\n");
        }
    }else{
        printf("签名失败!\n");
    }
#endif
#if 1
    // 多线程测试
    double begin,end;
    size_t count = 100000;

    // 签名性能测试
    begin = omp_get_wtime();
    #pragma omp parallel for num_threads(thread_num)
    for(int i = 0; i < count;i++){
        return_val = secp256k1_sm2_sign(ctx, &sig, msg_hash, seckey, seckeyInv, seckeyInvSeckey, NULL, NULL);
    }
    end = omp_get_wtime();
    printf("sign - %d threads: run %d times, , total time: %f s, per second run %f tims\n", \
			thread_num, count, (end-begin), count/(end-begin));
    assert(return_val);
    // 验签性能测试
    begin = omp_get_wtime();
    #pragma omp parallel for num_threads(thread_num)
    for(int i = 0;i < count;i++){
        is_signature_valid = secp256k1_sm2_verify(ctx, &sig, msg_hash, &pubkey);
    }
    end = omp_get_wtime();
    printf("verify - %d threads: run %d times, , total time: %f s, per second run %f tims\n", \
			thread_num, count, (end-begin), count/(end-begin));
#endif
    /* This will clear everything from the context and free the memory */
    secp256k1_context_destroy(ctx);
    memset(seckey, 0, sizeof(seckey));
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