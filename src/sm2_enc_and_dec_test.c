#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <secp256k1.h>
#include <random.h>
#include <time.h>
#include <omp.h>
#include "group.h"

static void hex_dump(char prefix[], unsigned char bytes[], size_t bytes_len){
    // 输出阶的字节数组
    printf("%s: ", prefix);
    for (int i = 0; i < bytes_len; ++i) {
        printf("%02x", bytes[i]);
    }
    printf("\n");
}
int run(int thread_num){
    unsigned char msg_hash[32] = {
        0x31, 0x5F, 0x5B, 0xDB, 0x76, 0xD0, 0x78, 0xC4,
        0x3B, 0x8A, 0xC0, 0x06, 0x4E, 0x4A, 0x01, 0x64,
        0x61, 0x2B, 0x1F, 0xCE, 0x77, 0xC8, 0x69, 0x34,
        0x5B, 0xFC, 0x94, 0xC7, 0x58, 0x94, 0xED, 0xD3,
    };
    unsigned char m[32];
    unsigned char cip[128];
    unsigned char seckey[32];
    unsigned char randomize[32];
    unsigned char compressed_pubkey[33];
    unsigned char serialized_signature[64];
    size_t len;
    int return_val;
    secp256k1_pubkey pubkey;
    secp256k1_ecdsa_signature sig;

    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

    if (!fill_random(randomize, sizeof(randomize))) {
        printf("Failed to generate randomness\n");
        return 1;
    }
    return_val = secp256k1_context_randomize(ctx, randomize);
    assert(return_val);

    // 生成随机私钥
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
#if 0
    // 正确性验证
    secp256k1_sm2_encryption(ctx, msg_hash, sizeof(msg_hash), &pubkey, NULL, NULL, cip);
    hex_dump("明文", msg_hash, 32);
    hex_dump("密文", cip, 128);
    secp256k1_sm2_decryption(cip, sizeof(msg_hash), m, seckey);
    hex_dump("解密后", m, 32);
    return 0;
#endif
#if 1
    // 测试多线程性能
    // 加密性能
    double begin,end;
    size_t count = 100000;  // 执行次数
    begin = omp_get_wtime();
    #pragma omp parallel for num_threads(thread_num)
    for(int i = 0; i < count;i++){
        return_val = secp256k1_sm2_encryption(ctx, msg_hash, sizeof(msg_hash), &pubkey, NULL, NULL, cip);
    }
    end = omp_get_wtime();
    printf("enc - %d threads: run %d times, , total time: %f s, per second run %f tims\n", \
			thread_num, count, (end-begin), count/(end-begin));
    assert(return_val);

    // 解密性能
    begin = omp_get_wtime();
    #pragma omp parallel for num_threads(thread_num)
    for(int i = 0;i < count; i++){
        secp256k1_sm2_decryption(cip, sizeof(msg_hash), m, seckey);
    }
    end = omp_get_wtime();
    printf("dec - %d threads: run %d times, , total time: %f s, per second run %f tims\n", \
			thread_num, count, (end-begin), count/(end-begin));
#endif
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
}