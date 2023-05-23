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

static void print_ge(secp256k1_ge t){

}
int run(int thread_num){
    /* Instead of signing the message directly, we must sign a 32-byte hash.
     * Here the message is "Hello, world!" and the hash function was SHA-256.
     * An actual implementation should just call SHA-256, but this example
     * hardcodes the output to avoid depending on an additional library.
     * See https://bitcoin.stackexchange.com/questions/81115/if-someone-wanted-to-pretend-to-be-satoshi-by-posting-a-fake-signature-to-defrau/81116#81116 */
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
    int is_signature_valid;
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

    /*** Key Generation ***/
    while (1) {
        if (!fill_random(seckey, sizeof(seckey))) {
            printf("Failed to generate randomness\n");
            return 1;
        }
        if (secp256k1_ec_seckey_verify(ctx, seckey)) {
            break;
        }
    }

    return_val = secp256k1_ec_pubkey_create(ctx, &pubkey, seckey);
    assert(return_val);
    len = sizeof(compressed_pubkey);
    return_val = secp256k1_ec_pubkey_serialize(ctx, compressed_pubkey, &len, &pubkey, SECP256K1_EC_COMPRESSED);
    assert(return_val);
    assert(len == sizeof(compressed_pubkey));
#if 1
//    // 正确性测试
//    secp256k1_ge Q;
//    secp256k1_gej tj;
//    secp256k1_ge t;
//    secp256k1_scalar sec;
//
//    // 计算[d]G
//    secp256k1_scalar_set_b32(&sec, seckey, NULL);
//    secp256k1_ecmult_gen(ctx, &tj, &sec);
//    secp256k1_ge_set_gej(&t, &tj);  // 将雅可比坐标转换为仿射坐标
//    secp256k1_pubkey_load(ctx, &Q, &pubkey);


    secp256k1_sm2_encryption(ctx, msg_hash, sizeof(msg_hash), &pubkey, NULL, NULL, cip);
    hex_dump("明文", msg_hash, 32);
    hex_dump("密文", cip, 128);
    secp256k1_sm2_decryption(cip, sizeof(msg_hash), m, seckey);
    hex_dump("解密后", m, 32);
    return 0;
#endif
    /*** Enctryption ***/
//    clock_t start,finish;
//    double total_time, average_time;
//    start = clock();
//    int i = 0;
//    for(;i < 1;i++){
//        return_val = secp256k1_sm2_encryption(ctx, msg_hash, sizeof(msg_hash), &pubkey, NULL, NULL, cip);
//    }
//    finish = clock();
//    total_time = (double)(finish - start) / CLOCKS_PER_SEC;
//    assert(return_val);
//    printf("encryption %d times, total time %f seconds\n", i,total_time);
//    printf("average time %f seconds\n", average_time/(float)i);
//
    double begin,end;
    size_t count = 1;

    begin = omp_get_wtime();
    #pragma omp parallel for num_threads(thread_num)
    for(int i = 0; i < count;i++){
        return_val = secp256k1_sm2_encryption(ctx, msg_hash, sizeof(msg_hash), &pubkey, NULL, NULL, cip);
    }
    end = omp_get_wtime();
    printf("enc - %d threads: run %d times, , total time: %f s, per second run %f tims\n", \
			thread_num, count, (end-begin), count/(end-begin));
    assert(return_val);
    /*** Decryption ***/
//    start = clock();
//    for(i = 0;i < 1;i++){
//        is_signature_valid = secp256k1_sm2_decryption(cip, sizeof(msg_hash), m, seckey);
//    }
//    finish = clock();
//    total_time = (double)(finish - start) / CLOCKS_PER_SEC;
//    printf("total time %f seconds\n", total_time);
//    printf("average time %f seconds\n", average_time/i);
    begin = omp_get_wtime();
    #pragma omp parallel for num_threads(thread_num)
    for(int i = 0;i < count; i++){
        is_signature_valid = secp256k1_sm2_decryption(cip, sizeof(msg_hash), m, seckey);
    }
    end = omp_get_wtime();
    printf("dec - %d threads: run %d times, , total time: %f s, per second run %f tims\n", \
			thread_num, count, (end-begin), count/(end-begin));
//
//   printf("Is the decrytion succeed? %s %d\n", is_signature_valid ? "true" : "false", is_signature_valid);
//    print_hex(m, 32);
    /* This will clear everything from the context and free the memory */
    secp256k1_context_destroy(ctx);
    memset(seckey, 0, sizeof(seckey));
    return 0;
}

int main(){
    run(1);
//    run(2);
//    run(4);
//    run(8);
//    run(12);
//    run(32);
}