#include <stdio.h>
#include <assert.h>
#include <string.h>

#include <secp256k1.h>
#include <random.h>
#include <time.h>

int main(void) {
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

    /*** Enctryption ***/
    clock_t start,finish;
    double total_time, average_time;
    start = clock();
    int i = 0;
    for(;i < 1;i++){
        return_val = secp256k1_sm2_encryption(ctx, msg_hash, sizeof(msg_hash), &pubkey, NULL, NULL, cip);
    }
    finish = clock();
    total_time = (double)(finish - start) / CLOCKS_PER_SEC;
    assert(return_val);
    printf("encryption %d times, total time %f seconds\n", i,total_time);
    printf("average time %f seconds\n", average_time/(float)i);
    
    /*** Decryption ***/
    start = clock();
    for(i = 0;i < 1;i++){
        is_signature_valid = secp256k1_sm2_decryption(cip, sizeof(msg_hash), m, seckey);
    }
    finish = clock();
    total_time = (double)(finish - start) / CLOCKS_PER_SEC;
    printf("total time %f seconds\n", total_time);
    printf("average time %f seconds\n", average_time/i);

    printf("Is the decrytion succeed? %s\n", is_signature_valid ? "true" : "false");
    
    /* This will clear everything from the context and free the memory */
    secp256k1_context_destroy(ctx);
    memset(seckey, 0, sizeof(seckey));

    return 0;
}