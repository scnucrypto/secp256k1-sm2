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
    unsigned char seckey[32];
    unsigned char seckeyInv[32];
    unsigned char seckeyInvSeckey[32];
    // unsigned char seckeyInv[32] = {0xba,0x57,0x1d,0xb0,0x73,0x64,0x40,0x0e,0xc5,0x83,0xb3,0x73,0x7b,0x15,0x74,0xc3,0xca,0xea,0x95,0xb6,0x6f,0xe2,0xb8,0xfe,0xdd,0x2a,0x96,0xcd,0x12,0x4c,0x05,0xa0};
    // unsigned char seckeyInvSeckey[32] = {0x45,0xa8,0xe2,0x4f,0x8c,0x9b,0xbf,0xf1,0x3a,0x7c,0x4c,0x8c,0x84,0xea,0x8b,0x3a,0xef,0xc4,0x47,0x30,0x3f,0x65,0xe7,0x3c,0xe2,0xa7,0xc7,0xbf,0xbd,0xea,0x3b,0xa2};
    unsigned char randomize[32];
    unsigned char compressed_pubkey[33];
    unsigned char serialized_signature[64];
    size_t len;
    int is_signature_valid;
    int return_val;
    secp256k1_pubkey pubkey;
    secp256k1_ecdsa_signature sig;
    /* The specification in secp256k1.h states that `secp256k1_ec_pubkey_create` needs
     * a context object initialized for signing and `secp256k1_ecdsa_verify` needs
     * a context initialized for verification, which is why we create a context
     * for both signing and verification with the SECP256K1_CONTEXT_SIGN and
     * SECP256K1_CONTEXT_VERIFY flags. */
    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    if (!fill_random(randomize, sizeof(randomize))) {
        printf("Failed to generate randomness\n");
        return 1;
    }
    /* Randomizing the context is recommended to protect against side-channel
     * leakage See `secp256k1_context_randomize` in secp256k1.h for more
     * information about it. This should never fail. */
    return_val = secp256k1_context_randomize(ctx, randomize);
    assert(return_val);

    /*** Key Generation ***/

    /* If the secret key is zero or out of range (bigger than secp256k1's
     * order), we try to sample a new key. Note that the probability of this
     * happening is negligible. */
    while (1) {
        if (!fill_random(seckey, sizeof(seckey))) {
            printf("Failed to generate randomness\n");
            return 1;
        }
        if (secp256k1_ec_seckey_verify(ctx, seckey)) {
            break;
        }
    }

    /* Public key creation using a valid context with a verified secret key should never fail */
    return_val = secp256k1_ec_pubkey_create(ctx, &pubkey, seckey);
    assert(return_val);

    /* Serialize the pubkey in a compressed form(33 bytes). Should always return 1. */
    len = sizeof(compressed_pubkey);
    return_val = secp256k1_ec_pubkey_serialize(ctx, compressed_pubkey, &len, &pubkey, SECP256K1_EC_COMPRESSED);
    assert(return_val);
    /* Should be the same size as the size of the output, because we passed a 33 byte array. */
    assert(len == sizeof(compressed_pubkey));

    /*** Signing ***/

    /* Generate an ECDSA signature `noncefp` and `ndata` allows you to pass a
     * custom nonce function, passing `NULL` will use the RFC-6979 safe default.
     * Signing with a valid context, verified secret key
     * and the default nonce function should never fail. */
    // unsigned char seckey[32] = "6ceecf6d2ba1cda1";
    secp256k1_sm2_precomputed(ctx, seckey, seckeyInv, seckeyInvSeckey);
    clock_t start,finish;
    double total_time, average_time;
    int count = 100000;
    start = clock();
    int i = 0;
    for(;i < count;i++){
        return_val = secp256k1_sm2_sign(ctx, &sig, msg_hash, seckey, seckeyInv, seckeyInvSeckey, NULL, NULL);
    }
    finish = clock();
    total_time = (double)(finish - start) / CLOCKS_PER_SEC;
    assert(return_val);
    printf("sign: total time %f seconds\n", total_time);
    printf("sign: one second run %f times\n", 1/(total_time/count));
    /* Serialize the signature in a compact form. Should always return 1
     * according to the documentation in secp256k1.h. */
    return_val = secp256k1_ecdsa_signature_serialize_compact(ctx, serialized_signature, &sig);
    assert(return_val);


    /*** Verification ***/

    /* Deserialize the signature. This will return 0 if the signature can't be parsed correctly. */
    if (!secp256k1_ecdsa_signature_parse_compact(ctx, &sig, serialized_signature)) {
        printf("Failed parsing the signature\n");
        return 1;
    }

    /* Deserialize the public key. This will return 0 if the public key can't be parsed correctly. */
    if (!secp256k1_ec_pubkey_parse(ctx, &pubkey, compressed_pubkey, sizeof(compressed_pubkey))) {
        printf("Failed parsing the public key\n");
        return 1;
    }

    /* Verify a signature. This will return 1 if it's valid and 0 if it's not. */
    start = clock();
    for(i = 0;i < count;i++){
        is_signature_valid = secp256k1_sm2_verify(ctx, &sig, msg_hash, &pubkey);
    }
    finish = clock();
    total_time = (double)(finish - start) / CLOCKS_PER_SEC;
    printf("verify: total time %f seconds\n", total_time);
    printf("verify: one second run %f timess\n", 1/(total_time/count));

    // printf("Is the signature valid? %s\n", is_signature_valid ? "true" : "false");
    // printf("Secret Key: ");
    // print_hex(seckey, sizeof(seckey));
    // printf("Public Key: ");
    // print_hex(compressed_pubkey, sizeof(compressed_pubkey));
    // printf("Signature: ");
    // print_hex(serialized_signature, sizeof(serialized_signature));

    /* This will clear everything from the context and free the memory */
    secp256k1_context_destroy(ctx);

    /* It's best practice to try to clear secrets from memory after using them.
     * This is done because some bugs can allow an attacker to leak memory, for
     * example through "out of bounds" array access (see Heartbleed), Or the OS
     * swapping them to disk. Hence, we overwrite the secret key buffer with zeros.
     *
     * TODO: Prevent these writes from being optimized out, as any good compiler
     * will remove any writes that aren't used. */
    memset(seckey, 0, sizeof(seckey));

    return 0;
}