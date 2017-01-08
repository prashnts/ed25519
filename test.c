#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

/* #define ED25519_DLL */
#include "src/ed25519.h"

#include "src/ge.h"
#include "src/sc.h"

#include "external/cutest.h"

void test_signature_verify(void) {
    unsigned char public_key[32], private_key[64], seed[32];
    unsigned char signature[64];
    const unsigned char message[] = "Hello, world!";
    const int message_len = strlen((char*) message);

    /* create a random seed, and a keypair out of that seed */
    ed25519_create_seed(seed);
    ed25519_create_keypair(public_key, private_key, seed);

    /* create signature on the message with the keypair */
    ed25519_sign(signature, message, message_len, public_key, private_key);

    /* verify the signature */
    TEST_CHECK(ed25519_verify(signature, message, message_len, public_key));
}

void test_signature_scalar(void) {
    unsigned char public_key[32], private_key[64], seed[32], scalar[32];
    unsigned char signature[64];
    const unsigned char message[] = "Hello, world!";
    const int message_len = strlen((char*) message);

    /* create a random seed, and a keypair out of that seed */
    ed25519_create_seed(seed);
    ed25519_create_keypair(public_key, private_key, seed);

    /* create scalar and add it to the keypair */
    ed25519_create_seed(scalar);
    ed25519_add_scalar(public_key, private_key, scalar);

    /* create signature with the new keypair */
    ed25519_sign(signature, message, message_len, public_key, private_key);

    /* verify the signature with the new keypair */
    TEST_CHECK(ed25519_verify(signature, message, message_len, public_key));
}

void test_signature_changes(void) {
    unsigned char public_key[32], private_key[64], seed[32];
    unsigned char signature[64];
    const unsigned char message[] = "Hello, world!";
    const int message_len = strlen((char*) message);

    ed25519_create_seed(seed);
    ed25519_create_keypair(public_key, private_key, seed);
    ed25519_sign(signature, message, message_len, public_key, private_key);

    signature[44] ^= 0x10;
    TEST_CHECK(!ed25519_verify(signature, message, message_len, public_key));
}

void test_key_exchange(void) {
    unsigned char public_key[32], private_key[64], seed[32];
    unsigned char other_public_key[32], other_private_key[64];
    unsigned char shared_secret[32], other_shared_secret[32];
    int i;

    ed25519_create_seed(seed);
    ed25519_create_keypair(public_key, private_key, seed);
    ed25519_create_seed(seed);
    ed25519_create_keypair(other_public_key, other_private_key, seed);

    /* create two shared secrets - from both perspectives - and check if they're equal */
    ed25519_key_exchange(shared_secret, other_public_key, private_key);
    ed25519_key_exchange(other_shared_secret, public_key, other_private_key);

    for (i = 0; i < 32; ++i) {
        if (shared_secret[i] != other_shared_secret[i]) {
            break;
        }
    }
    TEST_CHECK(i == 32);
}

TEST_LIST = {
   { "Signature Verification", test_signature_verify },
   { "Signature Scalar Addition", test_signature_scalar },
   { "Signature Change", test_signature_changes },
   { "Key Exchange", test_key_exchange },
   { 0 }
};
