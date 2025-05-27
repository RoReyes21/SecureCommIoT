#include "data_encryp.h"
#include <iostream>

/**
 * @brief Creation of a new session keys, with X25519 algorithm.
 * 
 */
SessionKeysAsymetric::SessionKeysAsymetric() {
    if (sodium_init() < 0) {
        std::cerr << "libsodium init failed" << std::endl;
    }

    crypto_kx_keypair(public_key, secret_key);
}

SessionKeysAsymetric::~SessionKeysAsymetric() {
    sodium_memzero(public_key, crypto_kx_PUBLICKEYBYTES);
    sodium_memzero(secret_key, crypto_kx_SECRETKEYBYTES);
}

/**
 * @brief Creation of a new session keys, with CHACHA20 algorithm.
 * 
 */
SessionKeySymetric::SessionKeySymetric(/* args */) {
    if (sodium_init() < 0) {
        std::cerr << "libsodium init failed" << std::endl;
    }

    crypto_secretstream_xchacha20poly1305_keygen(key);
}

SessionKeySymetric::~SessionKeySymetric() {
    sodium_memzero(key, crypto_secretstream_xchacha20poly1305_KEYBYTES);
}