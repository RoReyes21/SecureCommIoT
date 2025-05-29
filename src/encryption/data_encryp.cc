#include "data_encryp.h"
#include <iostream>

/**
 * @brief Creation of a new session keys, with Ed25519 and X25519 algorithm.
 * 
 */
SessionKeysAsymetric::SessionKeysAsymetric() {
    if (sodium_init() < 0) {
        std::cout << "[Error] libsodium init failed" << "\n";
    }

    crypto_sign_keypair(long_term_public_key, long_term_private_key); //Ed25519
    crypto_kx_keypair(public_key, private_key); //X25519
    crypto_sign_detached(signature, nullptr, public_key, sizeof(public_key), long_term_private_key);

    if (crypto_sign_detached(signature, nullptr, public_key, sizeof(public_key), long_term_private_key) != 0) {
        std::cout << "[Error] Could not be signed" << "\n";
        return;
    }
}

SessionKeysAsymetric::~SessionKeysAsymetric() {
    sodium_memzero(public_key, crypto_kx_PUBLICKEYBYTES);
    sodium_memzero(private_key, crypto_kx_SECRETKEYBYTES);
}