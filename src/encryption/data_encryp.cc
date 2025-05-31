#include "data_encryp.h"
#include <iostream>
#include <sodium.h>
#include <string>
#include <vector>
#include <stdexcept>

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

bool generate_keypair(unsigned char* pk, unsigned char* sk) { // Generar llaves
    if (crypto_box_keypair(pk, sk) != 0) return false;
    return true;
}

// Firmar mensajes

std::vector<unsigned char> sign_message(const std::vector<unsigned char>& message, const unsigned char* sk) {
    std::vector<unsigned char> signed_msg(crypto_sign_BYTES + message.size());
    unsigned long long signed_len;

    if (crypto_sign(signed_msg.data(), &signed_len, message.data(), message.size(), sk) != 0) {
        throw std::runtime_error("Signing failed");
    }

    signed_msg.resize(signed_len);
    return signed_msg;
}


// Verificar  mensajes firmados
bool verify_message(const std::vector<unsigned char>& signed_msg, std::vector<unsigned char>& out_message, const unsigned char* pk) {
    out_message.resize(signed_msg.size());
    unsigned long long msg_len;

    if (crypto_sign_open(out_message.data(), &msg_len, signed_msg.data(), signed_msg.size(), pk) != 0) {
        return false;
    }

    out_message.resize(msg_len);
    return true;
}