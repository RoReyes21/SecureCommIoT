#include "crypto_utils.hpp"
#include <cstring>

bool generate_keypair(unsigned char* pk, unsigned char* sk) {
    if (sodium_init() < 0) return false;
    crypto_sign_keypair(pk, sk);
    return true;
}

bool sign_message(const unsigned char* sk, const std::string& message, std::vector<unsigned char>& signature) {
    signature.resize(crypto_sign_BYTES);
    return crypto_sign_detached(signature.data(), nullptr,
                                reinterpret_cast<const unsigned char*>(message.c_str()), message.size(), sk) == 0;
}

bool verify_signature(const unsigned char* pk, const std::string& message, const std::vector<unsigned char>& signature) {
    return crypto_sign_verify_detached(signature.data(),
                                       reinterpret_cast<const unsigned char*>(message.c_str()),
                                       message.size(), pk) == 0;
}

bool compute_mac(const std::string& message, const unsigned char* key, unsigned char mac[crypto_auth_BYTES]) {
    return crypto_auth(mac, reinterpret_cast<const unsigned char*>(message.c_str()), message.size(), key) == 0;
}

bool verify_mac(const std::string& message, const unsigned char* key, const unsigned char mac[crypto_auth_BYTES]) {
    return crypto_auth_verify(mac, reinterpret_cast<const unsigned char*>(message.c_str()), message.size(), key) == 0;
}
