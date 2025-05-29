#ifndef DATA_ENCRYP_H
#define DATA_ENCRYP_H

#include <cstring>
#include <sodium.h>
#include <vector>
#include <iostream>

class SessionKeysAsymetric
{
public:
    SessionKeysAsymetric();
    ~SessionKeysAsymetric();

    unsigned char public_key[crypto_kx_PUBLICKEYBYTES];
    unsigned char private_key[crypto_kx_SECRETKEYBYTES];
    unsigned char signature[crypto_sign_BYTES];
    unsigned char long_term_public_key[crypto_sign_PUBLICKEYBYTES];
    unsigned char long_term_private_key[crypto_sign_SECRETKEYBYTES];
};

class SessionKeySymetric
{
public:
    SessionKeySymetric(const unsigned char* public_key, const unsigned char* private_key, const std::vector<unsigned char>& public_key_bin_other, bool is_server) 
    {
        if (sodium_init() < 0) {
            std::cerr << "libsodium init failed" << std::endl;
        }

        rx.resize(crypto_kx_SESSIONKEYBYTES);
        tx.resize(crypto_kx_SESSIONKEYBYTES);

        if (is_server) {
            if (crypto_kx_server_session_keys(rx.data(), tx.data(), public_key, private_key, public_key_bin_other.data()) != 0)
                std::cerr << "Error generando claves de sesión" << std::endl;
        } else {
            if (crypto_kx_client_session_keys(rx.data(), tx.data(), public_key, private_key, public_key_bin_other.data()) != 0)
                std::cerr << "Error generando claves de sesión" << std::endl;
        }
    }
    SessionKeySymetric() {};

    std::vector<unsigned char> rx;
    std::vector<unsigned char> tx;
};

#endif // DATA_ENCRYP_H