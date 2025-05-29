#ifndef DATA_ENCRYP_H
#define DATA_ENCRYP_H

#include <cstring>
#include <sodium.h>

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
    SessionKeySymetric();
    SessionKeySymetric(char key[crypto_secretstream_xchacha20poly1305_KEYBYTES]) {
        sodium_memzero(this->key, crypto_secretstream_xchacha20poly1305_KEYBYTES);
        memcpy(this->key, key, crypto_secretstream_xchacha20poly1305_KEYBYTES);
    }
    ~SessionKeySymetric();

private:
    unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES];
};

#endif // DATA_ENCRYP_H