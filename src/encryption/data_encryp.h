#ifndef DATA_ENCRYP_H
#define DATA_ENCRYP_H

#include <cstring>
#include <sodium.h>

class SessionKeysAsymetric
{
public:
    SessionKeysAsymetric();
    ~SessionKeysAsymetric();

private:
    unsigned char public_key[crypto_kx_PUBLICKEYBYTES];
    unsigned char secret_key[crypto_kx_SECRETKEYBYTES];
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