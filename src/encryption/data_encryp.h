#ifndef DATA_ENCRYP_H
#define DATA_ENCRYP_H

#include <cstring>
#include <sodium.h>
#include <vector>
#include <iostream>
#include <string>
#include <fstream>
#include <filesystem>

class SessionKeysAsymetric
{
public:
    SessionKeysAsymetric();
    SessionKeysAsymetric(const std::string& keys_file_path);
    ~SessionKeysAsymetric();

    bool load_keys_from_file(const std::string& file_path);
    bool save_keys_to_file(const std::string& file_path);
    std::string export_public_key_hex() const;
    std::string export_long_term_public_key_hex() const;
    
    static void ensure_keys_directory();
    static bool register_client_public_key(const std::string& client_id, const std::string& public_key_hex, const std::string& long_term_public_key_hex);
    static bool is_client_registered(const std::string& public_key_hex, const std::string& long_term_public_key_hex);
    static void initialize_trusted_clients_if_needed();
    static void auto_register_first_client();
    static bool authenticate_and_register_device(const std::string& device_id, 
                                                const std::string& public_key_hex, 
                                                const std::string& long_term_public_key_hex,
                                                const std::string& auth_token = "");
    static bool is_valid_auth_token(const std::string& auth_token);
    static std::string generate_device_auth_challenge();
    static bool verify_device_response(const std::string& challenge, const std::string& response, 
                                      const std::string& public_key_hex);
    static bool is_device_id_registered_with_different_keys(const std::string& device_id, 
                                                           const std::string& public_key_hex, 
                                                           const std::string& long_term_public_key_hex);

    unsigned char public_key[crypto_kx_PUBLICKEYBYTES];
    unsigned char private_key[crypto_kx_SECRETKEYBYTES];
    unsigned char signature[crypto_sign_BYTES];
    unsigned char long_term_public_key[crypto_sign_PUBLICKEYBYTES];
    unsigned char long_term_private_key[crypto_sign_SECRETKEYBYTES];

private:
    void generate_new_keys();
};

class SessionKeysSymetric
{
public:
    SessionKeysSymetric(const unsigned char* public_key, const unsigned char* private_key, const std::vector<unsigned char>& public_key_bin_other, bool is_server) 
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
    SessionKeysSymetric() {};

    std::vector<unsigned char> rx;
    std::vector<unsigned char> tx;
};

#endif // DATA_ENCRYP_H