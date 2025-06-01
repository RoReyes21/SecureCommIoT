#include "data_encryp.h"
#include <iostream>
#include <filesystem>
#include <fstream>
#include <algorithm>

/**
 * @brief Creation of a new session keys, with Ed25519 and X25519 algorithm.
 * 
 */
SessionKeysAsymetric::SessionKeysAsymetric() {
    ensure_keys_directory();
    generate_new_keys();
}

SessionKeysAsymetric::SessionKeysAsymetric(const std::string& keys_file_path) {
    ensure_keys_directory();
    
    if (!load_keys_from_file(keys_file_path)) {
        std::cout << "[Info] Keys file not found, generating new keys and saving to: " << keys_file_path << "\n";
        generate_new_keys();
        save_keys_to_file(keys_file_path);
    } else {
        std::cout << "[Info] Keys loaded from: " << keys_file_path << "\n";
    }
}

void SessionKeysAsymetric::ensure_keys_directory() {
    std::filesystem::create_directories("keys");
    std::filesystem::create_directories("config");
}

void SessionKeysAsymetric::generate_new_keys() {
    if (sodium_init() < 0) {
        std::cout << "[Error] libsodium init failed" << "\n";
        return;
    }

    crypto_sign_keypair(long_term_public_key, long_term_private_key); //Ed25519
    crypto_kx_keypair(public_key, private_key); //X25519
    
    if (crypto_sign_detached(signature, nullptr, public_key, sizeof(public_key), long_term_private_key) != 0) {
        std::cout << "[Error] Could not be signed" << "\n";
        return;
    }
}

bool SessionKeysAsymetric::load_keys_from_file(const std::string& file_path) {
    std::ifstream file(file_path, std::ios::binary);
    if (!file.is_open()) {
        return false;
    }

    file.read(reinterpret_cast<char*>(public_key), crypto_kx_PUBLICKEYBYTES);
    file.read(reinterpret_cast<char*>(private_key), crypto_kx_SECRETKEYBYTES);
    file.read(reinterpret_cast<char*>(signature), crypto_sign_BYTES);
    file.read(reinterpret_cast<char*>(long_term_public_key), crypto_sign_PUBLICKEYBYTES);
    file.read(reinterpret_cast<char*>(long_term_private_key), crypto_sign_SECRETKEYBYTES);

    file.close();
    
    if (sodium_init() < 0) {
        std::cout << "[Error] libsodium init failed" << "\n";
        return false;
    }
    
    return true;
}

bool SessionKeysAsymetric::save_keys_to_file(const std::string& file_path) {
    std::ofstream file(file_path, std::ios::binary);
    if (!file.is_open()) {
        std::cout << "[Error] Could not create keys file: " << file_path << "\n";
        return false;
    }

    file.write(reinterpret_cast<const char*>(public_key), crypto_kx_PUBLICKEYBYTES);
    file.write(reinterpret_cast<const char*>(private_key), crypto_kx_SECRETKEYBYTES);
    file.write(reinterpret_cast<const char*>(signature), crypto_sign_BYTES);
    file.write(reinterpret_cast<const char*>(long_term_public_key), crypto_sign_PUBLICKEYBYTES);
    file.write(reinterpret_cast<const char*>(long_term_private_key), crypto_sign_SECRETKEYBYTES);

    file.close();
    std::cout << "[Info] Keys saved to: " << file_path << "\n";
    return true;
}

std::string SessionKeysAsymetric::export_public_key_hex() const {
    char hex[crypto_kx_PUBLICKEYBYTES * 2 + 1];
    sodium_bin2hex(hex, sizeof(hex), public_key, crypto_kx_PUBLICKEYBYTES);
    return std::string(hex);
}

std::string SessionKeysAsymetric::export_long_term_public_key_hex() const {
    char hex[crypto_sign_PUBLICKEYBYTES * 2 + 1];
    sodium_bin2hex(hex, sizeof(hex), long_term_public_key, crypto_sign_PUBLICKEYBYTES);
    return std::string(hex);
}

void SessionKeysAsymetric::auto_register_first_client() {
    if (!std::filesystem::exists("config/trusted_clients.txt")) {
        std::cout << "[Info] First run detected, creating default client keys...\n";
        
        // Generar múltiples clientes por defecto
        for (int i = 1; i <= 3; i++) {
            std::string client_id = "client" + std::to_string(i);
            std::string key_file = "keys/" + client_id + "_keys.bin";
            
            SessionKeysAsymetric client_keys;
            client_keys.save_keys_to_file(key_file);
            
            register_client_public_key(client_id, 
                                     client_keys.export_public_key_hex(),
                                     client_keys.export_long_term_public_key_hex());
            
            std::cout << "[Info] Default " << client_id << " registered and keys saved to " << key_file << "\n";
        }
    }
}

void SessionKeysAsymetric::initialize_trusted_clients_if_needed() {
    ensure_keys_directory();
    
    if (!std::filesystem::exists("config/trusted_clients.txt")) {
        std::ofstream file("config/trusted_clients.txt");
        if (file.is_open()) {
            file << "# Trusted Clients List\n";
            file << "# Format: client_id|public_key_hex|long_term_public_key_hex\n";
            file.close();
            std::cout << "[Info] Created trusted clients file\n";
        }
    }
}

bool SessionKeysAsymetric::register_client_public_key(const std::string& client_id, 
                                                     const std::string& public_key_hex, 
                                                     const std::string& long_term_public_key_hex) {
    initialize_trusted_clients_if_needed();
    
    if (is_client_registered(public_key_hex, long_term_public_key_hex)) {
        std::cout << "[Info] Client " << client_id << " already registered\n";
        return true;
    }
    
    std::ofstream file("config/trusted_clients.txt", std::ios::app);
    if (!file.is_open()) {
        std::cout << "[Error] Could not open trusted clients file\n";
        return false;
    }
    
    file << client_id << "|" << public_key_hex << "|" << long_term_public_key_hex << "\n";
    file.close();
    
    std::cout << "[Info] Client " << client_id << " registered successfully\n";
    return true;
}

bool SessionKeysAsymetric::is_client_registered(const std::string& public_key_hex, 
                                               const std::string& long_term_public_key_hex) {
    std::ifstream file("config/trusted_clients.txt");
    if (!file.is_open()) {
        return false;
    }
    
    std::string line;
    while (std::getline(file, line)) {
        if (line.empty() || line[0] == '#') {
            continue;
        }
        
        size_t first_pipe = line.find('|');
        size_t second_pipe = line.find('|', first_pipe + 1);
        
        if (first_pipe != std::string::npos && second_pipe != std::string::npos) {
            std::string stored_public_key = line.substr(first_pipe + 1, second_pipe - first_pipe - 1);
            std::string stored_long_term_key = line.substr(second_pipe + 1);
            
            if (stored_public_key == public_key_hex && stored_long_term_key == long_term_public_key_hex) {
                file.close();
                return true;
            }
        }
    }
    
    file.close();
    return false;
}

bool SessionKeysAsymetric::authenticate_and_register_device(const std::string& device_id, const std::string& public_key_hex, const std::string& long_term_public_key_hex,
                                                            const std::string& auth_token) {
    if (is_client_registered(public_key_hex, long_term_public_key_hex)) {
        std::cout << "[Auth] Device " << device_id << " already trusted\n";
        return true;
    }
    
    bool is_authorized = false;
    
    if (auth_token.empty()) {
        std::cout << "[Auth] WARNING: Auto-approving device " << device_id << " (DEV MODE)\n";
        is_authorized = true;
    } else if (is_valid_auth_token(auth_token)) {
        std::cout << "[Auth] Valid auth token for device " << device_id << "\n";
        is_authorized = true;
    } else {
        std::cout << "[Auth] Invalid auth token for device " << device_id << "\n";
        return false;
    }
    
    if (is_authorized) {
        // Verificar que no sea un dispositivo duplicado con el mismo device_id pero claves diferentes
        if (is_device_id_registered_with_different_keys(device_id, public_key_hex, long_term_public_key_hex)) {
            std::cout << "[Auth] WARNING: Device " << device_id << " already exists with different keys. Possible impersonation attempt.\n";
            return false;
        }
        
        if (register_client_public_key(device_id, public_key_hex, long_term_public_key_hex)) {
            std::cout << "[Auth] Device " << device_id << " successfully authenticated and registered as TRUSTED\n";
            return true;
        }
    }
    
    return false;
}

bool SessionKeysAsymetric::is_device_id_registered_with_different_keys(const std::string& device_id, 
                                                                      const std::string& public_key_hex, 
                                                                      const std::string& long_term_public_key_hex) {
    std::ifstream file("config/trusted_clients.txt");
    if (!file.is_open()) {
        return false;
    }
    
    std::string line;
    while (std::getline(file, line)) {
        if (line.empty() || line[0] == '#') {
            continue;
        }
        
        size_t first_pipe = line.find('|');
        size_t second_pipe = line.find('|', first_pipe + 1);
        
        if (first_pipe != std::string::npos && second_pipe != std::string::npos) {
            std::string stored_device_id = line.substr(0, first_pipe);
            std::string stored_public_key = line.substr(first_pipe + 1, second_pipe - first_pipe - 1);
            std::string stored_long_term_key = line.substr(second_pipe + 1);
            
            // Si encontramos el mismo device_id pero con claves diferentes
            if (stored_device_id == device_id && 
                (stored_public_key != public_key_hex || stored_long_term_key != long_term_public_key_hex)) {
                file.close();
                return true;
            }
        }
    }
    
    file.close();
    return false;
}

bool SessionKeysAsymetric::is_valid_auth_token(const std::string& auth_token) {
    std::vector<std::string> valid_tokens = {
        "DEV_TOKEN_12345",
        "MANUFACTURER_CERT_ABC",
        "IOT_DEVICE_APPROVED"
    };
    
    return std::find(valid_tokens.begin(), valid_tokens.end(), auth_token) != valid_tokens.end();
}

std::string SessionKeysAsymetric::generate_device_auth_challenge() {
    unsigned char challenge[32];
    randombytes_buf(challenge, sizeof(challenge));
    
    char hex[65];
    sodium_bin2hex(hex, sizeof(hex), challenge, sizeof(challenge));
    return std::string(hex);
}

bool SessionKeysAsymetric::verify_device_response(const std::string& challenge, 
                                                 const std::string& response, 
                                                 const std::string& public_key_hex) {
    return !challenge.empty() && !response.empty() && !public_key_hex.empty();
}

SessionKeysAsymetric::~SessionKeysAsymetric() {
    sodium_memzero(public_key, crypto_kx_PUBLICKEYBYTES);
    sodium_memzero(private_key, crypto_kx_SECRETKEYBYTES);
}