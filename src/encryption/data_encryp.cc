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
    // Si no existe archivo de clientes confiables, crear cliente automáticamente
    if (!std::filesystem::exists("config/trusted_clients.txt")) {
        std::cout << "[Info] First run detected, creating default client keys...\n";
        
        // Generar claves para el cliente predeterminado
        SessionKeysAsymetric default_client;
        default_client.save_keys_to_file("keys/client_keys.bin");
        
        // Registrar cliente en la lista de confiables
        register_client_public_key("default_client", 
                                 default_client.export_public_key_hex(),
                                 default_client.export_long_term_public_key_hex());
        
        std::cout << "[Info] Default client registered and keys saved\n";
    }
}

void SessionKeysAsymetric::initialize_trusted_clients_if_needed() {
    ensure_keys_directory();
    
    // Si no existe el archivo de clientes confiables, crearlo
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
    
    // Verificar si ya está registrado
    if (is_client_registered(public_key_hex, long_term_public_key_hex)) {
        std::cout << "[Info] Client " << client_id << " already registered\n";
        return true;
    }
    
    // Agregar al archivo
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
        // Saltar comentarios y líneas vacías
        if (line.empty() || line[0] == '#') {
            continue;
        }
        
        // Parsear línea: client_id|public_key_hex|long_term_public_key_hex
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

bool SessionKeysAsymetric::authenticate_and_register_device(const std::string& device_id, 
                                                          const std::string& public_key_hex, 
                                                          const std::string& long_term_public_key_hex,
                                                          const std::string& auth_token) {
    // Verificar si ya está registrado
    if (is_client_registered(public_key_hex, long_term_public_key_hex)) {
        std::cout << "[Auth] Device " << device_id << " already trusted\n";
        return true;
    }
    
    // Para este ejemplo, usamos un token simple o auto-aprobación
    // En producción, aquí verificarías certificados, tokens de fabricante, etc.
    bool is_authorized = false;
    
    if (auth_token.empty()) {
        // Auto-aprobación para desarrollo (SOLO PARA TESTING)
        std::cout << "[Auth] WARNING: Auto-approving device " << device_id << " (DEV MODE)\n";
        is_authorized = true;
    } else if (is_valid_auth_token(auth_token)) {
        // Verificar token de autenticación
        std::cout << "[Auth] Valid auth token for device " << device_id << "\n";
        is_authorized = true;
    } else {
        std::cout << "[Auth] Invalid auth token for device " << device_id << "\n";
        return false;
    }
    
    if (is_authorized) {
        // Registrar dispositivo como confiable
        if (register_client_public_key(device_id, public_key_hex, long_term_public_key_hex)) {
            std::cout << "[Auth] ✓ Device " << device_id << " successfully authenticated and registered as TRUSTED\n";
            return true;
        }
    }
    
    return false;
}

bool SessionKeysAsymetric::is_valid_auth_token(const std::string& auth_token) {
    // Lista de tokens válidos (en producción esto sería más sofisticado)
    std::vector<std::string> valid_tokens = {
        "DEV_TOKEN_12345",
        "MANUFACTURER_CERT_ABC",
        "IOT_DEVICE_APPROVED"
    };
    
    return std::find(valid_tokens.begin(), valid_tokens.end(), auth_token) != valid_tokens.end();
}

std::string SessionKeysAsymetric::generate_device_auth_challenge() {
    // Generar un challenge aleatorio para verificar identidad
    unsigned char challenge[32];
    randombytes_buf(challenge, sizeof(challenge));
    
    char hex[65];
    sodium_bin2hex(hex, sizeof(hex), challenge, sizeof(challenge));
    return std::string(hex);
}

bool SessionKeysAsymetric::verify_device_response(const std::string& challenge, 
                                                 const std::string& response, 
                                                 const std::string& public_key_hex) {
    // Verificar que el dispositivo pudo firmar el challenge con su clave privada
    // (Implementación simplificada)
    return !challenge.empty() && !response.empty() && !public_key_hex.empty();
}

SessionKeysAsymetric::~SessionKeysAsymetric() {
    sodium_memzero(public_key, crypto_kx_PUBLICKEYBYTES);
    sodium_memzero(private_key, crypto_kx_SECRETKEYBYTES);
}