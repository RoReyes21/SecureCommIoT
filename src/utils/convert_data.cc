#include "convert_data.h"

std::string bin_to_hex_string(const unsigned char* bin, size_t bin_len) {
    size_t hex_len = bin_len * 2 + 1;
    char* hex = new char[hex_len];

    sodium_bin2hex(hex, hex_len, bin, bin_len);
    std::string hex_str(hex);

    delete[] hex;

    return hex_str;
}

std::vector<unsigned char> hex_string_to_bin(const std::string& hex_str) {
    std::vector<unsigned char> bin(hex_str.length() / 2);

    size_t bin_len;
    if (sodium_hex2bin(bin.data(), bin.size(), hex_str.c_str(), hex_str.length(), nullptr, &bin_len, nullptr) != 0)
        std::cout << "[ERROR] Could not convert hex string to binary data." << "\n";

    bin.resize(bin_len);

    return bin;
}

std::vector<unsigned char> encrypt_message(const std::vector<unsigned char>& tx_key, const std::string& message, std::vector<unsigned char>& nonce_out) {
    
    nonce_out.resize(crypto_aead_chacha20poly1305_IETF_NPUBBYTES);
    randombytes_buf(nonce_out.data(), nonce_out.size());

    std::vector<unsigned char> ciphertext(message.size() + crypto_aead_chacha20poly1305_IETF_ABYTES);

    unsigned long long ciphertext_len;
    crypto_aead_chacha20poly1305_ietf_encrypt(
        ciphertext.data(), &ciphertext_len,
        reinterpret_cast<const unsigned char*>(message.data()), message.size(),
        nullptr, 0,
        nullptr, nonce_out.data(), tx_key.data()
    );

    ciphertext.resize(ciphertext_len);
    return ciphertext;
}

/*std::string decrypt_message(const std::vector<unsigned char>& rx_key, const std::vector<unsigned char>& ciphertext, const std::vector<unsigned char>& nonce) {
    
    std::vector<unsigned char> decrypted(ciphertext.size() - crypto_aead_chacha20poly1305_IETF_ABYTES);
    unsigned long long decrypted_len;

    if (crypto_aead_chacha20poly1305_ietf_decrypt(
            decrypted.data(), &decrypted_len,
            nullptr,
            ciphertext.data(), ciphertext.size(),
            nullptr, 0,
            nonce.data(), rx_key.data()) != 0) {
        throw std::runtime_error("[ERROR] Decryption failed: Invalid ciphertext or nonce.");
    }

    return std::string(decrypted.begin(), decrypted.end());
}*/

// CAMBIO IMPORTANTE: Implementación de la nueva función decrypt_message
bool decrypt_message(const std::vector<unsigned char>& rx_key, 
                     const std::vector<unsigned char>& ciphertext, 
                     const std::vector<unsigned char>& nonce, 
                     std::string& decrypted_message_out) { // Parámetro de salida

    // Validación de tamaño mínimo: el ciphertext debe contener al menos el tag de autenticación
    if (ciphertext.size() < crypto_aead_chacha20poly1305_IETF_ABYTES) {
        std::cerr << "[ERROR] Decryption failed: Ciphertext too short to contain authentication tag." << std::endl;
        decrypted_message_out = ""; // Asegurarse de que el buffer de salida esté vacío
        return false; // Indicar fallo
    }
    
    // El tamaño del buffer para el mensaje descifrado es el tamaño del ciphertext menos el tag
    std::vector<unsigned char> decrypted_buf(ciphertext.size() - crypto_aead_chacha20poly1305_IETF_ABYTES); 
    unsigned long long decrypted_len;

    // La función de descifrado autenticada. Su valor de retorno es CLAVE para la seguridad.
    if (crypto_aead_chacha20poly1305_ietf_decrypt(
                decrypted_buf.data(), &decrypted_len,
                nullptr, // nsec (not used)
                ciphertext.data(), ciphertext.size(),
                nullptr, // ad (Additional Authenticated Data)
                0,       // <--- ¡CORRECCIÓN AQUÍ! Longitud de AAD (0 porque 'ad' es nullptr)
                nonce.data(),
                rx_key.data()) != 0) {
        
        // Si el valor de retorno es distinto de 0, la autenticación (Poly1305) falló.
        // Esto significa que el mensaje fue manipulado en tránsito o es incorrecto (clave, nonce, etc.).
        std::cerr << "[SECURITY ALERT] Decryption failed: Message has been tampered with or invalid key/nonce! Discarding message." << std::endl;
        decrypted_message_out = ""; // ¡CRÍTICO! Limpiar el buffer por seguridad, nunca usar datos no autenticados.
        return false; // Indicar que la autenticación falló
    }

    // Si llegamos aquí, la autenticación fue exitosa. El mensaje es auténtico e íntegro.
    decrypted_message_out.assign(reinterpret_cast<char*>(decrypted_buf.data()), decrypted_len);
    return true; // Indicar éxito
}
