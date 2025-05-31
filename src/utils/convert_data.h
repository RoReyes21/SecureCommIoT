#ifndef CONVERT_DATA_H
#define CONVERT_DATA_H

#include <sodium.h>
#include <string>
#include <vector>
#include <iostream>

std::string bin_to_hex_string(const unsigned char* bin, size_t bin_len);
std::vector<unsigned char> hex_string_to_bin(const std::string& hex_str);

std::vector<unsigned char> encrypt_message(const std::vector<unsigned char>& tx_key, const std::string& message, std::vector<unsigned char>& nonce_out);

// Devuelve bool y pasa el mensaje descifrado por referencia, contendrá el mensaje descifrado si la autenticación es exitosa
bool decrypt_message(const std::vector<unsigned char>& rx_key, const std::vector<unsigned char>& ciphertext, const std::vector<unsigned char>& nonce, std::string& decrypted_message_out);

#endif // CONVERT_DATA_H
