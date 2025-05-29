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