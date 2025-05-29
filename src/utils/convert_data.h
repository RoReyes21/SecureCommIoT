#ifndef CONVERT_DATA_H
#define CONVERT_DATA_H

#include <sodium.h>
#include <string>
#include <vector>
#include <iostream>

std::string bin_to_hex_string(const unsigned char* bin, size_t bin_len);
std::vector<unsigned char> hex_string_to_bin(const std::string& hex_str);

#endif // CONVERT_DATA_H