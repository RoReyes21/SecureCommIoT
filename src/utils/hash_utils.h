#ifndef HASH_UTILS_H
#define HASH_UTILS_H

#include <vector>
#include <string>

std::vector<unsigned char> sha256_hash(const std::vector<unsigned char>& data);
std::string sha256_hex(const std::vector<unsigned char>& data);

#endif
