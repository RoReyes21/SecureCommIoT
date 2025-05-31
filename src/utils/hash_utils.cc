#include "hash_utils.h"
#include <sodium.h>
#include <sstream>
#include <iomanip>

std::vector<unsigned char> sha256_hash(const std::vector<unsigned char>& data) {
    std::vector<unsigned char> hash(crypto_hash_sha256_BYTES);
    crypto_hash_sha256(hash.data(), data.data(), data.size());
    return hash;
}

std::string sha256_hex(const std::vector<unsigned char>& data) {
    std::vector<unsigned char> hash = sha256_hash(data);
    std::ostringstream oss;
    for (unsigned char byte : hash) {
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
    }
    return oss.str();
}
