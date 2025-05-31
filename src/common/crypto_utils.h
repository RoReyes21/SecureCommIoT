#pragma once
#include <sodium.h>
#include <string>
#include <vector>

bool generate_keypair(unsigned char* pk, unsigned char* sk);
bool sign_message(const unsigned char* sk, const std::string& message, std::vector<unsigned char>& signature);
bool verify_signature(const unsigned char* pk, const std::string& message, const std::vector<unsigned char>& signature);
bool compute_mac(const std::string& message, const unsigned char* key, unsigned char mac[crypto_auth_BYTES]);
bool verify_mac(const std::string& message, const unsigned char* key, const unsigned char mac[crypto_auth_BYTES]);
