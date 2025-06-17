#include "PasswordManager.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdexcept>
#include <iostream>

PasswordManager::PasswordManager() : userPassword(""), salt() {}

std::string PasswordManager::promptPassword() {
    std::cout << "Enter password: ";
    std::cin >> userPassword;
    return userPassword;
}

std::vector<unsigned char> PasswordManager::generateSalt(size_t length) {
    std::vector<unsigned char> salt(length);
    if (RAND_bytes(salt.data(), length) != 1) {
        throw std::runtime_error("Failed to generate random salt.");
    }
    return salt;
}

std::vector<unsigned char> PasswordManager::deriveKey(const std::string& password, const std::vector<unsigned char>& salt, int iterations, int keyLength) {
    std::vector<unsigned char> derivedKey(keyLength);
    if (PKCS5_PBKDF2_HMAC(password.c_str(), password.size(), salt.data(), salt.size(), iterations, EVP_sha256(), keyLength, derivedKey.data()) != 1) {
        throw std::runtime_error("Failed to derive key using PBKDF2.");
    }
    return derivedKey;
}