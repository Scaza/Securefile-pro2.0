#include "PasswordManager.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <iostream>
#include <vector>
#include <stdexcept>

std::string PasswordManager::promptPassword() {
    std::string password;
    std::cout << "Enter a password: ";
    std::cin >> password;
    return password;
}

std::vector<unsigned char> PasswordManager::generateSalt(size_t length) {
    std::vector<unsigned char> salt(length);

    if (RAND_bytes(salt.data(), static_cast<int>(length)) != 1) {
        throw std::runtime_error("Error generating random salt.");
    }

    return salt;
}

std::vector<unsigned char> PasswordManager::deriveKey(const std::string& password, const std::vector<unsigned char>& salt, int keyLength) {
    
    std::vector<unsigned char> key(keyLength);

    const EVP_MD* digest = EVP_sha256();
    int result = PKCS5_PBKDF2_HMAC(
        password.c_str(), static_cast<int>(password.length()),
        salt.data(), static_cast<int>(salt.size()),
        10000, digest, keyLength, key.data()
    );

    if (result != 1) {
        throw std::runtime_error("Error deriving key.");
    }

    return key;
}

std::string PasswordManager::promptPasswordConfirmation() {

    std::string password;
    std::cout << "Confirm password selection: ";
    std::cin >> password;
    return password;

}