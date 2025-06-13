#include "RSAKeyManager.h"
#include <openssl/pem.h>
#include <openssl/err.h>
#include <stdexcept>
#include <iostream>
#include <openssl/rsa.h>

RSAKeyManager::RSAKeyManager() {}

RSAKeyManager::~RSAKeyManager() {
    if (publicKey) RSA_free(publicKey);
    if (privateKey) RSA_free(privateKey);
}

void RSAKeyManager::generateKeys() {
    RSA* rsa = RSA_new();
    BIGNUM* bn = BN_new();
    BN_set_word(bn, RSA_F4);
    RSA_generate_key_ex(rsa, 2048, bn, nullptr);

    // Save public key
    FILE* pubFile = fopen(publicKeyPath.c_str(), "wb");
    if (!pubFile) {
        throw std::runtime_error("Error: Failed to open file to save public key.");
    }
    PEM_write_RSA_PUBKEY(pubFile, rsa);
    fclose(pubFile);

    // Save private key
    FILE* privFile = fopen(privateKeyPath.c_str(), "wb");
    if (!privFile) {
        throw std::runtime_error("Error: Failed to open file to save private key.");
    }
    PEM_write_RSAPrivateKey(privFile, rsa, nullptr, nullptr, 0, nullptr, nullptr);
    fclose(privFile);

    RSA_free(rsa);
    BN_free(bn);

    // Print the message only once
    std::cout << "RSA keys generated and saved to " << publicKeyPath << " and " << privateKeyPath << "\n";
}

void RSAKeyManager::loadKeys() {
    // Load public key
    FILE* pubFile = fopen(publicKeyPath.c_str(), "rb");
    if (!pubFile) {
        throw std::runtime_error("Error: Failed to open public key file.");
    }
    publicKey = PEM_read_RSA_PUBKEY(pubFile, nullptr, nullptr, nullptr);
    fclose(pubFile);
    if (!publicKey) {
        throw std::runtime_error("Error: Failed to read public key.");
    }

    // Load private key
    FILE* privFile = fopen(privateKeyPath.c_str(), "rb");
    if (!privFile) {
        throw std::runtime_error("Error: Failed to open private key file.");
    }
    privateKey = PEM_read_RSAPrivateKey(privFile, nullptr, nullptr, nullptr);
    fclose(privFile);
    if (!privateKey) {
        throw std::runtime_error("Error: Failed to read private key.");
    }
}

#include <openssl/rsa.h>
std::vector<unsigned char> RSAKeyManager::encryptAESKey(const std::vector<unsigned char>& aesKey) {
    std::vector<unsigned char> encrypted(RSA_size(publicKey));
    int len = RSA_public_encrypt(
        aesKey.size(), aesKey.data(), encrypted.data(), publicKey, RSA_PKCS1_OAEP_PADDING);
    if (len == -1) {
        throw std::runtime_error("Error: RSA encryption failed.");
    }
    encrypted.resize(len);
    return encrypted;
}

std::vector<unsigned char> RSAKeyManager::decryptAESKey(const std::vector<unsigned char>& encryptedKey) {
    std::vector<unsigned char> decrypted(RSA_size(privateKey));
    int len = RSA_private_decrypt(
        encryptedKey.size(), encryptedKey.data(), decrypted.data(), privateKey, RSA_PKCS1_OAEP_PADDING);
    if (len == -1) {
        throw std::runtime_error("Error: RSA decryption failed.");
    }
    decrypted.resize(len);
    return decrypted;
}