#include "RSAKeyManager.h"
#include <fstream>
#include <iostream>

RSAKeyManager::RSAKeyManager(const std::string& pubPath, const std::string& privPath)
    : publicKeyPath(pubPath), privateKeyPath(privPath) {}

RSAKeyManager::~RSAKeyManager() {
    if (rsa) {
        RSA_free(rsa);
    }
}

void RSAKeyManager::generateKeys(int bits) {
    BIGNUM* bn = BN_new();
    BN_set_word(bn, RSA_F4);
    rsa = RSA_new();
    if (!RSA_generate_key_ex(rsa, bits, bn, nullptr)) {
        std::cerr << "RSA key generation failed.\n";
    }
    BN_free(bn);
}

void RSAKeyManager::saveKeys() {
    FILE* privFile = fopen(privateKeyPath.c_str(), "wb");
    if (!privFile) throw std::runtime_error("Unable to open private key file.");
    PEM_write_RSAPrivateKey(privFile, rsa, nullptr, nullptr, 0, nullptr, nullptr);
    fclose(privFile);

    FILE* pubFile = fopen(publicKeyPath.c_str(), "wb");
    if (!pubFile) throw std::runtime_error("Unable to open public key file.");
    PEM_write_RSA_PUBKEY(pubFile, rsa);
    fclose(pubFile);
}

void RSAKeyManager::loadKeys() {
    FILE* privFile = fopen(privateKeyPath.c_str(), "rb");
    if (!privFile) throw std::runtime_error("Private key file not found.");
    rsa = PEM_read_RSAPrivateKey(privFile, nullptr, nullptr, nullptr);
    fclose(privFile);
}

std::vector<unsigned char> RSAKeyManager::encryptAESKey(const std::vector<unsigned char>& aesKey) {
    FILE* pubFile = fopen(publicKeyPath.c_str(), "rb");
    if (!pubFile) throw std::runtime_error("Public key file not found.");
    RSA* pubRSA = PEM_read_RSA_PUBKEY(pubFile, nullptr, nullptr, nullptr);
    fclose(pubFile);

    std::vector<unsigned char> encrypted(RSA_size(pubRSA));
    int result = RSA_public_encrypt(aesKey.size(), aesKey.data(), encrypted.data(), pubRSA, RSA_PKCS1_OAEP_PADDING);
    RSA_free(pubRSA);

    if (result == -1) throw std::runtime_error("AES key encryption failed.");
    encrypted.resize(result);
    return encrypted;
}

std::vector<unsigned char> RSAKeyManager::decryptAESKey(const std::vector<unsigned char>& encryptedKey) {
    if (!rsa) loadKeys();

    std::vector<unsigned char> decrypted(RSA_size(rsa));
    int result = RSA_private_decrypt(encryptedKey.size(), encryptedKey.data(), decrypted.data(), rsa, RSA_PKCS1_OAEP_PADDING);
    if (result == -1) throw std::runtime_error("AES key decryption failed.");
    decrypted.resize(result);
    return decrypted;
}