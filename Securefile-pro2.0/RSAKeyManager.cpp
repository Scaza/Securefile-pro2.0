#include "RSAKeyManager.h"
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <fstream>
#include <iostream>
#include <vector>
#include <stdexcept>


RSAKeyManager::RSAKeyManager(const std::string& pubPath, const std::string& privPath)
    : publicKeyPath(pubPath), privateKeyPath(privPath) {}

void RSAKeyManager::generateKeys() {
    RSA* rsa = RSA_new();
    BIGNUM* e = BN_new();
    BN_set_word(e, RSA_F4);

    if (!RSA_generate_key_ex(rsa, 2048, e, nullptr)) {
        BN_free(e);
        RSA_free(rsa);
        throw std::runtime_error("Failed to generate RSA keys");
    }

    BIO* pub = BIO_new_file(publicKeyPath.c_str(), "w+");
    BIO* priv = BIO_new_file(privateKeyPath.c_str(), "w+");

    PEM_write_bio_RSAPublicKey(pub, rsa);
    PEM_write_bio_RSAPrivateKey(priv, rsa, nullptr, nullptr, 0, nullptr, nullptr);

    BIO_free_all(pub);
    BIO_free_all(priv);
    BN_free(e);
    RSA_free(rsa);
}

void RSAKeyManager::saveKeys(const std::string& pubPath, const std::string& privPath) {
    publicKeyPath = pubPath;
    privateKeyPath = privPath;
    generateKeys();
}

void RSAKeyManager::loadKeys(const std::string& pubPath, const std::string& privPath) {
    
    publicKeyPath = pubPath;
    privateKeyPath = privPath;

    BIO* pub = BIO_new_file(publicKeyPath.c_str(), "r");
    BIO* priv = BIO_new_file(privateKeyPath.c_str(), "r");

    if (!pub || !priv) {
        if (pub) BIO_free(pub);
        if (priv) BIO_free(priv);
        throw std::runtime_error("Unable to open RSA key files");
    }

    publicKey = PEM_read_bio_RSAPublicKey(pub, nullptr, nullptr, nullptr);
    privateKey = PEM_read_bio_RSAPrivateKey(priv, nullptr, nullptr, nullptr);

    BIO_free(pub);
    BIO_free(priv);

    if (!publicKey || !privateKey) {
        throw std::runtime_error("Failed to load RSA keys");
    }
}

std::vector<unsigned char> RSAKeyManager::encryptAESKey(const std::vector<unsigned char>& aesKey) {
    std::vector<unsigned char> encrypted(RSA_size(publicKey));
    int result = RSA_public_encrypt(aesKey.size(), aesKey.data(), encrypted.data(), publicKey, RSA_PKCS1_OAEP_PADDING);

    if (result == -1) {
        throw std::runtime_error("RSA encryption failed");
    }
    encrypted.resize(result);
    return encrypted;
}

std::vector<unsigned char> RSAKeyManager::decryptAESKey(const std::vector<unsigned char>& encryptedKey) {
    std::vector<unsigned char> decrypted(RSA_size(privateKey));
    int result = RSA_private_decrypt(encryptedKey.size(), encryptedKey.data(), decrypted.data(), privateKey, RSA_PKCS1_OAEP_PADDING);

    if (result == -1) {
        throw std::runtime_error("RSA decryption failed");
    }
    decrypted.resize(result);
    return decrypted;
}
