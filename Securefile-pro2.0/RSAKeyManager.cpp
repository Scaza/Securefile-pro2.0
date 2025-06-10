#include "RSAKeyManager.h"
#include <fstream>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <stdexcept>
#include <iostream>
#include <filesystem>
namespace fs = std::filesystem;


// Generate RSA keys and save them to files
void RSAKeyManager::generateKeys() {
    RSA* rsa = RSA_new();
    BIGNUM* bn = BN_new();
    BN_set_word(bn, RSA_F4);
    RSA_generate_key_ex(rsa, 2048, bn, nullptr);

    BIO* pri = BIO_new_file(privateKeyPath.c_str(), "w");
    PEM_write_bio_RSAPrivateKey(pri, rsa, nullptr, nullptr, 0, nullptr, nullptr);
    BIO_free(pri);

    BIO* pub = BIO_new_file(publicKeyPath.c_str(), "w");
    PEM_write_bio_RSA_PUBKEY(pub, rsa);
    BIO_free(pub);

    BN_free(bn);
    RSA_free(rsa);
}

// Load public and private keys from files
void RSAKeyManager::loadKeys(const std::string& pubPath, const std::string& privPath) {
    publicKeyPath = pubPath;
    privateKeyPath = privPath;

	// Load public key
    FILE* pubFile = fopen(publicKeyPath.c_str(), "rb");
    if (!pubFile) {
        throw std::runtime_error("Failed to open public key file.");
    }
    publicKey = PEM_read_RSA_PUBKEY(pubFile, nullptr, nullptr, nullptr);
    fclose(pubFile);
    if (!publicKey) {
        throw std::runtime_error("Failed to read public key.");
    }

	// Load private key
    FILE* privFile = fopen(privateKeyPath.c_str(), "rb");
    if (!privFile) {
        throw std::runtime_error("Failed to open private key file.");
    }
    privateKey = PEM_read_RSAPrivateKey(privFile, nullptr, nullptr, nullptr);
    fclose(privFile);
    if (!privateKey) {
        throw std::runtime_error("Failed to read private key.");
    }
}

// Save public and private keys to files

void RSAKeyManager::saveKeys(const std::string& pubPath, const std::string& privPath) {
    publicKeyPath = pubPath;
    privateKeyPath = privPath;

    // Create the directory if it does not exist
    fs::path pubDir = fs::path(publicKeyPath).parent_path();
    fs::create_directories(pubDir);

    // Save public key
    FILE* pubFile = fopen(publicKeyPath.c_str(), "wb");
    if (!pubFile) {
        throw std::runtime_error("Failed to open file to save public key." + publicKeyPath);
    }

    if (!PEM_write_RSA_PUBKEY(pubFile, publicKey)) {
        fclose(pubFile);
        throw std::runtime_error("Failed to write public key." + publicKeyPath);
    }
    fclose(pubFile);

    // Save private key
    FILE* privFile = fopen(privateKeyPath.c_str(), "wb");
    if (!privFile) {
        throw std::runtime_error("Failed to open file to save private key." + privateKeyPath);
    }

    if (!PEM_write_RSAPrivateKey(privFile, privateKey, nullptr, nullptr, 0, nullptr, nullptr)) {
        fclose(privFile);
        throw std::runtime_error("Failed to write private key." + privateKeyPath);
    }
    fclose(privFile);

	std::cout << "Keys saved successfully to " << publicKeyPath << " and " << privateKeyPath << "\n";


}







// Encrypt the AES key using the public RSA key
std::vector<unsigned char> RSAKeyManager::encryptAESKey(const std::vector<unsigned char>& aesKey) {
    std::vector<unsigned char> encrypted(RSA_size(publicKey));
    int len = RSA_public_encrypt(
        aesKey.size(), aesKey.data(), encrypted.data(), publicKey, RSA_PKCS1_OAEP_PADDING);
    if (len == -1) throw std::runtime_error("RSA encryption failed");
    encrypted.resize(len);
    return encrypted;
}


// Decrypt the AES key using the private RSA key
std::vector<unsigned char> RSAKeyManager::decryptAESKey(const std::vector<unsigned char>& encryptedKey) {
    std::vector<unsigned char> decrypted(RSA_size(privateKey));
    int len = RSA_private_decrypt(
        encryptedKey.size(), encryptedKey.data(), decrypted.data(), privateKey, RSA_PKCS1_OAEP_PADDING);
    if (len == -1) throw std::runtime_error("RSA decryption failed");
    decrypted.resize(len);
    return decrypted;
}

// Set custom key paths for public and private keys
void RSAKeyManager::setKeyPaths(const std::string& pub, const std::string& pri) {
    publicKeyPath = pub;
    privateKeyPath = pri;
}


//destructor to clean up allocated RSA structures
RSAKeyManager::~RSAKeyManager() {
    if (publicKey) RSA_free(publicKey);
    if (privateKey) RSA_free(privateKey);
}