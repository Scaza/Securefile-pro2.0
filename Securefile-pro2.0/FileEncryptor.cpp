#include "FileEncryptor.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <fstream>
#include <iostream>

FileEncryptor::FileEncryptor() {
    iv.resize(16);
    RAND_bytes(iv.data(), iv.size());
}

void FileEncryptor::setFilePaths(const std::string& input, const std::string& output) {
    inputFilePath = input;
    outputFilePath = output;
}

void FileEncryptor::setKey(const std::vector<unsigned char>& key) {
    aesKey = key;
}

bool FileEncryptor::encryptFile() {
    std::ifstream input(inputFilePath, std::ios::binary);
    std::ofstream output(outputFilePath, std::ios::binary);

    if (!input || !output) {
        std::cerr << "File error: Check paths." << std::endl;
        return false;
    }

    output.write(reinterpret_cast<char*>(iv.data()), iv.size());

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, aesKey.data(), iv.data());

    std::vector<unsigned char> buffer(4096);
    std::vector<unsigned char> outBuffer(4096 + EVP_MAX_BLOCK_LENGTH);
    int outLen;

    while (input.good()) {
        input.read(reinterpret_cast<char*>(buffer.data()), buffer.size());
        std::streamsize bytesRead = input.gcount();

        EVP_EncryptUpdate(ctx, outBuffer.data(), &outLen, buffer.data(), static_cast<int>(bytesRead));
        output.write(reinterpret_cast<char*>(outBuffer.data()), outLen);
    }

    EVP_EncryptFinal_ex(ctx, outBuffer.data(), &outLen);
    output.write(reinterpret_cast<char*>(outBuffer.data()), outLen);

    EVP_CIPHER_CTX_free(ctx);
    return true;
}

bool FileEncryptor::decryptFile() {
    std::ifstream input(inputFilePath, std::ios::binary);
    std::ofstream output(outputFilePath, std::ios::binary);

    if (!input || !output) {
        std::cerr << "File error: Check paths." << std::endl;
        return false;
    }

    input.read(reinterpret_cast<char*>(iv.data()), iv.size());

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, aesKey.data(), iv.data());

    std::vector<unsigned char> buffer(4096);
    std::vector<unsigned char> outBuffer(4096 + EVP_MAX_BLOCK_LENGTH);
    int outLen;

    while (input.good()) {
        input.read(reinterpret_cast<char*>(buffer.data()), buffer.size());
        std::streamsize bytesRead = input.gcount();

        EVP_DecryptUpdate(ctx, outBuffer.data(), &outLen, buffer.data(), static_cast<int>(bytesRead));
        output.write(reinterpret_cast<char*>(outBuffer.data()), outLen);
    }

    if (!EVP_DecryptFinal_ex(ctx, outBuffer.data(), &outLen)) {
        std::cerr << "Decryption failed: Possibly incorrect key or corrupted data." << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    output.write(reinterpret_cast<char*>(outBuffer.data()), outLen);

    EVP_CIPHER_CTX_free(ctx);
    return true;
}