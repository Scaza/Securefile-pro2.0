#include "FileEncryptor.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <fstream>
#include <iostream>
#include <cstring>

#define AES_BLOCK_SIZE 16
#define AES_KEY_SIZE 32 // 256-bit key

FileEncryptor::FileEncryptor(const std::string& inputFile, const std::string& outputFile)
    : inputFilePath(inputFile), outputFilePath(outputFile) {}

void FileEncryptor::setKey(const std::vector<unsigned char>& key) {
    if (key.size() != AES_KEY_SIZE) {
        throw std::runtime_error("AES key must be 256 bits (32 bytes) long.");
    }
    aesKey = key;
}

void FileEncryptor::encryptFile() {
    std::ifstream inFile(inputFilePath, std::ios::binary);
    std::ofstream outFile(outputFilePath, std::ios::binary);

    if (!inFile || !outFile) {
        throw std::runtime_error("Failed to open input or output file.");
    }

    unsigned char iv[AES_BLOCK_SIZE];
    if (!RAND_bytes(iv, AES_BLOCK_SIZE)) {
        throw std::runtime_error("Failed to generate IV.");
    }

    outFile.write(reinterpret_cast<char*>(iv), AES_BLOCK_SIZE);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, aesKey.data(), iv);

    const size_t bufferSize = 4096;
    unsigned char inBuffer[bufferSize];
    unsigned char outBuffer[bufferSize + AES_BLOCK_SIZE];
    int outLen;

    while (!inFile.eof()) {
        inFile.read(reinterpret_cast<char*>(inBuffer), bufferSize);
        std::streamsize bytesRead = inFile.gcount();

        if (!EVP_EncryptUpdate(ctx, outBuffer, &outLen, inBuffer, bytesRead)) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("Encryption failed.");
        }

        outFile.write(reinterpret_cast<char*>(outBuffer), outLen);
    }

    if (!EVP_EncryptFinal_ex(ctx, outBuffer, &outLen)) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Final encryption block failed.");
    }

    outFile.write(reinterpret_cast<char*>(outBuffer), outLen);
    EVP_CIPHER_CTX_free(ctx);
}

void FileEncryptor::decryptFile() {
    std::ifstream inFile(inputFilePath, std::ios::binary);
    std::ofstream outFile(outputFilePath, std::ios::binary);

    if (!inFile || !outFile) {
        throw std::runtime_error("Failed to open input or output file.");
    }

    unsigned char iv[AES_BLOCK_SIZE];
    inFile.read(reinterpret_cast<char*>(iv), AES_BLOCK_SIZE);
    if (inFile.gcount() != AES_BLOCK_SIZE) {
        throw std::runtime_error("Failed to read IV.");
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, aesKey.data(), iv);

    const size_t bufferSize = 4096;
    unsigned char inBuffer[bufferSize];
    unsigned char outBuffer[bufferSize + AES_BLOCK_SIZE];
    int outLen;

    while (!inFile.eof()) {
        inFile.read(reinterpret_cast<char*>(inBuffer), bufferSize);
        std::streamsize bytesRead = inFile.gcount();

        if (!EVP_DecryptUpdate(ctx, outBuffer, &outLen, inBuffer, bytesRead)) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("Decryption failed.");
        }

        outFile.write(reinterpret_cast<char*>(outBuffer), outLen);
    }

    if (!EVP_DecryptFinal_ex(ctx, outBuffer, &outLen)) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Final decryption block failed. Possible key/IV mismatch or corrupted file.");
    }

    outFile.write(reinterpret_cast<char*>(outBuffer), outLen);
    EVP_CIPHER_CTX_free(ctx);
}