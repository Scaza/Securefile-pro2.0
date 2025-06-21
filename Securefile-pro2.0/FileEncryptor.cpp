#include "FileEncryptor.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <fstream>
#include <iostream>
#include <stdexcept>

FileEncryptor::FileEncryptor() {
    iv.resize(16);
    if (!RAND_bytes(iv.data(), iv.size())) {
        throw std::runtime_error("Error: Failed to generate IV.");
    }
}

void FileEncryptor::setFilePaths(const std::string& input, const std::string& output) {
    inputFilePath = input;
    outputFilePath = output;
}

void FileEncryptor::setKey(const std::vector<unsigned char>& key) {
    aesKey = key;
}

bool FileEncryptor::checkIfEncrypted(const std::string& filePath) {
    std::ifstream inFile(filePath, std::ios::binary);
    if (!inFile) {
        throw std::runtime_error("Error: Could not open file to check encryption status.");
    }

    // Read the first few bytes of the file
    std::vector<unsigned char> buffer(ENCRYPTION_HEADER_SIZE); // Ensure buffer is declared as a vector
    inFile.read(reinterpret_cast<char*>(buffer.data()), static_cast<std::streamsize>(buffer.size()));

    // Check if the header matches
    return std::string(buffer.begin(), buffer.begin() + ENCRYPTION_HEADER.size()) == ENCRYPTION_HEADER;
}

bool FileEncryptor::encryptFile() {
    if (aesKey.empty()) {
        std::cerr << "Error: AES key is not set.\n";
        return false;
    }

    std::ifstream inputFile(inputFilePath, std::ios::binary);
    std::ofstream outputFile(outputFilePath, std::ios::binary);

    if (!inputFile || !outputFile) {
        std::cerr << "Error: Failed to open input or output file.\n";
        return false;
    }

    // Write the encryption header
    outputFile.write(ENCRYPTION_HEADER.c_str(), ENCRYPTION_HEADER.size());

    // Write the IV to the output file
    outputFile.write(reinterpret_cast<char*>(iv.data()), iv.size());

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, aesKey.data(), iv.data());

    std::vector<unsigned char> buffer(4096); // Ensure buffer is declared as a vector
    std::vector<unsigned char> outBuffer(4096 + EVP_MAX_BLOCK_LENGTH);
    int outLen;

    while (inputFile.good()) {
        inputFile.read(reinterpret_cast<char*>(buffer.data()), static_cast<std::streamsize>(buffer.size()));
        std::streamsize bytesRead = inputFile.gcount();

        EVP_EncryptUpdate(ctx, outBuffer.data(), &outLen, buffer.data(), static_cast<int>(bytesRead));
        outputFile.write(reinterpret_cast<char*>(outBuffer.data()), outLen);
    }

    EVP_EncryptFinal_ex(ctx, outBuffer.data(), &outLen);
    outputFile.write(reinterpret_cast<char*>(outBuffer.data()), outLen);

    EVP_CIPHER_CTX_free(ctx);
    return true;
}

bool FileEncryptor::decryptFile() {
    if (aesKey.empty()) {
        std::cerr << "Error: AES key is not set.\n";
        return false;
    }

    std::ifstream inputFile(inputFilePath, std::ios::binary);
    std::ofstream outputFile(outputFilePath, std::ios::binary);

    if (!inputFile || !outputFile) {
        std::cerr << "Error: Failed to open input or output file.\n";
        return false;
    }

    // Read and verify the encryption header
    std::vector<unsigned char> buffer(ENCRYPTION_HEADER_SIZE); // Ensure buffer is declared as a vector
    inputFile.read(reinterpret_cast<char*>(buffer.data()), static_cast<std::streamsize>(buffer.size()));
    if (std::string(buffer.begin(), buffer.begin() + ENCRYPTION_HEADER.size()) != ENCRYPTION_HEADER) {
        throw std::runtime_error("Error: File is not encrypted or has an invalid format.");
    }

    // Read the IV from the input file
    inputFile.read(reinterpret_cast<char*>(iv.data()), iv.size());

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, aesKey.data(), iv.data());

    std::vector<unsigned char> dataBuffer(4096);
    std::vector<unsigned char> outBuffer(4096 + EVP_MAX_BLOCK_LENGTH);
    int outLen;

    while (inputFile.good()) {
        inputFile.read(reinterpret_cast<char*>(dataBuffer.data()), static_cast<std::streamsize>(dataBuffer.size()));
        std::streamsize bytesRead = inputFile.gcount();
        if (bytesRead <= 0) break;

        if (!EVP_DecryptUpdate(ctx, outBuffer.data(), &outLen, dataBuffer.data(), static_cast<int>(bytesRead))) {
            std::cerr << "Decryption failed during update.\n";
            EVP_CIPHER_CTX_free(ctx);
            return false;
        }
        outputFile.write(reinterpret_cast<char*>(outBuffer.data()), outLen);
    }

    if (!EVP_DecryptFinal_ex(ctx, outBuffer.data(), &outLen)) {
        std::cerr << "Decryption failed: Possibly incorrect key or corrupted data.\n";
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    outputFile.write(reinterpret_cast<char*>(outBuffer.data()), outLen);

    EVP_CIPHER_CTX_free(ctx);
    return true;
}