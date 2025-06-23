#include "FileEncryptor.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <fstream>
#include <iostream>
#include <vector>
#include <cstring>

FileEncryptor::FileEncryptor() {
    // Optionally initialize default paths or clear the key
    inputFilePath = "";
    outputFilePath = "";
    aesKey.clear();
}

void FileEncryptor::setFilePaths(const std::string& input, const std::string& output) {
    inputFilePath = input;
    outputFilePath = output;
}

void FileEncryptor::setKey(const std::vector<unsigned char>& key) {
    aesKey = key;
}

void FileEncryptor::encryptFile() {
    std::ifstream inFile(inputFilePath, std::ios::binary);
    std::ofstream outFile(outputFilePath, std::ios::binary);

    if (!inFile.is_open()) {
        std::cerr << "Error: Could not open input file: " << inputFilePath << "\n";
        return;
    }
    if (!outFile.is_open()) {
        std::cerr << "Error: Could not open output file: " << outputFilePath << "\n";
        return;
    }

    // Extract and save original extension
    size_t extPos = inputFilePath.find_last_of(".");
    std::string originalExt = (extPos != std::string::npos) ? inputFilePath.substr(extPos) : "";
    size_t extLen = originalExt.size();

    // Write magic header
    outFile.write("SFENC", 5);
    outFile.put(static_cast<char>(extLen));
    outFile.write(originalExt.c_str(), extLen);

    unsigned char iv[EVP_MAX_IV_LENGTH];
    RAND_bytes(iv, EVP_MAX_IV_LENGTH);
    outFile.write(reinterpret_cast<char*>(iv), EVP_MAX_IV_LENGTH);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, aesKey.data(), iv);

    std::vector<unsigned char> buffer(4096);
    std::vector<unsigned char> cipherBuffer(4096 + EVP_MAX_BLOCK_LENGTH);
    int outLen;

    while (inFile.read(reinterpret_cast<char*>(buffer.data()), buffer.size()) || inFile.gcount()) {
        EVP_EncryptUpdate(ctx, cipherBuffer.data(), &outLen, buffer.data(), static_cast<int>(inFile.gcount()));
        outFile.write(reinterpret_cast<char*>(cipherBuffer.data()), outLen);
    }

    EVP_EncryptFinal_ex(ctx, cipherBuffer.data(), &outLen);
    outFile.write(reinterpret_cast<char*>(cipherBuffer.data()), outLen);

    EVP_CIPHER_CTX_free(ctx);
}

void FileEncryptor::decryptFile() {
    
    std::ifstream inFile(inputFilePath, std::ios::binary);

    if (!inFile.is_open()) {
        std::cerr << "Error: Could not open input file: " << inputFilePath << "\n";
        return;
    }
 
    // Check magic header
    char header[5];
    inFile.read(header, 5);
    if (std::strncmp(header, "SFENC", 5) != 0) {
        std::cerr << "Error: File is not encrypted with this program or is corrupted.\n";
        return;
    }
    
    // Read original extension
    char extLenChar;
    inFile.get(extLenChar);
    size_t extLen = static_cast<unsigned char>(extLenChar);
    std::string originalExt(extLen, '\0');
    inFile.read(&originalExt[0], extLen);

    std::string adjustedOutput = outputFilePath;
    if (adjustedOutput.find_last_of(".") != std::string::npos) {
        adjustedOutput = adjustedOutput.substr(0, adjustedOutput.find_last_of("."));
    }
    adjustedOutput += originalExt;

    std::ofstream outFile(adjustedOutput, std::ios::binary);
    if (!outFile.is_open()) {
        std::cerr << "Error: Could not open output file: " << adjustedOutput << "\n";
        return;
    }

    unsigned char iv[EVP_MAX_IV_LENGTH];
    inFile.read(reinterpret_cast<char*>(iv), EVP_MAX_IV_LENGTH);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, aesKey.data(), iv);

    std::vector<unsigned char> buffer(4096);
    std::vector<unsigned char> plainBuffer(4096 + EVP_MAX_BLOCK_LENGTH);
    int outLen;

    while (inFile.read(reinterpret_cast<char*>(buffer.data()), buffer.size()) || inFile.gcount()) {
        EVP_DecryptUpdate(ctx, plainBuffer.data(), &outLen, buffer.data(), static_cast<int>(inFile.gcount()));
        outFile.write(reinterpret_cast<char*>(plainBuffer.data()), outLen);
    }

    if (EVP_DecryptFinal_ex(ctx, plainBuffer.data(), &outLen)) {
        outFile.write(reinterpret_cast<char*>(plainBuffer.data()), outLen);
    }
    else {
        std::cerr << "Error: Decryption failed.\n";
    }

    EVP_CIPHER_CTX_free(ctx);
}

bool FileEncryptor::isEncryptedFile() {
    std::ifstream inFile(inputFilePath, std::ios::binary);
    if (!inFile.is_open()) {
        return false;
    }

    char header[5];
    inFile.read(header, 5);
    return std::strncmp(header, "SFENC", 5) == 0;
}
