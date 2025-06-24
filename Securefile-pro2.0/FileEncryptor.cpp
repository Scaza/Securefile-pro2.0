#include "FileEncryptor.h"
#include "Benchmarking.h"
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <iostream>
#include <fstream>
#include <thread>
#include <vector>
#include <mutex>
#include <chrono>

#define CHUNK_SIZE 1048576  // 1 MB per chunk

FileEncryptor::FileEncryptor(const std::string& inputPath) {
    this->inputFilePath = inputPath;
}

FileEncryptor::FileEncryptor(const std::string& inputPath, const std::string& outputPath) {

    this->inputFilePath = inputPath;
    this->outputFilePath = outputPath;
}

void FileEncryptor::setKey(const std::vector<unsigned char>& key) {
    aesKey = key;
}

void FileEncryptor::setFilePaths(const std::string& inputPath, const std::string& outputPath) {
    inputFilePath = inputPath;
    outputFilePath = outputPath;
}

bool FileEncryptor::isEncryptedFile() {
    
    std::ifstream inFile(inputFilePath, std::ios::binary);
    
    if (!inFile.is_open()) {
        std::cerr << "Error: Cannot open file to check encryption status.\n";
        return false;
    }

    char signature[12] = { 0 };
    inFile.read(signature, 11);
    inFile.close();

    return std::string(signature) == "ENCRYPTED::";
}

void FileEncryptor::encryptFile() {
    if (isEncryptedFile()) {
        std::cerr << "Error: File is already encrypted.\n";
        return;
    }

    std::ifstream inFile(inputFilePath, std::ios::binary);
    if (!inFile.is_open()) {
        std::cerr << "Error: Cannot open input file for encryption.\n";
        return;
    }

    std::ofstream outFile(outputFilePath, std::ios::binary);
    if (!outFile.is_open()) {
        std::cerr << "Error: Cannot open output file for encryption.\n";
        return;
    }

    outFile.write("ENCRYPTED::", 11);

    Benchmarking benchmark;
    benchmark.start();

    std::vector<std::thread> threads;
    std::mutex fileMutex;
    size_t chunkIndex = 0;

    while (!inFile.eof()) {
        std::vector<unsigned char> buffer(CHUNK_SIZE);
        inFile.read(reinterpret_cast<char*>(buffer.data()), CHUNK_SIZE);
        std::streamsize bytesRead = inFile.gcount();

        if (bytesRead <= 0) break;

        threads.emplace_back([&, buffer, bytesRead, chunkIndex]() {
            std::vector<unsigned char> encryptedData = encryptChunk(buffer, bytesRead);

            std::lock_guard<std::mutex> lock(fileMutex);
            outFile.seekp(11 + chunkIndex * CHUNK_SIZE);
            outFile.write(reinterpret_cast<const char*>(encryptedData.data()), bytesRead);
        });

        ++chunkIndex;
    }

    for (auto& t : threads) {
        if (t.joinable()) t.join();
    }

    inFile.close();
    outFile.close();

    double elapsed = benchmark.stop();
    std::cout << "Encryption completed in " << elapsed << " seconds.\n";
}

void FileEncryptor::decryptFile() {
    if (!isEncryptedFile()) {
        std::cerr << "Error: File is not encrypted or already decrypted.\n";
        return;
    }

    std::ifstream inFile(inputFilePath, std::ios::binary);
    if (!inFile.is_open()) {
        std::cerr << "Error: Cannot open input file for decryption.\n";
        return;
    }

    std::ofstream outFile(outputFilePath, std::ios::binary);
    if (!outFile.is_open()) {
        std::cerr << "Error: Cannot open output file for decryption.\n";
        return;
    }

    // Skip the ENCRYPTED signature
    inFile.seekg(11);

    Benchmarking benchmark;
    benchmark.start();

    std::vector<std::thread> threads;
    std::mutex fileMutex;
    size_t chunkIndex = 0;

    while (!inFile.eof()) {
        std::vector<unsigned char> buffer(CHUNK_SIZE);
        inFile.read(reinterpret_cast<char*>(buffer.data()), CHUNK_SIZE);
        std::streamsize bytesRead = inFile.gcount();

        if (bytesRead <= 0) break;

        threads.emplace_back([&, buffer, bytesRead, chunkIndex]() {
            std::vector<unsigned char> decryptedData = decryptChunk(buffer, bytesRead);

            std::lock_guard<std::mutex> lock(fileMutex);
            outFile.seekp(chunkIndex * CHUNK_SIZE);
            outFile.write(reinterpret_cast<const char*>(decryptedData.data()), bytesRead);
        });

        ++chunkIndex;
    }

    for (auto& t : threads) {
        if (t.joinable()) t.join();
    }

    inFile.close();
    outFile.close();

    double elapsed = benchmark.stop();
    std::cout << "Decryption completed in " << elapsed << " seconds.\n";
}

std::vector<unsigned char> FileEncryptor::encryptChunk(const std::vector<unsigned char>& data, size_t length) {
    std::vector<unsigned char> encryptedData(length);

    AES_KEY encryptKey;
    AES_set_encrypt_key(aesKey.data(), 256, &encryptKey);

    for (size_t i = 0; i < length; i += AES_BLOCK_SIZE) {
        AES_encrypt(data.data() + i, encryptedData.data() + i, &encryptKey);
    }

    return encryptedData;
}

std::vector<unsigned char> FileEncryptor::decryptChunk(const std::vector<unsigned char>& data, size_t length) {
    std::vector<unsigned char> decryptedData(length);

    AES_KEY decryptKey;
    AES_set_decrypt_key(aesKey.data(), 256, &decryptKey);

    for (size_t i = 0; i < length; i += AES_BLOCK_SIZE) {
        AES_decrypt(data.data() + i, decryptedData.data() + i, &decryptKey);
    }

    return decryptedData;
}