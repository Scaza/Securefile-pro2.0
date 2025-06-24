#include "HashUtility.h"
#include <openssl/sha.h>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <vector>

std::string HashUtility::calculateHash(const std::string& filePath) {
    std::ifstream file(filePath, std::ios::binary);
    if (!file) {
        throw std::runtime_error("Error: Could not open file for hashing.");
    }

    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    char buffer[4096];
    while (file.read(buffer, sizeof(buffer)) || file.gcount()) {
        SHA256_Update(&sha256, buffer, file.gcount());
    }

    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_Final(hash, &sha256);

    std::stringstream ss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }

    return ss.str();
}

bool HashUtility::verifyHash(const std::string& filePath, const std::string& expectedHash) {
    return calculateHash(filePath) == expectedHash;
}