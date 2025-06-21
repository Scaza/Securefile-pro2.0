#ifndef FILE_ENCRYPTOR_H
#define FILE_ENCRYPTOR_H

#include <iostream>
#include <string>
#include <vector>

constexpr size_t ENCRYPTION_HEADER_SIZE = 14; // Length of "ENCRYPTED_FILE"
const std::string ENCRYPTION_HEADER = "ENCRYPTED_FILE"; // Header to identify encrypted files

class FileEncryptor {
private:
    std::string inputFilePath;
    std::string outputFilePath;
    std::vector<unsigned char> aesKey; // 256-bit AES key
    std::vector<unsigned char> iv;     // Initialization Vector (16 bytes)

public:
    FileEncryptor();

    void setFilePaths(const std::string& input, const std::string& output);
    void setKey(const std::vector<unsigned char>& key);

    bool encryptFile();
    bool decryptFile();

    // New method to check if a file is encrypted
    bool checkIfEncrypted(const std::string& filePath);
};

#endif // FILE_ENCRYPTOR_H