#pragma 

#ifndef FILEENCRYPTOR_H
#define FILEENCRYPTOR_H

#include <string>
#include <vector>

class FileEncryptor {
private:
    std::string inputFilePath;
    std::string outputFilePath;
    std::vector<unsigned char> aesKey;

public:
    // Constructor
    FileEncryptor(const std::string& inputFile, const std::string& outputFile);

    // Set AES key (256-bit)
    void setKey(const std::vector<unsigned char>& key);

    // Encrypt the file at inputFilePath and write to outputFilePath
    void encryptFile();

    // Decrypt the file at inputFilePath and write to outputFilePath
    void decryptFile();
};

#endif // FILEENCRYPTOR_H