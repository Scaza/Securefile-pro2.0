#ifndef FILE_ENCRYPTOR_H
#define FILE_ENCRYPTOR_H

#include <string>
#include <vector>

class FileEncryptor {
private:
    std::string inputFilePath;
    std::string outputFilePath;
    std::vector<unsigned char> aesKey;

public:
    FileEncryptor();
    void setFilePaths(const std::string& input, const std::string& output);
    void setKey(const std::vector<unsigned char>& key);
    void encryptFile();
    void decryptFile();
    bool isEncryptedFile();
};

#endif // FILE_ENCRYPTOR_H
