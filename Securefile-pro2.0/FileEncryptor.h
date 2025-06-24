#ifndef FILE_ENCRYPTOR_H
#define FILE_ENCRYPTOR_H

#include <string>
#include <vector>
#include <thread>
#include <mutex>

const size_t CHUNK_SIZE = 1024 * 1024; //1mb chunks (adjustable)

class FileEncryptor {
private:
    std::string inputFilePath;
    std::string outputFilePath;
    std::vector<unsigned char> aesKey;
    std::mutex writeMutex;

public:
    FileEncryptor(const std::string& input);
    FileEncryptor(const std::string& input, const std::string& output);
    void setFilePaths(const std::string& input, const std::string& output);
    void setKey(const std::vector<unsigned char>& key);
    void encryptFile();
    void decryptFile();
    bool isEncryptedFile();
    std::vector<unsigned char> encryptChunk(const std::vector<unsigned char>& data, size_t length);
    std::vector<unsigned char> decryptChunk(const std::vector<unsigned char>& data, size_t length);
    
};

#endif // FILE_ENCRYPTOR_H
