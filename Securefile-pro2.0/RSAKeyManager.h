
#ifndef RSA_KEY_MANAGER_H
#define RSA_KEY_MANAGER_H

#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <vector>
#include <string>
#include <memory>

class RSAKeyManager {
private:
    std::string publicKeyPath;
    std::string privateKeyPath;
    RSA* rsa = nullptr;

public:
    RSAKeyManager(const std::string& pubPath, const std::string& privPath);
    ~RSAKeyManager();

    void generateKeys(int bits = 2048);
    void saveKeys();
    void loadKeys();
    std::vector<unsigned char> encryptAESKey(const std::vector<unsigned char>& aesKey);
    std::vector<unsigned char> decryptAESKey(const std::vector<unsigned char>& encryptedKey);
};

#endif