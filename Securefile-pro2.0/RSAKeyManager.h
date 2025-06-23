#ifndef RSA_KEY_MANAGER_H
#define RSA_KEY_MANAGER_H

#include <string>
#include <vector>
#include <openssl/rsa.h>

class RSAKeyManager {
private:
    std::string publicKeyPath;
    std::string privateKeyPath;

    RSA* publicKey = nullptr;
    RSA* privateKey = nullptr;

public:
    // Constructors
    RSAKeyManager();
    RSAKeyManager(const std::string& pubPath, const std::string& privPath);

    // Key Management
    void generateKeys();
    void saveKeys(const std::string& pubPath, const std::string& privPath);
    void loadKeys(const std::string& pubPath, const std::string& privPath);

    // AES Key Wrapping
    std::vector<unsigned char> encryptAESKey(const std::vector<unsigned char>& aesKey);
    std::vector<unsigned char> decryptAESKey(const std::vector<unsigned char>& encryptedKey);
};

#endif // RSA_KEY_MANAGER_H