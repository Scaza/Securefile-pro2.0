#ifndef RSAKEYMANAGER_H
#define RSAKEYMANAGER_H

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
    void setKeyPaths(const std::string& pub, const std::string& pri);

    void generateKeys();
    void saveKeys(); // Not implemented above, optional to add if needed
    void loadKeys();

    std::vector<unsigned char> encryptAESKey(const std::vector<unsigned char>& aesKey);
    std::vector<unsigned char> decryptAESKey(const std::vector<unsigned char>& encryptedKey);

    ~RSAKeyManager(); // Clean up allocated RSA structures
};

#endif // RSAKEYMANAGER_H