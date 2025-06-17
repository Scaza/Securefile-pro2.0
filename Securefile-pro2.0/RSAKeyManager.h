#ifndef RSAKEYMANAGER_H
#define RSAKEYMANAGER_H

#include <string>
#include <vector>
#include <openssl/rsa.h>

class RSAKeyManager {
private:
    const std::string publicKeyPath = "public.pem";
    const std::string privateKeyPath = "private.pem";
    RSA* publicKey = nullptr;
    RSA* privateKey = nullptr;

public:
    RSAKeyManager();
    ~RSAKeyManager();

    void generateKeys();
    void loadKeys();
    std::vector<unsigned char> encryptAESKey(const std::vector<unsigned char>& aesKey);
    std::vector<unsigned char> decryptAESKey(const std::vector<unsigned char>& encryptedKey);
};

#endif // RSAKEYMANAGER_H