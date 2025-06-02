#include <iostream>
#include <vector>
#include <string>
#include <openssl/rand.h>

#include "FileEncryptor.h"
#include "RSAKeyManager.h"

int main() {
    // File paths
    std::string inputFile = "sample.txt";
    std::string encryptedFile = "sample.enc";
    std::string decryptedFile = "sampledec.txt";

    // RSA Key paths
    std::string pubKeyPath = "public.pem";
    std::string privKeyPath = "private.pem";

    // Step 1: RSA Key Setup
    RSAKeyManager keyManager;
    keyManager.setKeyPaths(pubKeyPath, privKeyPath);

    // Generate keys only if not already present
    keyManager.generateKeys(); // This will overwrite existing keys

    keyManager.loadKeys();

    // Step 2: AES Key Generation
    std::vector<unsigned char> aesKey(32); // 256-bit key
    if (!RAND_bytes(aesKey.data(), aesKey.size())) {
        std::cerr << "Failed to generate AES key." << std::endl;
        return 1;
    }

    // Step 3: Encrypt AES Key with RSA Public Key
    std::vector<unsigned char> encryptedAESKey = keyManager.encryptAESKey(aesKey);

    // Step 4: Decrypt AES Key with RSA Private Key
    std::vector<unsigned char> decryptedAESKey = keyManager.decryptAESKey(encryptedAESKey);

    // Step 5: File Encryption
    FileEncryptor encryptor;
    encryptor.setKey(decryptedAESKey);
    encryptor.setFilePaths(inputFile, encryptedFile);
    encryptor.encryptFile();

    // Step 6: File Decryption
    encryptor.setFilePaths(encryptedFile, decryptedFile);
    encryptor.decryptFile();

    std::cout << "Encryption and decryption completed successfully." << std::endl;

    return 0;
}