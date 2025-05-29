#include "FileEncryptor.h"
#include "RSAKeyManager.h"
#include <iostream>
#include <fstream>
#include <random>
#include <openssl\applink.c>

// Helper: Generate 256-bit AES key
std::vector<unsigned char> generateAESKey() {
    std::vector<unsigned char> key(32); // 256 bits
    std::random_device rd;
    std::generate(key.begin(), key.end(), [&rd]() { return rd(); });
    return key;
}

int main() {
    
    const std::string pubKeyPath = "public.pem";
    const std::string privKeyPath = "private.pem";
    const std::string inputFilePath = "input.txt";
    const std::string encryptedFilePath = "encrypted.bin";
    const std::string decryptedFilePath = "decrypted.txt";
    const std::string encryptedKeyFile = "encrypted_key.bin";

    try {
        // Step 1: Setup RSA key manager
        RSAKeyManager keyManager(pubKeyPath, privKeyPath);
        keyManager.generateKeys();
        keyManager.saveKeys();

        // Step 2: Generate AES key
        auto aesKey = generateAESKey();

        // Step 3: Encrypt AES key using RSA and save it
        auto encryptedAESKey = keyManager.encryptAESKey(aesKey);
        std::ofstream keyOut(encryptedKeyFile, std::ios::binary);
        keyOut.write(reinterpret_cast<const char*>(encryptedAESKey.data()), encryptedAESKey.size());
        keyOut.close();

        // Step 4: Encrypt file using AES key
        FileEncryptor encryptor(inputFilePath, encryptedFilePath);
        encryptor.setKey(aesKey);
        encryptor.encryptFile();

        // Step 5: Decrypt AES key using RSA
        std::ifstream keyIn(encryptedKeyFile, std::ios::binary);
        std::vector<unsigned char> encryptedKeyData((std::istreambuf_iterator<char>(keyIn)),
            std::istreambuf_iterator<char>());
        keyIn.close();

        auto decryptedAESKey = keyManager.decryptAESKey(encryptedKeyData);

        // Step 6: Decrypt file using decrypted AES key
        FileEncryptor decryptor(encryptedFilePath, decryptedFilePath);
        decryptor.setKey(decryptedAESKey);
        decryptor.decryptFile();

        std::cout << "Encryption and decryption successful.\n";

    }
    catch (const std::exception& ex) {
        std::cerr << "Error: " << ex.what() << "\n";
        return 1;
    }

    return 0;
}