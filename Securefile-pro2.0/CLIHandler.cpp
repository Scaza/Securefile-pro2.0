#include "CLIHandler.h"
#include "FileEncryptor.h"
#include "RSAKeyManager.h"
#include "PasswordManager.h"
#include "HashUtility.h"
#include "Benchmarking.h"
#include <iostream>
#include <fstream>
#include <vector>

CLIHandler::CLIHandler(int argc, char* argv[]) {
    for (int i = 1; i < argc; ++i) {
        args.emplace_back(argv[i]);
    }
}

void CLIHandler::displayHelp() {
    std::cout << "Usage:\n"
        << "  encrypt <inputFile> <outputFile>\n"
        << "  decrypt <inputFile> <outputFile>\n"
        << "  help\n";
}

int CLIHandler::displayMenuAndPrompt() {
    int choice;
    std::cout << "\nChoose an operation:\n";
    std::cout << "1. Encrypt a file\n";
    std::cout << "2. Decrypt a file\n";
    std::cout << "3. Exit\n";
    std::cout << "Enter your choice (1-3): ";
    std::cin >> choice;
    return choice;
}

void CLIHandler::handleEncryption(const std::string& inputFile, const std::string& outputFile) {
    FileEncryptor check(inputFile);
    RSAKeyManager rsa("public.pem", "private.pem");
    
    if (check.isEncryptedFile()) {
        std::cout << "Error: This file is already encrypted.\n";
        return;
    }
    try {
        rsa.loadKeys("public.pem", "private.pem");
    }
    catch (const std::exception& ex) {
        std::cerr << ex.what() << "\n";
        return;
    }

    PasswordManager passwordManager;
    std::string password = passwordManager.promptPassword();
    std::string confirmPassword = passwordManager.promptPasswordConfirmation();

    if (password != confirmPassword) {
        std::cerr << "Error: Passwords do not match. Encryption cancelled.\n";
        return;
    }

    std::vector<unsigned char> salt;
    try {
        salt = passwordManager.generateSalt();
    }
    catch (const std::exception& ex) {
        std::cerr << ex.what() << "\n";
        return;
    }

    std::ofstream saltOut("salt.bin", std::ios::binary);
    saltOut.write(reinterpret_cast<const char*>(salt.data()), salt.size());
    saltOut.close();

    std::vector<unsigned char> aesKey;
    try {
        aesKey = passwordManager.deriveKey(password, salt);
    }
    catch (const std::exception& ex) {
        std::cerr << ex.what() << "\n";
        return;
    }

    std::vector<unsigned char> encryptedAESKey = rsa.encryptAESKey(aesKey);
    std::ofstream keyOut("encrypted_aes.key", std::ios::binary);
    keyOut.write(reinterpret_cast<const char*>(encryptedAESKey.data()), encryptedAESKey.size());
    keyOut.close();

    FileEncryptor encryptor(inputFile, outputFile);
    if (encryptor.isEncryptedFile()) {
        std::cout << "File is already encrypted. Returning to main menu.\n";
        return;
    }

    encryptor.setKey(aesKey);

    Benchmarking benchmark;
    benchmark.start();
    encryptor.encryptFile();
    double encryptionTime = benchmark.stop();
  
    HashUtility hashUtil;
    std::string hash = hashUtil.calculateHash(inputFile);
    std::ofstream hashOut(outputFile + ".hash");
    hashOut << hash;
    hashOut.close();

    std::cout << "File encrypted successfully in " << encryptionTime << " seconds.\n";
}

void CLIHandler::handleDecryption(const std::string& inputFile, const std::string& outputFile) {
    FileEncryptor check(inputFile);
    RSAKeyManager rsa("public.pem", "private.pem");

    if (!check.isEncryptedFile()) {
        std::cout << "Error: This file is already encrypted.\n";
        return;
    }
    try {
        rsa.loadKeys("public.pem", "private.pem");
    }
    catch (const std::exception& ex) {
        std::cerr << ex.what() << "\n";
        return;
    }

    std::ifstream keyIn("encrypted_aes.key", std::ios::binary);
    if (!keyIn) {
        std::cerr << "Error: Could not open encrypted_aes.key.\n";
        return;
    }
    std::vector<unsigned char> encryptedAESKey((std::istreambuf_iterator<char>(keyIn)), {});
    keyIn.close();

    std::vector<unsigned char> aesKey = rsa.decryptAESKey(encryptedAESKey);

    std::ifstream saltIn("salt.bin", std::ios::binary);
    if (!saltIn) {
        std::cerr << "Error: Could not open salt file.\n";
        return;
    }
    std::vector<unsigned char> salt((std::istreambuf_iterator<char>(saltIn)), {});
    saltIn.close();

    PasswordManager passwordManager;
    std::string password = passwordManager.promptPassword();

    std::vector<unsigned char> derivedKey = passwordManager.deriveKey(password, salt);
    std::vector<unsigned char> decryptedKey = rsa.decryptAESKey(encryptedAESKey);

    if (derivedKey != decryptedKey) {
        std::cerr << "Error: Incorrect password. Decryption cancelled.\n";
        return;
    }
    try {
        derivedKey = passwordManager.deriveKey(password, salt);
    }
    catch (const std::exception& ex) {
        std::cerr << ex.what() << "\n";
        return;
    }

    FileEncryptor decryptor(inputFile, outputFile);
    if (!decryptor.isEncryptedFile()) {
        std::cout << "File is not encrypted. Returning to main menu.\n";
        return;
    }

    decryptor.setKey(derivedKey);

    Benchmarking benchmark;
    benchmark.start();
    decryptor.decryptFile();
    double decryptionTime = benchmark.stop();

    HashUtility hashUtil;
    std::ifstream hashIn(inputFile + ".hash");
    if (!hashIn) {
        std::cerr << "Hash file not found.\n";
    }
    else {
        std::string expectedHash;
        std::getline(hashIn, expectedHash);
        hashIn.close();

        bool hashMatch = hashUtil.verifyHash(outputFile, expectedHash);
        if (hashMatch) {
            std::cout << "File decrypted successfully in " << decryptionTime << " seconds.\nHash verification successful.\n";
        }
        else {
            std::cout << "Decryption completed but hash verification failed.\n";
        }
    }

}

void CLIHandler::parseArguments() {
    std::cout << "Command-line arguments not implemented. Please use the menu system.\n";
}