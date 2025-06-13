#include "CLIHandler.h"
#include "FileEncryptor.h"
#include "RSAKeyManager.h"
#include "PasswordManager.h"
#include <iostream>
#include <fstream>

CLIHandler::CLIHandler(int argc, char* argv[]) {
    for (int i = 1; i < argc; ++i) {
        args.emplace_back(argv[i]);
    }
}

void CLIHandler::displayHelp() {
    std::cout << "Usage:\n"
        << "  encrypt <inputFile> <outputFile>\n"
        << "  decrypt <inputFile> <outputFile>\n"
        << "  genkeys <publicKeyFile> <privateKeyFile>\n"
        << "  help\n";
}

int CLIHandler::displayMenuAndPrompt() {
    int choice;
    std::cout << "Choose an operation:\n";
    std::cout << "1. Encrypt a file\n";
    std::cout << "2. Decrypt a file\n";
    std::cout << "3. Generate RSA keys\n";
    std::cout << "4. Exit\n";
    std::cout << "Enter your choice (1-4): ";
    std::cin >> choice;
    return choice;
}

void CLIHandler::handleEncryption() {
    const std::string inputFile = "sample.txt";
    const std::string outputFile = "sample.enc";

    RSAKeyManager rsa;
    try {
        rsa.loadKeys();
    }
    catch (const std::exception& ex) {
        std::cerr << ex.what() << "\n";
        std::cout << "RSA keys not found. Generating new keys...\n";
        rsa.generateKeys();
        rsa.loadKeys();
    }

    PasswordManager passwordManager;
    std::string password = passwordManager.promptPassword();
    std::vector<unsigned char> salt = passwordManager.generateSalt();
    std::vector<unsigned char> aesKey = passwordManager.deriveKey(password, salt);

    // Debug: Display salt and AES key
    std::cout << "Salt: ";
    for (unsigned char c : salt) std::cout << std::hex << (int)c;
    std::cout << "\n";

    std::ofstream saltOut("salt.bin", std::ios::binary);
    saltOut.write(reinterpret_cast<const char*>(salt.data()), salt.size());
    saltOut.close();

    std::vector<unsigned char> encryptedAESKey = rsa.encryptAESKey(aesKey);
    std::ofstream keyOut("encrypted_aes.key", std::ios::binary);
    keyOut.write(reinterpret_cast<const char*>(encryptedAESKey.data()), encryptedAESKey.size());
    keyOut.close();

    FileEncryptor encryptor;
    encryptor.setFilePaths(inputFile, outputFile);
    encryptor.setKey(aesKey);
    encryptor.encryptFile();

    std::cout << "File encrypted successfully and saved to " << outputFile << "\n";
}

void CLIHandler::handleDecryption() {
    const std::string inputFile = "sample.enc";
    const std::string outputFile = "sampledec.txt";

        RSAKeyManager rsa;
        try {
            rsa.loadKeys();
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

        FileEncryptor decryptor;
        decryptor.setFilePaths(inputFile, outputFile);
        decryptor.setKey(aesKey);
        decryptor.decryptFile();

        std::cout << "File decrypted successfully and saved to " << outputFile << "\n";
    }

    void CLIHandler::handleKeyGeneration() {
        RSAKeyManager rsa;
        rsa.generateKeys();
        std::cout << "RSA keys generated and saved to public.pem and private.pem\n";
    }

    void CLIHandler::parseArguments()
    {
    }

