#include "CLIHandler.h"
#include "FileEncryptor.h"
#include "RSAKeyManager.h"
#include "PasswordManager.h"
#include <iostream>
#include <fstream>
#include <stdexcept>
#include <vector>
#include <string>
#include <openssl/rand.h>

// Constructor for CLIHandler
CLIHandler::CLIHandler(int argc, char* argv[]) {
    for (int i = 1; i < argc; ++i) {
        args.emplace_back(argv[i]);
    }
}

// Parse the command line arguments
std::string CLIHandler::parseArguments() {
    if (args.empty()) {
        displayHelp();
        return "";
    }
    return args[0];
}

// Display help menu
void CLIHandler::displayHelp() {
    std::cout << "Usage:\n"
        << "  encrypt <inputFile> <outputFile>\n"
        << "  decrypt <inputFile> <outputFile>\n"
        << "  genkeys <publicKeyFile> <privateKeyFile>\n"
        << "  help\n"
        << "  version\n";
}

// Display main menu and prompt user for an option
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
    std::string inputFile, outputFile;

    // Prompt user for file paths
    std::cout << "Enter the path of the file to encrypt: ";
    std::cin.ignore();
    std::getline(std::cin, inputFile);

    std::cout << "Enter the path to save the encrypted file: ";
    std::getline(std::cin, outputFile);

    // Validate input file
    std::ifstream file(inputFile);
    if (!file) {
        std::cerr << "Error: Input file not found: " << inputFile << "\n";
        return;
    }

    // RSA Key Management
    RSAKeyManager rsa;
    try {
        std::cout << "Using default RSA key paths: " << defaultPublicKeyPath << " and " << defaultPrivateKeyPath << "\n";
        rsa.loadKeys(defaultPublicKeyPath, defaultPrivateKeyPath);
    }
    catch (const std::exception& ex) {
        std::cerr << ex.what() << "\n";
        std::cout << "RSA keys not found. Would you like to generate new keys? (y/n): ";
        char choice;
        std::cin >> choice;
        if (choice == 'y' || choice == 'Y') {
            handleKeyGeneration();
            rsa.loadKeys(defaultPublicKeyPath, defaultPrivateKeyPath);
        }
        else {
            return;
        }
    }

    // Password-Based AES Key Derivation
    PasswordManager passwordManager;
    std::string password = passwordManager.promptPassword();
    std::vector<unsigned char> salt = passwordManager.generateSalt();
    std::vector<unsigned char> aesKey = passwordManager.deriveKey(password, salt);

    // Save the salt
    std::ofstream saltOut("salt.bin", std::ios::binary);
    saltOut.write(reinterpret_cast<const char*>(salt.data()), salt.size());
    saltOut.close();

    // Encrypt AES Key
    std::vector<unsigned char> encryptedAESKey = rsa.encryptAESKey(aesKey);
    std::ofstream keyOut("encrypted_aes.key", std::ios::binary);
    keyOut.write(reinterpret_cast<const char*>(encryptedAESKey.data()), encryptedAESKey.size());
    keyOut.close();

    // File Encryption
    FileEncryptor encryptor;
    encryptor.setFilePaths(inputFile, outputFile);
    encryptor.setKey(aesKey);
    encryptor.encryptFile();

    std::cout << "File encrypted successfully and saved to " << outputFile << "\n";
}

// Handle decryption
void CLIHandler::handleDecryption() {
    std::string inputFile, outputFile;

    // Prompt user for input and output file paths
    std::cout << "Enter the path of the file to decrypt: ";
    std::cin.ignore();
    std::getline(std::cin, inputFile);

    std::cout << "Enter the path to save the decrypted file: ";
    std::getline(std::cin, outputFile);

    // Validate input file
    std::ifstream file(inputFile);
    if (!file) {
        std::cerr << "Error: Input file not found: " << inputFile << "\n";
        return;
    }

    // RSA Key Management
    RSAKeyManager rsa;
    try {
        std::cout << "Using default RSA key paths: " << defaultPublicKeyPath << " and " << defaultPrivateKeyPath << "\n";
        rsa.loadKeys(defaultPublicKeyPath, defaultPrivateKeyPath);
    }
    catch (const std::exception& ex) {
        std::cerr << ex.what() << "\n";
        return;
    }

    // Load Encrypted AES Key
    std::ifstream keyIn("encrypted_aes.key", std::ios::binary);
    if (!keyIn) {
        std::cerr << "Error: Could not open encrypted AES key file.\n";
        return;
    }
    std::vector<unsigned char> encryptedAESKey((std::istreambuf_iterator<char>(keyIn)), {});
    keyIn.close();

    // Decrypt AES Key
    std::vector<unsigned char> aesKey = rsa.decryptAESKey(encryptedAESKey);

    // Load Salt
    std::ifstream saltIn("salt.bin", std::ios::binary);
    if (!saltIn) {
        std::cerr << "Error: Could not open salt file.\n";
        return;
    }
    std::vector<unsigned char> salt((std::istreambuf_iterator<char>(saltIn)), {});
    saltIn.close();

    // File Decryption
    FileEncryptor decryptor;
    decryptor.setFilePaths(inputFile, outputFile);
    decryptor.setKey(aesKey);
    decryptor.decryptFile();

    std::cout << "File decrypted successfully and saved to " << outputFile << "\n";
}

// Handle RSA key generation
void CLIHandler::handleKeyGeneration() {
    RSAKeyManager rsa;
    rsa.generateKeys();
    rsa.saveKeys(defaultPublicKeyPath, defaultPrivateKeyPath);

    std::cout << "RSA keys generated and saved to " << defaultPublicKeyPath << " and " << defaultPrivateKeyPath << "\n";
}