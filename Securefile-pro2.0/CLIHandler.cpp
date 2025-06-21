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
    std::cout << "4. Exit\n";
    std::cout << "Enter your choice (1-4): ";
    std::cin >> choice;
    return choice;
}

void CLIHandler::handleEncryption() {
    const std::string inputFile = "sample.txt";
    const std::string outputFile = "sample.enc";

    FileEncryptor encryptor;
    // Check if the file is already encrypted
    if (encryptor.checkIfEncrypted(inputFile)) {
        std::cout << "The file is already encrypted.\n";
        return;
    }

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

    // Debug: Display encrypted AES key
    encryptor.setFilePaths(inputFile, outputFile);
    encryptor.setKey(aesKey);
    
    // Benchmark the encryption process
    BenchmarkUtility benchmarkUtility;
    benchmarkUtility.benchMarkEncryption([&]() {
        encryptor.encryptFile();
    });

    // Calculate and store the hash of the original file
    HashUtility hashUtility;
    std::string fileHash = hashUtility.calculateHash(inputFile);
    std::ofstream hashOut("file.hash", std::ios::binary);
    hashOut << fileHash;
    hashOut.close();

    std::cout << "File encrypted successfully and saved to " << outputFile << "\n";
}

void CLIHandler::handleDecryption() {
    const std::string inputFile = "sample.enc";
    const std::string outputFile = "sampledec.txt";

    FileEncryptor decryptor; // Declare decryptor only once

    // Check if the file is encrypted
    if (!decryptor.checkIfEncrypted(inputFile)) {
        std::cerr << "The file is not encrypted. Decryption cannot proceed.\n";
        return;
    } else {
        std::cout << "The file is encrypted and ready for decryption.\n";
    }

    RSAKeyManager rsa;
    try {
        rsa.loadKeys();
    } catch (const std::exception& ex) {
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

    decryptor.setFilePaths(inputFile, outputFile); // Use the same decryptor instance
    decryptor.setKey(aesKey);

    // Benchmark the decryption process
    BenchmarkUtility benchmarkUtility;
    benchmarkUtility.benchMarkDecryption([&]() {
        decryptor.decryptFile();
    });

    // Verify the hash of the decrypted file
    HashUtility hashUtility;
    std::ifstream hashIn("file.hash", std::ios::binary);
    std::string expectedHash;
    hashIn >> expectedHash;
    hashIn.close();

    std::string decryptedHash = hashUtility.calculateHash(outputFile);
    if (hashUtility.verifyHash(outputFile, expectedHash)) {
        std::cout << "File decrypted successfully and saved to " << outputFile << "\n";
        std::cout << "Hash verification successful: The decrypted file matches the original file.\n";
    } else {
        std::cerr << "Hash verification failed: The decrypted file does not match the original file.\n";
    }
}

void CLIHandler::handleKeyGeneration() {
    RSAKeyManager rsa;
    rsa.generateKeys();
    std::cout << "RSA keys generated and saved to public.pem and private.pem\n";
}

void CLIHandler::parseArguments() {
}