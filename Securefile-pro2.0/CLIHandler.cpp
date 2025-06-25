#include "CLIHandler.h"
#include "FileEncryptor.h"
#include "RSAKeyManager.h"
#include "PasswordManager.h"
#include "HashUtility.h"
#include "Benchmarking.h"
#include <iostream>
#include <fstream>
#include <vector>

//Colours to improve UI 
#define RESET "\033[0m"
#define CYAN "\033[36m"
#define GREEN "\033[32m"
#define RED "\033[31m"
#define YELLOW "\033[33m"
#define MAGENTA "\033[35m"
#define BOLD_WHITE "\033[1;37m"

CLIHandler::CLIHandler(int argc, char* argv[]) {
    for (int i = 1; i < argc; ++i) {
        args.emplace_back(argv[i]);
    }
}


void CLIHandler::displayHelp() {
    
    std::cout << YELLOW << "\n=== HELP MENU ===" << RESET << "\n";
    std::cout << "This program allows you to encrypt and decrypt files securely using AES and RSA hybrid encryption.\n";
    std::cout << "Menu Options:\n";
    std::cout << "1. Encrypt File: Provide the full input and output file paths to encrypt a file.\n";
    std::cout << "2. Decrypt File: Provide the full input and output file paths to decrypt a file.\n";
    std::cout << "3. Help: Display this help information.\n";
    std::cout << "4. Exit: Close the program.\n\n";

    std::cout << CYAN << "Encryption Workflow:\n" << RESET;
    std::cout << "- Enter the file path of the file you wish to encrypt.\n";
    std::cout << "- Choose a password and confirm it.\n";
    std::cout << "- The program will encrypt the file and provide timing and hash information.\n\n";

    std::cout << CYAN << "Decryption Workflow:\n" << RESET;
    std::cout << "- Enter the path of the encrypted file.\n";
    std::cout << "- Enter the same password used for encryption.\n";
    std::cout << "- The program will decrypt the file and verify its integrity.\n\n";

    std::cout << GREEN << "Tip: Ensure you do not lose your RSA keys, salts, or passwords as they are required to decrypt files.\n" << RESET;
    std::cout << YELLOW << "Press Enter to return to the main menu..." << RESET;
    
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
    std::cin.get();

    std::cout << GREEN << "\nReturning to Main Menu";
    for (int i = 0; i < 3; ++i) {
        std::cout << ".";
        std::cout.flush();
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }
    std::cout << "\n\n" << RESET;
}

int CLIHandler::displayMenuAndPrompt() {
    
    int choice;
    std::cout << CYAN;
    std::cout << "\n===========================" << std::endl;
    std::cout << "  SecureFile-Pro 2.0 Menu  " << std::endl;
    std::cout << "===========================\n" << std::endl;
    std::cout << RESET;

    std::cout << CYAN << " Main Menu:\n" << RESET;
    std::cout << GREEN << "1.Encrypt a file\n";
    std::cout << "2.Decrypt a file\n";
    std::cout << "3.Help\n" << RESET;
    std::cout << RED << "4.Exit\n" << RESET;
    std::cout << YELLOW << "Enter your choice (1-4): " <<RESET;
    std::cin >> choice;
    return choice;
}

void CLIHandler::handleEncryption(const std::string& inputFile, const std::string& outputFile) {
    
    FileEncryptor check(inputFile);
    
    RSAKeyManager rsa("public.pem", "private.pem");
    
    if (check.isEncryptedFile()) {
        std::cout << RED << "Error: This file is already encrypted.\n" << RESET;
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
        std::cerr << RED << "Error: Passwords do not match. Encryption cancelled.\n" << RESET;
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
        std::cout << RED << "\nFile is already encrypted. Returning to main menu.\n" << RESET;
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

    std::cout << GREEN << "File encrypted successfully in " << encryptionTime << " seconds.\n" << RESET;
}

void CLIHandler::handleDecryption(const std::string& inputFile, const std::string& outputFile) {
    FileEncryptor check(inputFile);
    RSAKeyManager rsa("public.pem", "private.pem");

    if (!check.isEncryptedFile()) {
        std::cout << RED << "Error: This file is already encrypted.\n" << RESET;
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
        std::cerr << RED << "Error: Could not open encrypted_aes.key.\n" <<RESET;
        return;
    }
    std::vector<unsigned char> encryptedAESKey((std::istreambuf_iterator<char>(keyIn)), {});
    keyIn.close();

    std::vector<unsigned char> aesKey = rsa.decryptAESKey(encryptedAESKey);

    std::ifstream saltIn("salt.bin", std::ios::binary);
    if (!saltIn) {
        std::cerr << RED << "Error: Could not open salt file.\n" << RESET;
        return;
    }
    std::vector<unsigned char> salt((std::istreambuf_iterator<char>(saltIn)), {});
    saltIn.close();

    PasswordManager passwordManager;
    std::string password = passwordManager.promptPassword();

    std::vector<unsigned char> derivedKey = passwordManager.deriveKey(password, salt);
    std::vector<unsigned char> decryptedKey = rsa.decryptAESKey(encryptedAESKey);

    if (derivedKey != decryptedKey) {
        std::cerr << RED << "Error: Incorrect password. Decryption cancelled.\n" << RESET;
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
        std::cout << RED << "File is not encrypted. Returning to main menu.\n" <<RESET;
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
        std::cerr << RED << "Hash file not found.\n" << RESET;
    }
    else {
        std::string expectedHash;
        std::getline(hashIn, expectedHash);
        hashIn.close();

        bool hashMatch = hashUtil.verifyHash(outputFile, expectedHash);
        if (hashMatch) {
            std::cout << MAGENTA << "\nFile decrypted successfully in " << decryptionTime << " seconds." << RESET;
            std::cout << GREEN << "\nHash verification successful.\n" << RESET;
        }
        else {
            std::cout << RED << "\nDecryption completed but hash verification failed.\n" <<RESET;
        }
    }

}

void CLIHandler::displayBanner() {
    std::cout << "\033[36m";
    std::cout << R"(
   ____                           _  __ _ _       
  / ___| ___ _ __   ___ _ __ __ _| |/ _(_) | ___  
 | |  _ / _ \ '_ \ / _ \ '__/ _` | | |_| | |/ _ \ 
 | |_| |  __/ | | |  __/ | | (_| | |  _| | |  __/ 
  \____|\___|_| |_|\___|_|  \__,_|_|_| |_|_|\___| 
                                                  
            SecureFile-Pro 2.0 - File Security
===================================================
)";
    std::cout << "\033[0m" << std::endl;
}

void CLIHandler::parseArguments() {
    std::cout << "Command-line arguments not implemented. Please use the menu system.\n";
}