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
//#include "HashUtility.h"
//#include "BenchmarkUtility.h"

//constructor for CLIHandler
CLIHandler::CLIHandler(int argc, char* argv[]) {
    for (int i = 1; i < argc; ++i) {
        args.emplace_back(argv[i]);
    }
}

//Parse the command line arguments
std::string CLIHandler::parseArguments() {
    if (args.empty()) {
		displayHelp();
		return "";
    }
	return args[0];
}
//display help menu
void CLIHandler::displayHelp() {
    
    std::cout << "Usage:\n"
        << "  encrypt <inputFile> <outputFile>\n"
        << "  decrypt <inputFile> <outputFile>\n"
        << "  genkeys <publicKeyFile> <privateKeyFile>\n"
        << "  help\n"
        << "  version\n";

}

//Prompt the user for an operation
int CLIHandler::promptUserForOperation() {
	int choice;
    std::cout << "Choose an operation:\n";
	std::cout << "1. Encrypt a file\n";
	std::cout << "2. Decrypt a file\n";
	std::cout << "3. Generate RSA keys\n";
	std::cout << "Enter your choice (1-3): ";
	std::cin >> choice;
    return choice;
}

//handle encryption
void CLIHandler::handleEncryption() {
	std::string inputFile, outputFile;
	std::cout << "Enter path of the file to encrypt: ";
	std::cin.ignore();//ignore any leftover newline character in the input file
	std::getline(std::cin, inputFile); // Use getline to allow spaces in the file path
	std::cout << "Enter the path to save the encrypted file: ";
	std::getline(std::cin, outputFile); // Use getline to allow spaces in the file path

	outputFile = ensureOutputFilePath(outoutFile);

    //validate input file
    std::ifstream file(inputFile);
    if (!file) {
		std::cerr << "Error: Input file not found:" << inputFile << "\n";
		return;
    }

	std::cout << "File path read successfully: " << inputFile << "\n";
	std::cout << "Output file path read successfully: " << outputFile << "\n";


	// RSA Key Management
	RSAKeyManager rsa;
	std::string publicKeyPath, privateKeyPath;
	std::cout << "Enter path to public key file(eg public.pem): ";
	std::cin >> publicKeyPath;
	std::cout << "Enter path to private key file(eg private.pem): ";
	std::cin >> privateKeyPath;
	rsa.loadKeys(publicKeyPath, privateKeyPath);




	// Password based AES Key Derivation
	PasswordManager passwordManager;
	std::string password = passwordManager.promptPassword();

	// Generate a random salt
	std::vector<unsigned char> salt = passwordManager.generateSalt();

	// Derive AES Key from Password and Salt
	std::vector<unsigned char> aesKey = passwordManager.deriveKey(password, salt, 100000, 32); // 32 bytes for AES-256
	
	//Encrypt AES Key
	std::vector<unsigned char> encryptedAESKey = rsa.encryptAESKey(aesKey);
	std::ofstream keyOut("enccrypted_aes.key", std::ios::binary);
	keyOut.write(reinterpret_cast<const char*>(encryptedAESKey.data()), encryptedAESKey.size());
	keyOut.close();

//File Encrption
	FileEncryptor encryptor;
	encryptor.setFilePaths(inputFile, outputFile);
	encryptor.setKey(aesKey);
	encryptor.encryptFile();

	std::cout << "File encrypted successfully and saved to" << outputFile << "\n";
}


//handle decryption
void CLIHandler::handleDecryption() {
	std::string inputFile, outputFile;
	std::cout << "Enter path of the file to decrypt: ";
	std::cin >> inputFile;
	std::cout << "Enter the path to save the decrypted file: ";
	std::cin >> outputFile;
	// Validate input file
	std::ifstream file(inputFile);
	if (!file) {
		std::cerr << "Error: Input file not found: " << inputFile << "\n";
		return;
	}
	// RSA Key Management
	RSAKeyManager rsa;
	std::string publicKeyPath, privateKeyPath;
	std::cout << "Enter path to pub;lic key file (eg public.pem): ";
	std::cin >> publicKeyPath;
	std::cout << "Enter path to private key file (eg private.pem): ";
	std::cin >> privateKeyPath;
	rsa.loadKeys(publicKeyPath, privateKeyPath);

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

	// File Decryption
	FileEncryptor decryptor;
	decryptor.setFilePaths(inputFile, outputFile);
	decryptor.setKey(aesKey);
	decryptor.decryptFile();

	std::cout << "File decrypted successfully and saved to " << outputFile << "\n";
}

//handle RSA key generation
void CLIHandler::handleKeyGeneration() {
	std::string publicKeyFile, privateKeyFile;
	std::cout << "Enter path to save public key file (eg public.pem): ";
	std::cin >> publicKeyFile;
	std::cout << "Enter path to save private key file (eg private.pem): ";
	std::cin >> privateKeyFile;

	RSAKeyManager rsa;
	rsa.generateKeys();
	rsa.saveKeys(publicKeyFile, privateKeyFile);

	std::cout << "RSA keys generated and saved to " << publicKeyFile << " and " << privateKeyFile << "\n";
}
    
