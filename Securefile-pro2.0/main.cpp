#include <iostream>
#include <vector>
#include <string>
#include <openssl/rand.h>
#include <stdexcept>
#include <fstream>

#include "CLIHandler.h"
#include "FileEncryptor.h"
#include "RSAKeyManager.h"

int main(int argc, char* argv[]) {
    try {
        // Step 1 : Initialize CLIHandler
		CLIHandler cli(argc, argv);

		//step 2 : Parse command line arguments
		std::string command = cli.parseArguments();
		if (command.empty()) {
			return 1; // Exit if no valid command is provided
       
    }

		// Step 3 : Handle commands
        if (command == CLIHandler :: COMMAND_ENCRYPT) {
           
            //  Encryption
			std::string inputFile = argv[2];
			std::string outputFile = argv[3];

			//validate file paths
			if (!cli.validateFilePath(inputFile)) {
				std::cerr << "Invalid input file path: " << inputFile << "\n";	
				return 1;
			}

			//RSA Key Management
			RSAKeyManager rsa;
			rsa.loadKeys("public.pem", "private.pem");

			//Generate AES key
			std::vector<unsigned char> aesKey(32); // 256-bit AES key
            if (!RAND_bytes(aesKey.data(), static_cast<int>(aesKey.size()))) {
				throw std::runtime_error("Failed to generate AES key");
			}

			//Encrypt AES Key
			std::vector<unsigned char> encryptedAESKey = rsa.encryptAESKey(aesKey);
			cli.saveEncryptedAESKey(encryptedAESKey,"encrypted_aes.key");
			
			
			// File Encryption
            FileEncryptor encryptor;
            encryptor.setFilePaths(inputFile, outputFile);
            encryptor.setKey(aesKey);
            encryptor.encryptFile();

            std::cout << "File encrypted successfully.\n";

        }
        else if (command == CLIHandler::COMMAND_DECRYPT) {
            // Decryption
            std::string inputFile = argv[2];
            std::string outputFile = argv[3];

            // Validate file paths
            if (!cli.validateFilePath(inputFile)) {
                std::cerr << "Error: Input file not found: " << inputFile << "\n";
                return 1;
            }

            // RSA Key Management
            RSAKeyManager rsa;
            rsa.loadKeys("public.pem", "private.pem");

            // Load Encrypted AES Key
            std::vector<unsigned char> encryptedAESKey = cli.loadEncryptedAESKey("encrypted_aes.key");

            // Decrypt AES Key
            std::vector<unsigned char> aesKey = rsa.decryptAESKey(encryptedAESKey);

            // File Decryption
            FileEncryptor decryptor;
            decryptor.setFilePaths(inputFile, outputFile);
            decryptor.setKey(aesKey);
            decryptor.decryptFile();

            std::cout << "File decrypted successfully.\n";

        }
        else if (command == CLIHandler::COMMAND_GENKEYS) {
            // Key Generation
            std::string publicKeyFile = argv[2];
            std::string privateKeyFile = argv[3];

            RSAKeyManager rsa;
            rsa.generateKeys();
            rsa.saveKeys(publicKeyFile, privateKeyFile);

            std::cout << "RSA keys generated and saved.\n";

        }
        else if (command == "help") {
            // Display Help
            cli.displayHelp();

        }
        else if (command == "version") {
            // Display Version
            std::cout << "Encryption Program v1.0\n";

        }
        else {
            // Invalid Command
            cli.displayHelp();
            return 1;
        }

    }
    catch (const std::exception& ex) {
        std::cerr << "Error: " << ex.what() << "\n";
        return 1;
    }

    return 0;
}




