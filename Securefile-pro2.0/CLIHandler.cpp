#include "CLIHandler.h"
#include "FileEncryptor.h"
#include "RSAKeyManager.h"
#include <iostream>
#include <fstream>
#include <openssl/rand.h>

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

void CLIHandler::parseArguments() {
    if (args.empty()) {
        displayHelp();
        return;
    }

    std::string command = args[0];

    if (command == "encrypt" && args.size() == 3) {
        FileEncryptor encryptor;
        encryptor.setFilePaths(args[1], args[2]);

        RSAKeyManager rsa;
        rsa.loadKeys("public.pem", "private.pem");

        // Generate 256-bit AES key (32 bytes)
        std::vector<unsigned char> aesKey(32);
        if (!RAND_bytes(aesKey.data(), aesKey.size())) {
            std::cerr << "Error: Failed to generate AES key.\n";
            return;
        }

        encryptor.setKey(aesKey);

        std::vector<unsigned char> encryptedAESKey = rsa.encryptAESKey(aesKey);
        std::ofstream keyOut("encrypted_aes.key", std::ios::binary);
        keyOut.write(reinterpret_cast<const char*>(encryptedAESKey.data()), encryptedAESKey.size());
        keyOut.close();

        encryptor.encryptFile();

        std::cout << "File encrypted successfully.\n";
    }
    else if (command == "decrypt" && args.size() == 3) {
        FileEncryptor decryptor;
        decryptor.setFilePaths(args[1], args[2]);

        RSAKeyManager rsa;
        rsa.loadKeys("public.pem", "private.pem");

        std::ifstream keyIn("encrypted_aes.key", std::ios::binary);
        if (!keyIn) {
            std::cerr << "Error: Could not open encrypted_aes.key.\n";
            return;
        }

        std::vector<unsigned char> encryptedAESKey((std::istreambuf_iterator<char>(keyIn)), {});
        keyIn.close();

        std::vector<unsigned char> aesKey = rsa.decryptAESKey(encryptedAESKey);
        decryptor.setKey(aesKey);
        decryptor.decryptFile();

        std::cout << "File decrypted successfully.\n";
    }
    else if (command == "genkeys" && args.size() == 3) {
        RSAKeyManager rsa;
        rsa.generateKeys();
        rsa.saveKeys(args[1], args[2]);
        std::cout << "RSA keys generated and saved.\n";
    }
    else {
        displayHelp();
    }
}