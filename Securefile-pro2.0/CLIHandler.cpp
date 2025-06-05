#include "CLIHandler.h"
#include "FileEncryptor.h"
#include "RSAKeyManager.h"
#include <iostream>
#include <fstream>
#include <openssl/rand.h>


const std::string CLIHandler::COMMAND_ENCRYPT = "encrypt";
const std::string CLIHandler::COMMAND_DECRYPT = "decrypt";
const std::string CLIHandler::COMMAND_GENKEYS = "genkeys";




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
        << "  help\n"
        << "  version\n";

}

std::string CLIHandler::parseArguments() {
    if (args.empty()) {
        displayHelp();
        return "";
    }

    std::string command = args[0];

    if (command == COMMAND_ENCRYPT && args.size() == 3) {
        return COMMAND_ENCRYPT;
    }
    else if (command == COMMAND_DECRYPT && args.size() == 3) {
        return COMMAND_DECRYPT;
    }
    else if (command == COMMAND_GENKEYS && args.size() == 3) {
        return COMMAND_GENKEYS;
    }
    else if (command == "help") {
        displayHelp();
        return "help";
    }
    else {
        displayHelp();
        return "";
    }
}

bool CLIHandler::validateFilePath(const std::string& filePath) {
    std::ifstream file(filePath);
    return file.good();
}

void CLIHandler::saveEncryptedAESKey(const std::vector < unsigned char >& encryptedKey, const std::string& filePath) {

    std::ofstream keyOut(filePath, std::ios::binary);
    if (!keyOut) {
        throw std::runtime_error("Error: Could not open file to save encrypted AES key.");
    }
    keyOut.write(reinterpret_cast<const char*>(encryptedKey.data()), encryptedKey.size());
    }

    std::vector<unsigned char> CLIHandler::loadEncryptedAESKey(const std::string& filePath) {
        std::ifstream keyIn(filePath, std::ios::binary);
        if (!keyIn) {
            throw std::runtime_error("Error: Could not open file to load encrypted AES key.");
        }
        return std::vector<unsigned char>((std::istreambuf_iterator<char>(keyIn)), {});
    }

const std::vector<std::string>& CLIHandler::getArguments() const {
    return args;
}

