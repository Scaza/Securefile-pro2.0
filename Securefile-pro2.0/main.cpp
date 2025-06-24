#include "CLIHandler.h"
#include <iostream>

int main(int argc, char* argv[]) {
    CLIHandler cli(argc, argv);

    while (true) {
        int choice = cli.displayMenuAndPrompt();

        if (choice == 1) {  // Encrypt a file
            std::string inputFile, outputFile;
            std::cout << "Enter the full path of the input file to encrypt: ";
            std::cin >> inputFile;
            std::cout << "Enter the full path for the output (encrypted) file: ";
            std::cin >> outputFile;

            cli.handleEncryption(inputFile, outputFile);
        }
        else if (choice == 2) {  // Decrypt a file
            std::string inputFile, outputFile;
            std::cout << "Enter the full path of the input file to decrypt: ";
            std::cin >> inputFile;
            std::cout << "Enter the full path for the output (decrypted) file: ";
            std::cin >> outputFile;

            cli.handleDecryption(inputFile, outputFile);
        }
        else if (choice == 3) {  // Exit
            std::cout << "Exiting program.\n";
            break;
        }
        else {
            std::cout << "Invalid option. Please try again.\n";
        }
    }

    return 0;
}