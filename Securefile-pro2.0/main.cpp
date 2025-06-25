#include "CLIHandler.h"
#include <iostream>


#define CYAN "\033[36m"
#define RESET "\033[0m"
#define RED "\033[31m"

int main(int argc, char* argv[]) {
    
    CLIHandler cli(argc, argv);
    cli.displayBanner();

    while (true) {
        
        int choice = cli.displayMenuAndPrompt();

        if (choice == 1) {  // Encrypt a file
            std::string inputFile, outputFile;
            std::cout << CYAN << "Enter the full path of the input file to encrypt: " << RESET;
            std::cin >> inputFile;

            std::cout << CYAN << "Enter the full path for the output (encrypted) file: " << RESET;
            std::cin >> outputFile;

            cli.handleEncryption(inputFile, outputFile);
        }
        else if (choice == 2) {  // Decrypt a file
            std::string inputFile, outputFile;
            std::cout << CYAN << "Enter the full path of the input file to decrypt: " << RESET;
            std::cin >> inputFile;
            std::cout << CYAN << "Enter the full path for the output (decrypted) file: " << RESET;
            std::cin >> outputFile;

            cli.handleDecryption(inputFile, outputFile);
        }
        else if (choice == 3) {  // Exit
            cli.displayHelp();
            break;
        }
        else if (choice == 4) {
            std::cout << CYAN << "Exiting program.\n" << RESET;
            break;
        }
        else {
            std::cout << RED << "\nInvalid option. Please try again.\n"<< RESET;
        }
    }

    return 0;
}