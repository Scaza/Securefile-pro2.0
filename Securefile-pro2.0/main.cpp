#include "CLIHandler.h"
#include <iostream>
#include <string>

int main(int argc, char* argv[]) {
    CLIHandler handler(argc, argv);
    int choice;
    std::string inputFile, outputFile;

    do {
        choice = handler.displayMenuAndPrompt();
        switch (choice) {
        case 1:
            std::cout << "Enter input file path: ";
            std::cin >> inputFile;
            std::cout << "Enter output file path: ";
            std::cin >> outputFile;
            handler.handleEncryption(inputFile, outputFile);
            break;
        case 2:
            std::cout << "Enter encrypted file path: ";
            std::cin >> inputFile;
            std::cout << "Enter output (decrypted) file path: ";
            std::cin >> outputFile;
            handler.handleDecryption(inputFile, outputFile);
            break;
        case 3:
            std::cout << "Exiting program.\n";
            break;
        default:
            std::cout << "Invalid choice. Please try again.\n";
        }
    } while (choice != 3);

    return 0;
}

