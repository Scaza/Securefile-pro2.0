#include "CLIHandler.h"
#include <iostream>
#include <openssl/applink.c> // Required for OpenSSL on Windows

int main(int argc, char* argv[]) {
    try {
        // Initialize CLIHandler with command-line arguments
        CLIHandler cli(argc, argv);

        // Main menu loop
        while (true) {
            // Display the menu and get the user's choice
            int choice = cli.displayMenuAndPrompt();

            // Handle the user's choice
            switch (choice) {
            case 1:
                cli.handleEncryption(); // Encrypt a file
                break;
            case 2:
                cli.handleDecryption(); // Decrypt a file
                break;
            case 3:
                cli.handleKeyGeneration(); // Generate RSA keys
                break;
            case 4:
                std::cout << "Exiting the program.\n";
                return 0; // Exit the program
            default:
                std::cerr << "Invalid choice. Please try again.\n";
            }
        }
    }
    catch (const std::exception& ex) {
        // Handle any unexpected exceptions
        std::cerr << "Error: " << ex.what() << "\n";
        return 1;
    }
}