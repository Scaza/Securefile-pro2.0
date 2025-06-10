#include "CLIHandler.h"
#include <iostream>
#include <openssl/applink.c>


int main(int argc, char* argv[]) {
	try {
		CLIHandler cli(argc, argv);

		while (true) {
			int choice = cli.displayMenuAndPrompt();
			switch (choice) {
			case 1:
				cli.handleEncryption();
				break;
			case 2:
				cli.handleDecryption();
				break;
			case 3:
				cli.handleKeyGeneration();
				break;
			case 4:
				std::cout << "Exiting the program.\n";
				return 0;
			default:
				std::cerr << "Invalid choice. Please try again.\n";

			}
		}
	}
	catch (const std::exception& ex) {
		std::cerr << "Error: " << ex.what() << "\n";
		return 1;
	}
}




