#include "CLIHandler.h"
#include <iostream>

int main(int argc, char* argv[]) {
	try {
		CLIHandler cli(argc, argv);

		int choice = cli.promptUserForOperation();
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
		default:
			std::cerr << "Invalid choice. Please try again.\n";
			return 1;
		}
	}
	catch (const std::exception& ex) {
		std::cerr << "Error: " << ex.what() << "\n";
		return 1;
	}

	return 0;
};




