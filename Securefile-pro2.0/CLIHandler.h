#ifndef CLIHANDLER_H
#define CLIHANDLER_H

#include <vector>
#include <string>

class CLIHandler {
private:
	std::vector<std::string> args;

public:

	//Constructor
	CLIHandler(int argc, char* argv[]);

	//parse the command line arguments
	std::string parseArguments();

	//display help menu
	void displayHelp();

	//handle encryption
	void handleEncryption();

	//handle decryption
	void handleDecryption();

	//handle RSA key generation
	void handleKeyGeneration();

	//prompt the user for an operation
	int promptUserForOperation();

};

#endif

