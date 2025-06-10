#ifndef CLIHANDLER_H
#define CLIHANDLER_H

#include <vector>
#include <string>

class CLIHandler {
private:
	std::vector<std::string> args; // Command-line arguments
	const std::string defaultPublicKeyPath = "C:\\Users\\shana\\Documents\\GitHub\\Securefile-pro2.0\\Securefile-pro2.0\\public.pem";
	const std::string defaultPrivateKeyPath = "C:\\Users\\shana\\Documents\\GitHub\\Securefile-pro2.0\\Securefile-pro2.0\\private.pem";
public:

	//Constructor
	CLIHandler(int argc, char* argv[]);

	//parse the command line arguments
	std::string parseArguments();

	//display help menu
	void displayHelp();

	//prompt the user for an operation
	int displayMenuAndPrompt();

	//handle encryption
	void handleEncryption();

	//handle decryption
	void handleDecryption();
    
	//handle RSA key generation
	void handleKeyGeneration();

	

};

#endif

