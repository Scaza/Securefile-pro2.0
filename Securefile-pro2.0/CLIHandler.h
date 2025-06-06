#ifndef CLIHANDLER_H
#define CLIHANDLER_H

#include <vector>
#include <string>

class CLIHandler {
private:
    std::vector<std::string> args;

public:

    //constants for commands
	static const std::string COMMAND_ENCRYPT;
	static const std::string COMMAND_DECRYPT;
    static const std::string COMMAND_GENKEYS;

    //Constructor
    CLIHandler(int argc, char* argv[]);
    
	//Destructor
	virtual ~CLIHandler() = default;

	//parse the command line arguments
     std::string parseArguments();

     //display help menu
    void displayHelp();

    //get parsed arguments
    const std::vector<std::string>& getArguments() const;

	// Validate file path
	bool validateFilePath(const std::string& filePath);

	// Save encrypted AES key to file
	void saveEncryptedAESKey(const std::vector<unsigned char>& encryptedKey, const std::string& filePath);

	// Load encrypted AES key from file
	std::vector<unsigned char> loadEncryptedAESKey(const std::string& filePath);
};

#endif

