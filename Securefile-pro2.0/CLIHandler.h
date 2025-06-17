#ifndef CLIHANDLER_H
#define CLIHANDLER_H

#include <string>
#include <vector>

class CLIHandler {
private:
    std::vector<std::string> args; // Command-line arguments

public:
    CLIHandler(int argc, char* argv[]); // Constructor
    void displayHelp();
    int displayMenuAndPrompt();
    void handleEncryption();
    void handleDecryption();
    void handleKeyGeneration();
    void parseArguments();
};

#endif // CLIHANDLER_H