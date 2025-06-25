#ifndef CLI_HANDLER_H
#define CLI_HANDLER_H

#include <string>
#include <vector>

class CLIHandler {
private:
    std::vector<std::string> args;

public:
    // Constructor
    CLIHandler(int argc, char* argv[]);

    // Menu display
    void displayHelp();
    int displayMenuAndPrompt();
    void displayBanner();

    // Handlers for operations
    void handleEncryption(const std::string& inputFile, const std::string& outputFile);
    void handleDecryption(const std::string& inputFile, const std::string& outputFile);
   
    // Argument parser
    void parseArguments();
};

#endif // CLI_HANDLER_H