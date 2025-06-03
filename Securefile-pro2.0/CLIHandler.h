#ifndef CLIHANDLER_H
#define CLIHANDLER_H

#include <vector>
#include <string>

class CLIHandler {
private:
    std::vector<std::string> args;

public:
    CLIHandler(int argc, char* argv[]);
    void parseArguments();
    void displayHelp();
};

#endif
