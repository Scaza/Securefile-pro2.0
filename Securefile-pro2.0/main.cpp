#include <iostream>
#include <vector>
#include <string>
#include <openssl/rand.h>

#include "CLIHandler.h"
#include "FileEncryptor.h"
#include "RSAKeyManager.h"

int main(int argc, char* argv[]) {
    CLIHandler cli(argc, argv);
    cli.parseArguments();
    return 0;
}