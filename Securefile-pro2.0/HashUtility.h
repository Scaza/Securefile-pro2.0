#ifndef HASHUTILITY_H
#define HASHUTILITY_H

#include <string>

class HashUtility {
public:
    // Calculates the hash of a file and returns it as a string
    std::string calculateHash(const std::string& filePath);

    // Verifies the hash of a file against an expected hash
    bool verifyHash(const std::string& filePath, const std::string& expectedHash);
};

#endif // HASHUTILITY_H