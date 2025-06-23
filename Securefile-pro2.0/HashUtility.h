#pragma once

// HashUtility.h
#ifndef HASH_UTILITY_H
#define HASH_UTILITY_H

#include <string>

class HashUtility {
public:
    static std::string calculateHash(const std::string& filePath);
    static bool verifyHash(const std::string& filePath, const std::string& expectedHash);
};

#endif // HASH_UTILITY_H