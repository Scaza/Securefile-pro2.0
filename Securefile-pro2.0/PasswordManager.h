#ifndef PASSWORDMANAGER_H
#define PASSWORDMANAGER_H

#include <string>
#include <vector>

class PasswordManager {
private:
    std::string userPassword;
    std::vector<unsigned char> salt;
    
public:
    PasswordManager();
    std::string promptPassword();
    std::vector<unsigned char> generateSalt(size_t length = 16);
    std::vector<unsigned char> deriveKey(const std::string& password, const std::vector<unsigned char>& salt, int iterations = 10000, int keyLength = 32);
};

#endif // PASSWORDMANAGER_H