#ifndef PASSWORD_MANAGER_H
#define PASSWORD_MANAGER_H

#include <string>
#include <vector>

class PasswordManager {
public:
    std::string promptPassword();
    std::vector<unsigned char> generateSalt(size_t length = 16);
    std::vector<unsigned char> deriveKey(const std::string& password, const std::vector<unsigned char>& salt, int keyLength = 32);
};

#endif // PASSWORD_MANAGER_H

