#ifndef PASSWORDMANAGER_H  
#define PASSWORDMANAGER_H  

#include <string>  
#include <vector>  

class PasswordManager
{
private:
	std::string userPassword;// stores the user's password
	std::vector<unsigned char> salt; // stores the salt for password hashing

public:
	// Constructor
	PasswordManager();

	// Prompts the user for a password
	std::string promptPassword();

	//Derive a cryptographic key from the user's password
	std::vector<unsigned char> deriveKey(const std::string& password, const std::vector<unsigned char>& salt, int iterations = 100000, int keyLength = 32);

	// Generate a random salt
	std::vector<unsigned char> generateSalt(size_t length = 16);

};  

#endif // PASSWORDMANAGER_H
