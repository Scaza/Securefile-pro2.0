#include "PasswordManager.h"
#include <iostream>
#include <vector>
#include <stdexcept>
#include <openssl/evp.h>
#include <openssl/rand.h>

//Constructor
PasswordManager::PasswordManager() : userPassword (""), salt() {}

//Prompt the user for a password
std::string PasswordManager::promptPassword() {
	std::cout << "Enter password: ";
	std::cin >> userPassword ;
	return userPassword;
}

// Generate a random salt
std::vector<unsigned char> PasswordManager::generateSalt(size_t length) {
	std::vector<unsigned char> salt(length);
	if (RAND_bytes(salt.data(), length) != 1) {
		throw std::runtime_error("Failed to generate random salt");
	}
	return salt;
}

std::vector<unsigned char> PasswordManager::deriveKey(const std::string& password, const std::vector<unsigned char>& salt, int iterations, int keyLength) {  
  std::vector<unsigned char> localSalt = salt; // Create a local copy of the salt  

  if (localSalt.empty()) {  
   localSalt = generateSalt(16); // Generate a random salt if not provided  
      throw std::invalid_argument("Salt cannot be empty.");  
  }  

  std::vector<unsigned char> derivedKey(keyLength);  

  // Use PBKDF2 to derive the key  
  if (PKCS5_PBKDF2_HMAC(  
      password.c_str(), password.size(),  
      localSalt.data(), localSalt.size(),  
      iterations, EVP_sha256(),  
      keyLength, derivedKey.data()) != 1) {  
      throw std::runtime_error("Error: Failed to derive key using PBKDF2.");  
  }  

  return derivedKey;  
}