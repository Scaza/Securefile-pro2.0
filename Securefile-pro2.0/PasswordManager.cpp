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

// Derive a cryptographic key from the user's password and randomly generated salt
std::vector<unsigned char> PasswordManager::deriveKey(const std::string& password, const std::vector<unsigned char>& salt, int iterations, int keyLength) {  
	std::vector<unsigned char> derivedKey(keyLength);// Initialize the derived key vector with the specified length


  // Use PBKDF2 to derive the key  
  if (PKCS5_PBKDF2_HMAC(  
      password.c_str(), password.size(),  
      salt.data(), salt.size(),  
      iterations, EVP_sha256(),  
      keyLength, derivedKey.data()) != 1) {  
      throw std::runtime_error("Error: Failed to derive key using PBKDF2.");  
  }  

  return derivedKey;  
}