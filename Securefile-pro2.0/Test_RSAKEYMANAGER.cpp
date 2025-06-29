#include <gtest/gtest.h>
#include "RSAKeyManager.h"
#include <fstream>
#include <cstdio>   // std::remove
#include <vector>

static const std::string PUB_FILE = "gtest_pub.pem";
static const std::string PRIV_FILE = "gtest_priv.pem";

class RSAKeyManagerTest : public ::testing::Test {
protected:
    void TearDown() override {
        // Cleanup generated files after each test
        std::remove(PUB_FILE.c_str());
        std::remove(PRIV_FILE.c_str());
    }
};

TEST_F(RSAKeyManagerTest, GenerateAndSaveKeys) {
    RSAKeyManager rsa(PUB_FILE, PRIV_FILE);

    // Should generate and write keys without throwing
    EXPECT_NO_THROW(rsa.generateKeys());

    // The files should now exist
    std::ifstream pubIn(PUB_FILE, std::ios::binary);
    std::ifstream privIn(PRIV_FILE, std::ios::binary);
    EXPECT_TRUE(pubIn.is_open()) << "Public key file missing";
    EXPECT_TRUE(privIn.is_open()) << "Private key file missing";
}

TEST_F(RSAKeyManagerTest, SaveKeysWithPaths) {
    RSAKeyManager rsa("other_pub.pem", "other_priv.pem");

    // Use saveKeys to generate at new paths
    EXPECT_NO_THROW(rsa.saveKeys(PUB_FILE, PRIV_FILE));

    // Check files at PUB_FILE and PRIV_FILE
    std::ifstream pubIn(PUB_FILE, std::ios::binary);
    std::ifstream privIn(PRIV_FILE, std::ios::binary);
    EXPECT_TRUE(pubIn.is_open());
    EXPECT_TRUE(privIn.is_open());
}

TEST_F(RSAKeyManagerTest, LoadKeysSuccess) {
    // First generate and save
    {
        RSAKeyManager rsa(PUB_FILE, PRIV_FILE);
        rsa.generateKeys();
    }
    // Now load from those files
    RSAKeyManager loader("dummy1", "dummy2");
    EXPECT_NO_THROW(loader.loadKeys(PUB_FILE, PRIV_FILE));
}

TEST_F(RSAKeyManagerTest, LoadNonexistentThrows) {
    RSAKeyManager rsa("no_pub.pem", "no_priv.pem");
    EXPECT_THROW(rsa.loadKeys("no_pub.pem", "no_priv.pem"), std::runtime_error);
}

TEST_F(RSAKeyManagerTest, EncryptDecryptAESKeyRoundTrip) {
    // Prepare keys
    RSAKeyManager rsa(PUB_FILE, PRIV_FILE);
    rsa.generateKeys();
    // Now load them back
    RSAKeyManager rsa2("dummy1", "dummy2");
    EXPECT_NO_THROW(rsa2.loadKeys(PUB_FILE, PRIV_FILE));

    // Create dummy AES key
    std::vector<unsigned char> key(32);
    for (size_t i = 0; i < key.size(); ++i) key[i] = static_cast<unsigned char>(i);

    // Encrypt
    std::vector<unsigned char> encrypted;
    EXPECT_NO_THROW(encrypted = rsa2.encryptAESKey(key));
    ASSERT_FALSE(encrypted.empty());

    // Decrypt
    std::vector<unsigned char> decrypted;
    EXPECT_NO_THROW(decrypted = rsa2.decryptAESKey(encrypted));
    EXPECT_EQ(decrypted, key);
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}