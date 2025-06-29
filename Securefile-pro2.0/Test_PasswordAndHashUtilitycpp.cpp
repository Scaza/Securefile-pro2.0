#include <gtest/gtest.h>
#include "PasswordManager.h"
#include "HashUtility.h"

#include <fstream>
#include <cstdio>
#include <vector>

// Helper: write content to file
static void writeFile(const std::string& path, const std::string& content) {
    std::ofstream out(path, std::ios::binary);
    ASSERT_TRUE(out.is_open()) << "Failed to create file: " << path;
    out << content;
    out.close();
}

// Helper: append a byte to a file
static void appendByte(const std::string& path, char c) {
    std::ofstream out(path, std::ios::binary | std::ios::app);
    ASSERT_TRUE(out.is_open()) << "Failed to open file: " << path;
    out.put(c);
    out.close();
}

TEST(PasswordManager, GenerateSaltLengthAndRandomness) {
    PasswordManager pm;
    // Generate two salts of same length
    const size_t len = 16;
    std::vector<unsigned char> salt1 = pm.generateSalt(len);
    std::vector<unsigned char> salt2 = pm.generateSalt(len);

    // Correct length
    EXPECT_EQ(salt1.size(), len);
    EXPECT_EQ(salt2.size(), len);

    // Very likely different
    EXPECT_NE(salt1, salt2);
}

TEST(PasswordManager, DeriveKeyRepeatability) {
    PasswordManager pm;
    std::string password = "correct horse battery staple";
    std::vector<unsigned char> salt = pm.generateSalt(16);
    int keyLength = 32;

    // Derive twice with same salt and password
    std::vector<unsigned char> key1 = pm.deriveKey(password, salt, keyLength);
    std::vector<unsigned char> key2 = pm.deriveKey(password, salt, keyLength);

    EXPECT_EQ(key1.size(), keyLength);
    EXPECT_EQ(key2.size(), keyLength);
    EXPECT_EQ(key1, key2);
}

TEST(PasswordManager, DeriveKeyDifferentSaltProducesDifferentKey) {
    PasswordManager pm;
    std::string password = "p@ssw0rd";
    std::vector<unsigned char> salt1 = pm.generateSalt(16);
    std::vector<unsigned char> salt2 = pm.generateSalt(16);
    int keyLength = 32;

    std::vector<unsigned char> key1 = pm.deriveKey(password, salt1, keyLength);
    std::vector<unsigned char> key2 = pm.deriveKey(password, salt2, keyLength);

    // Same password, different salt -> very likely different key
    EXPECT_EQ(key1.size(), keyLength);
    EXPECT_EQ(key2.size(), keyLength);
    EXPECT_NE(key1, key2);
}

TEST(PasswordManager, DeriveKeyInvalidParamsThrows) {
    PasswordManager pm;
    std::string password = "foo";
    std::vector<unsigned char> salt; // empty salt
    int keyLength = 32;

    // Should throw due to invalid salt length
    EXPECT_THROW(pm.deriveKey(password, salt, keyLength), std::runtime_error);
}

TEST(HashUtility, CalculateAndVerifyHash) {
    const std::string file = "hash_test.bin";
    // Write initial content
    writeFile(file, "data1234");

    // Calculate hash
    std::string hash1 = HashUtility::calculateHash(file);
    ASSERT_FALSE(hash1.empty());

    // Verify correct hash
    EXPECT_TRUE(HashUtility::verifyHash(file, hash1));

    // Modify file
    appendByte(file, 'X');

    // Hash should change
    std::string hash2 = HashUtility::calculateHash(file);
    EXPECT_NE(hash1, hash2);

    // Verification should fail with old hash
    EXPECT_FALSE(HashUtility::verifyHash(file, hash1));

    // Clean up
    std::remove(file.c_str());
}
/*
int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
*/