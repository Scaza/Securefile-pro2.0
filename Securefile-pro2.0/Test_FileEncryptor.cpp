// test_FileEncryptor.cpp

#include <gtest/gtest.h>
#include "FileEncryptor.h"
#include <fstream>
#include <cstdio>

// Helper: write a test file with content padded to AES block size (16 bytes)
static void writeTestFile(const std::string& path, const std::string& content) {
    std::ofstream out(path, std::ios::binary);
    ASSERT_TRUE(out.is_open()) << "Failed to create test file: " << path;
    out << content;
    out.close();
}

// Helper: read entire file to string
static std::string readAll(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in.is_open()) {
        ADD_FAILURE() << "Failed to open file: " << path;
        return std::string();
    }
    std::ostringstream ss;
    ss << in.rdbuf();
    return ss.str();
}

TEST(FileEncryptor, RoundTripEncryptionDecryption) {
    const std::string original = "test_orig.dat";
    const std::string encrypted = "test_orig.dat.enc";
    const std::string decrypted = "test_orig.dat.dec";

    // Prepare content length multiple of AES_BLOCK_SIZE (16)
    std::string content(64, 'A');
    writeTestFile(original, content);

    // Prepare dummy 32-byte key
    std::vector<unsigned char> key(32, 0x01);

    FileEncryptor enc;
    enc.setFilePaths(original, encrypted);
    enc.setKey(key);

    // Initially not encrypted
    EXPECT_FALSE(enc.isEncryptedFile());

    // Perform encryption (should add signature)
    enc.encryptFile();
    EXPECT_TRUE(enc.isEncryptedFile()) << "Encrypted file signature not found";

    // Check encrypted file prefix
    std::string dataEnc = readAll(encrypted);
    ASSERT_GE(dataEnc.size(), 11u);
    EXPECT_EQ(dataEnc.substr(0, 11), std::string("ENCRYPTED::"));

    FileEncryptor dec;
    dec.setFilePaths(encrypted, decrypted);
    dec.setKey(key);

    // Perform decryption
    dec.decryptFile();
    EXPECT_FALSE(dec.isEncryptedFile()) << "Decrypted file still appears encrypted";

    // Verify content matches original
    std::string dataDec = readAll(decrypted);
    EXPECT_EQ(dataDec, content);

    // Cleanup
    std::remove(original.c_str());
    std::remove(encrypted.c_str());
    std::remove(decrypted.c_str());
}

/*

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
*/