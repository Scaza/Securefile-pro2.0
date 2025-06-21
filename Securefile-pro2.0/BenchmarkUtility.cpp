#include "BenchmarkUtility.h"

void BenchmarkUtility::benchMarkEncryption(const std::function<void()>& encryptionFunction) {
    auto start = std::chrono::high_resolution_clock::now();
    encryptionFunction();
    auto end = std::chrono::high_resolution_clock::now();

    std::chrono::duration<double, std::milli> duration = end - start;
    std::cout << "Encryption completed in " << duration.count() << " ms.\n";
}

void BenchmarkUtility::benchMarkDecryption(const std::function<void()>& decryptionFunction) {
    auto start = std::chrono::high_resolution_clock::now();
    decryptionFunction();
    auto end = std::chrono::high_resolution_clock::now();

    std::chrono::duration<double, std::milli> duration = end - start;
    std::cout << "Decryption completed in " << duration.count() << " ms.\n";
}





