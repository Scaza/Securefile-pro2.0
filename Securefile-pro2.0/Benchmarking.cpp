// Benchmarking.cpp
#include "Benchmarking.h"
#include <chrono>

void Benchmarking::start() {
    startTime = std::chrono::high_resolution_clock::now();
}

double Benchmarking::stop() {
    auto endTime = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> elapsed = endTime - startTime;
    return elapsed.count();                                        // Return the elapsed time in seconds
}

double Benchmarking::getElapsedTime() const {
    return std::chrono::duration<double>(endTime - startTime).count();
}
