// Benchmarking.cpp
#include "Benchmarking.h"

void Benchmarking::startTimer() {
    start = std::chrono::high_resolution_clock::now();
}

void Benchmarking::stopTimer() {
    end = std::chrono::high_resolution_clock::now();
}

double Benchmarking::getElapsedTime() const {
    return std::chrono::duration<double, std::milli>(end - start).count();
}
