#pragma once
// Benchmarking.h
#ifndef BENCHMARKING_H
#define BENCHMARKING_H

#include <chrono>
#include <string>

class Benchmarking {
private:
    std::chrono::high_resolution_clock::time_point start;
    std::chrono::high_resolution_clock::time_point end;

public:
    void startTimer();
    void stopTimer();
    double getElapsedTime() const; // in milliseconds
};

#endif // BENCHMARKING_H