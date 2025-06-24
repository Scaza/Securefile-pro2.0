#pragma once
// Benchmarking.h
#ifndef BENCHMARKING_H
#define BENCHMARKING_H

#include <chrono>
#include <string>

class Benchmarking {
private:
    std::chrono::high_resolution_clock::time_point startTime;
    std::chrono::high_resolution_clock::time_point endTime;

public:
    void start();
    double stop();
    double getElapsedTime() const; // in milliseconds
};

#endif // BENCHMARKING_H