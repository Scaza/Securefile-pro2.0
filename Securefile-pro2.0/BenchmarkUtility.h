#ifndef BENCHMARKUTILITY_H  
#define BENCHMARKUTILITY_H  

#include <functional>  
#include <chrono>  
#include <iostream>  

class BenchmarkUtility {
public:
    void benchMarkEncryption(const std::function<void()>& operation);
    void benchMarkDecryption(const std::function<void()>& operation);
};

#endif // BENCHMARKUTILITY_H

