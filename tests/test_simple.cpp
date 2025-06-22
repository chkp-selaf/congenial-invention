#include <windows.h>
#include <iostream>
#include <thread>
#include <chrono>

int main() {
    OutputDebugStringW(L"[TEST_SIMPLE] Starting program\n");
    std::cout << "Test simple starting, PID: " << GetCurrentProcessId() << std::endl;
    std::cout << "This program will sleep for 5 seconds..." << std::endl;
    
    OutputDebugStringW(L"[TEST_SIMPLE] About to sleep\n");
    Sleep(5000);
    
    OutputDebugStringW(L"[TEST_SIMPLE] Woke up, exiting\n");
    std::cout << "Done!" << std::endl;
    return 0;
} 