#include <windows.h>
#include <iostream>
#include <filesystem>
#include <detours.h>

int main() {
    std::cout << "Testing ARM64 DLL injection..." << std::endl;
    
    // Test 1: Can we load Detours?
    std::cout << "Detours version: " << DETOURS_VERSION << std::endl;
    
    // Test 2: Create a simple suspended process
    STARTUPINFOW si{sizeof(si)};
    PROCESS_INFORMATION pi{};
    
    if (!CreateProcessW(L"C:\\Windows\\System32\\notepad.exe", nullptr, nullptr, nullptr,
                        FALSE, CREATE_SUSPENDED, nullptr, nullptr, &si, &pi)) {
        std::cerr << "Failed to create process: " << GetLastError() << std::endl;
        return 1;
    }
    
    std::cout << "Created process with PID: " << pi.dwProcessId << std::endl;
    
    // Test 3: Try to inject our minimal DLL
    std::filesystem::path dllPath = std::filesystem::current_path() / "dll" / "Release" / "minimal_test.dll";
    if (!std::filesystem::exists(dllPath)) {
        // Try build directory
        dllPath = std::filesystem::path(__FILE__).parent_path().parent_path() / "build_vs_arm64" / "dll" / "Release" / "minimal_test.dll";
    }
    
    std::cout << "Looking for DLL at: " << dllPath << std::endl;
    std::cout << "DLL exists: " << std::filesystem::exists(dllPath) << std::endl;
    
    if (std::filesystem::exists(dllPath)) {
        std::string dllPathStr = dllPath.string();
        const char* dlls[] = { dllPathStr.c_str() };
        
        SetLastError(0);
        BOOL result = DetourUpdateProcessWithDll(pi.hProcess, dlls, 1);
        DWORD error = GetLastError();
        
        std::cout << "DetourUpdateProcessWithDll result: " << result << std::endl;
        std::cout << "Error code: " << error << std::endl;
        
        if (result) {
            std::cout << "Injection prepared, resuming process..." << std::endl;
            ResumeThread(pi.hThread);
            
            // Wait a bit to see if process crashes
            Sleep(1000);
            
            DWORD exitCode = STILL_ACTIVE;
            GetExitCodeProcess(pi.hProcess, &exitCode);
            
            if (exitCode == STILL_ACTIVE) {
                std::cout << "Process is still running - injection successful!" << std::endl;
            } else {
                std::cout << "Process exited with code: 0x" << std::hex << exitCode << std::endl;
            }
        }
    } else {
        std::cerr << "Could not find minimal_test.dll" << std::endl;
    }
    
    // Clean up
    TerminateProcess(pi.hProcess, 0);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    
    return 0;
} 