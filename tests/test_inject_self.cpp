#include <windows.h>
#include <winhttp.h>
#include <iostream>
#include <filesystem>
#include <fstream>
#include <ctime>

#pragma comment(lib, "winhttp.lib")

void TestWinHttpRequest() {
    HINTERNET hSession = WinHttpOpen(L"TestInjectSelf/1.0", 
                                      WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                      WINHTTP_NO_PROXY_NAME, 
                                      WINHTTP_NO_PROXY_BYPASS, 0);
    
    if (!hSession) {
        std::cerr << "WinHttpOpen failed: " << GetLastError() << std::endl;
        return;
    }
    
    HINTERNET hConnect = WinHttpConnect(hSession, L"httpbin.org",
                                        INTERNET_DEFAULT_HTTPS_PORT, 0);
    
    if (!hConnect) {
        std::cerr << "WinHttpConnect failed: " << GetLastError() << std::endl;
        WinHttpCloseHandle(hSession);
        return;
    }
    
    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET", L"/get",
                                            NULL, WINHTTP_NO_REFERER,
                                            WINHTTP_DEFAULT_ACCEPT_TYPES,
                                            WINHTTP_FLAG_SECURE);
    
    if (!hRequest) {
        std::cerr << "WinHttpOpenRequest failed: " << GetLastError() << std::endl;
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return;
    }
    
    BOOL bResults = WinHttpSendRequest(hRequest,
                                       WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                                       WINHTTP_NO_REQUEST_DATA, 0,
                                       0, 0);
    
    if (bResults) {
        bResults = WinHttpReceiveResponse(hRequest, NULL);
    }
    
    if (bResults) {
        std::cout << "WinHTTP request completed successfully!" << std::endl;
        
        // Read response
        DWORD dwSize = 0;
        DWORD dwDownloaded = 0;
        LPSTR pszOutBuffer;
        
        do {
            dwSize = 0;
            if (!WinHttpQueryDataAvailable(hRequest, &dwSize)) {
                std::cerr << "Error in WinHttpQueryDataAvailable: " << GetLastError() << std::endl;
            }
            
            pszOutBuffer = new char[dwSize+1];
            if (!pszOutBuffer) {
                std::cerr << "Out of memory" << std::endl;
                dwSize = 0;
            } else {
                ZeroMemory(pszOutBuffer, dwSize+1);
                
                if (!WinHttpReadData(hRequest, (LPVOID)pszOutBuffer, dwSize, &dwDownloaded)) {
                    std::cerr << "Error in WinHttpReadData: " << GetLastError() << std::endl;
                } else {
                    std::cout << "Response chunk: " << pszOutBuffer << std::endl;
                }
                
                delete [] pszOutBuffer;
            }
        } while (dwSize > 0);
    } else {
        std::cerr << "WinHttpSendRequest/ReceiveResponse failed: " << GetLastError() << std::endl;
    }
    
    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
}

int main() {
    std::cout << "Test program starting, PID: " << GetCurrentProcessId() << std::endl;
    
    // Create a marker file to show we started
    std::ofstream marker("test_inject_self_started.txt");
    marker << "Started at " << std::time(nullptr) << std::endl;
    marker.close();
    
    // Load the hook DLL
    HMODULE hDll = LoadLibraryW(L"..\\..\\dll\\Release\\ai_hook.dll");
    
    if (hDll) {
        std::cout << "DLL loaded successfully at: 0x" << std::hex << hDll << std::dec << std::endl;
        
        // Give the DLL time to initialize and connect to pipe
        std::cout << "Waiting for DLL to initialize..." << std::endl;
        Sleep(2000);
        
        // Make a WinHTTP request to test if hooks are working
        std::cout << "Making WinHTTP request..." << std::endl;
        TestWinHttpRequest();
        
        // Keep the process alive for a bit
        std::cout << "Keeping process alive for 5 seconds..." << std::endl;
        Sleep(5000);
        
        FreeLibrary(hDll);
        std::cout << "DLL unloaded" << std::endl;
    } else {
        DWORD error = GetLastError();
        std::cerr << "Failed to load DLL, error: " << error << std::endl;
        return 1;
    }
    
    std::cout << "Test program exiting normally" << std::endl;
    return 0;
} 