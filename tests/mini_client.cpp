#include <windows.h>
#include <winhttp.h>
#include <iostream>
#include <string>

#pragma comment(lib, "winhttp.lib")

int main() {
    std::cout << "Mini client starting..." << std::endl;
    
    // Initialize WinHTTP
    HINTERNET hSession = WinHttpOpen(L"MiniClient/1.0",
                                      WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                      WINHTTP_NO_PROXY_NAME,
                                      WINHTTP_NO_PROXY_BYPASS, 0);
    
    if (!hSession) {
        std::cerr << "WinHttpOpen failed: " << GetLastError() << std::endl;
        return 1;
    }
    
    // Connect to httpbin.org
    HINTERNET hConnect = WinHttpConnect(hSession, L"httpbin.org",
                                         INTERNET_DEFAULT_HTTPS_PORT, 0);
    
    if (!hConnect) {
        std::cerr << "WinHttpConnect failed: " << GetLastError() << std::endl;
        WinHttpCloseHandle(hSession);
        return 1;
    }
    
    // Create a POST request
    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"POST", L"/post",
                                            NULL, WINHTTP_NO_REFERER,
                                            WINHTTP_DEFAULT_ACCEPT_TYPES,
                                            WINHTTP_FLAG_SECURE);
    
    if (!hRequest) {
        std::cerr << "WinHttpOpenRequest failed: " << GetLastError() << std::endl;
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return 1;
    }
    
    // Send the request with test data
    LPCWSTR headers = L"Content-Type: application/json\r\n";
    std::string data = "{\"test\": \"data from mini_client\"}";
    
    std::cout << "Sending request to https://httpbin.org/post..." << std::endl;
    
    BOOL bResults = WinHttpSendRequest(hRequest,
                                        headers, -1L,
                                        (LPVOID)data.c_str(), data.length(),
                                        data.length(), 0);
    
    if (!bResults) {
        std::cerr << "WinHttpSendRequest failed: " << GetLastError() << std::endl;
    } else {
        // Receive response
        bResults = WinHttpReceiveResponse(hRequest, NULL);
        
        if (bResults) {
            DWORD dwSize = 0;
            DWORD dwDownloaded = 0;
            LPSTR pszOutBuffer;
            
            std::cout << "Response received:" << std::endl;
            
            // Keep reading data until there is nothing left
            do {
                dwSize = 0;
                if (!WinHttpQueryDataAvailable(hRequest, &dwSize)) {
                    std::cerr << "Error in WinHttpQueryDataAvailable: " << GetLastError() << std::endl;
                }
                
                // Allocate space for the buffer
                pszOutBuffer = new char[dwSize + 1];
                if (!pszOutBuffer) {
                    std::cerr << "Out of memory" << std::endl;
                    dwSize = 0;
                } else {
                    // Read the data
                    ZeroMemory(pszOutBuffer, dwSize + 1);
                    
                    if (!WinHttpReadData(hRequest, (LPVOID)pszOutBuffer,
                                         dwSize, &dwDownloaded)) {
                        std::cerr << "Error in WinHttpReadData: " << GetLastError() << std::endl;
                    } else {
                        std::cout << pszOutBuffer;
                    }
                    
                    delete[] pszOutBuffer;
                }
            } while (dwSize > 0);
            
            std::cout << std::endl << "Request completed successfully!" << std::endl;
        }
    }
    
    // Clean up
    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    
    std::cout << "Mini client exiting..." << std::endl;
    return 0;
} 