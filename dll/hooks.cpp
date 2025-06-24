#include "hooks.h"
#include "pipe_client.h"
#include "pattern_scan.h"
#include "openssl_types.h"
#include "logging.h"  // Add new logging header
#include <windows.h>
#include <winhttp.h>
#include <detours.h>
#include <string>
#include <vector>
#include <algorithm>
#include <set>  // For std::set
#include <chrono>  // For timestamp
#define SECURITY_WIN32
#include <sspi.h>
#include <schannel.h>
#include <sstream>      // For wstringstream
#include <iomanip>      // For std::hex
#include <cstdlib>      // For getenv
#include <cstring>      // For strcmp
#include <fstream>      // For config file reading
#include "json.h" // For parsing JSON from preload.js

#pragma comment(lib, "secur32.lib")

// Define missing constants
#ifndef SCH_CRED_ALPN_ENABLED
#define SCH_CRED_ALPN_ENABLED 0x00000010
#endif

#ifndef SCHANNEL_CRED_VERSION_APPLICATION_PROTOCOLS
#define SCHANNEL_CRED_VERSION_APPLICATION_PROTOCOLS 5
#endif

// Define missing WinHTTP constants
#ifndef WINHTTP_QUERY_URL
#define WINHTTP_QUERY_URL 38
#endif

// For PostMessage from preload.js
static decltype(&PostMessageW) Real_PostMessageW = PostMessageW;

// --- Function Pointers ---
// WinHTTP
static decltype(&WinHttpSendRequest) Real_WinHttpSendRequest = WinHttpSendRequest;
static decltype(&WinHttpReadData) Real_WinHttpReadData = WinHttpReadData;
static decltype(&WinHttpWebSocketSend) Real_WinHttpWebSocketSend = WinHttpWebSocketSend;
static decltype(&WinHttpWebSocketReceive) Real_WinHttpWebSocketReceive = WinHttpWebSocketReceive;
static decltype(&LoadLibraryW) Real_LoadLibraryW = LoadLibraryW;

// OpenSSL/BoringSSL
static SSL_write_t Real_SSL_write = nullptr;
static SSL_read_t Real_SSL_read = nullptr;
static SSL_get_servername_t Real_SSL_get_servername = nullptr;
static SSL_CTX_set_keylog_callback_t Real_SSL_CTX_set_keylog_callback = nullptr;
static SSL_new_t Real_SSL_new = nullptr;

static std::set<SSL_CTX*> g_processed_ssl_contexts; // To track SSL_CTX for keylog callback

// Schannel
static decltype(&EncryptMessage) Real_EncryptMessage = EncryptMessage;
static decltype(&DecryptMessage) Real_DecryptMessage = DecryptMessage;
static decltype(&AcquireCredentialsHandleW) Real_AcquireCredentialsHandleW = AcquireCredentialsHandleW;

// --- ETW Globals & Functions ---
static REGHANDLE g_etwRegHandle = 0;

static bool g_sslHooksInstalled = false; // before any function definitions

void EtwRegister() {
    EventRegister(&AiTraceProviderId, NULL, NULL, &g_etwRegHandle);
}

void EtwUnregister() {
    if (g_etwRegHandle != 0) {
        EventUnregister(g_etwRegHandle);
        g_etwRegHandle = 0;
    }
}

void EtwTraceMessage(PCWSTR message) {
    if (g_etwRegHandle == 0 || message == nullptr) return;

    EVENT_DESCRIPTOR desc;
    EventDescCreate(&desc, 1, 0, 0, 4, 0, 0, 0); // Informational level, generic event

    EVENT_DATA_DESCRIPTOR data;
    EventDataDescCreate(&data, message, (ULONG)((wcslen(message) + 1) * sizeof(wchar_t)));

    EventWrite(g_etwRegHandle, &desc, 1, &data);
}

// --- Schannel AcquireCredentialsHandle Detour ---
SECURITY_STATUS SEC_ENTRY Mine_AcquireCredentialsHandleW(
    LPWSTR pszPrincipal,    // Name of principal
    LPWSTR pszPackage,      // Name of package
    ULONG fCredentialUse,   // Flags indicating use
    PLUID pvLogonId,        // Pointer to logon ID
    PVOID pAuthData,        // Package specific data
    PVOID pGetKeyFn,        // Pointer to GetKey function
    PVOID pvGetKeyArgument, // Value to pass to GetKey
    PCredHandle phCredential, // (out) Cred Handle
    PTimeStamp ptsExpiry      // (out) Lifetime of cred
) {
    // Ensure 16-byte stack alignment for WoA compatibility
    volatile int dummy[4] = {0};
    (void)dummy; // Prevent optimization
    SECURITY_STATUS status = Real_AcquireCredentialsHandleW(
        pszPrincipal, pszPackage, fCredentialUse, pvLogonId, pAuthData,
        (SEC_GET_KEY_FN)pGetKeyFn, pvGetKeyArgument, phCredential, ptsExpiry
    );

    if (status == SEC_E_OK && pAuthData && pszPackage && wcscmp(pszPackage, UNISP_NAME_W) == 0) {
        PSCHANNEL_CRED pSchannelCred = static_cast<PSCHANNEL_CRED>(pAuthData);
        std::wstringstream ss;
        ss << L"grbitEnabledProtocols: 0x" << std::hex << pSchannelCred->grbitEnabledProtocols;
        ss << L", dwFlags: 0x" << std::hex << pSchannelCred->dwFlags;

        // Check for ALPN data - simplified version without accessing unsupported fields
        if (pSchannelCred->dwFlags & SCH_CRED_ALPN_ENABLED) {
            ss << L", ALPNs: (ALPN enabled but parsing not supported in this Windows SDK version)";
        }

        std::wstring credHandleStr = L"SchannelCred_" + 
                                     std::to_wstring(phCredential->dwLower) + L"_" + 
                                     std::to_wstring(phCredential->dwUpper);
        
        std::wstring dataStr = ss.str();
        CreateAndSendEvent(ApiType::SchannelAcquireCred, credHandleStr, dataStr.c_str(), dataStr.length() * sizeof(wchar_t));
    }

    return status;
}


// --- Event Creation Helper ---
void CreateAndSendEvent(ApiType apiType, const std::wstring& url, const void* data, DWORD dataLength) {
    CapturedEvent event;
    event.timestamp = std::chrono::system_clock::now();
    event.processId = GetCurrentProcessId();
    event.threadId = GetCurrentThreadId();
    event.apiType = apiType;
    event.url = url;

    if (data && dataLength > 0) {
        const auto* pData = static_cast<const unsigned char*>(data);
        event.data.assign(pData, pData + dataLength);
    }

    PipeSendEvent(event);
}

// --- WinHTTP Detours ---
BOOL WINAPI Mine_WinHttpSendRequest(HINTERNET hRequest, LPCWSTR h, DWORD hl, LPVOID o, DWORD ol, DWORD tl, DWORD_PTR c) {
    LOG_TRACE_F(L"WinHTTP", L"WinHttpSendRequest called - hRequest: 0x%p, dataLength: %d", hRequest, ol);
    
    // Preserve context value for WoA compatibility
    DWORD_PTR originalContext = 0;
    DWORD contextSize = sizeof(DWORD_PTR);
    WinHttpQueryOption(hRequest, WINHTTP_OPTION_CONTEXT_VALUE, &originalContext, &contextSize);
    
    try {
        // Always try to capture data if present
        if (o && ol > 0) {
            // Try to get URL - but don't fail if we can't
            std::wstring url = L"<unknown>";
            DWORD dwUrlLength = 0;
            
            // Try WINHTTP_QUERY_URI first
            if (WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_URI, WINHTTP_HEADER_NAME_BY_INDEX, NULL, &dwUrlLength, WINHTTP_NO_HEADER_INDEX) || 
                GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
                std::vector<wchar_t> urlBuffer(dwUrlLength / sizeof(wchar_t) + 1);
                if (WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_URI, WINHTTP_HEADER_NAME_BY_INDEX, urlBuffer.data(), &dwUrlLength, WINHTTP_NO_HEADER_INDEX)) {
                    url = std::wstring(urlBuffer.data());
                    LOG_DEBUG_F(L"WinHTTP", L"Got URI: %s", url.c_str());
                }
            }
            
            // If that didn't work, try to get the Host header
            if (url == L"<unknown>") {
                DWORD hostLength = 0;
                if (WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_HOST, WINHTTP_HEADER_NAME_BY_INDEX, NULL, &hostLength, WINHTTP_NO_HEADER_INDEX) || 
                    GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
                    std::vector<wchar_t> hostBuffer(hostLength / sizeof(wchar_t) + 1);
                    if (WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_HOST, WINHTTP_HEADER_NAME_BY_INDEX, hostBuffer.data(), &hostLength, WINHTTP_NO_HEADER_INDEX)) {
                        url = L"https://" + std::wstring(hostBuffer.data());
                        LOG_DEBUG_F(L"WinHTTP", L"Got Host: %s", hostBuffer.data());
                    }
                }
            }
            
            LOG_INFO_F(L"WinHTTP", L"Intercepted WinHttpSendRequest - URL: %s, Size: %d bytes", url.c_str(), ol);
            LOG_DATA(LogLevel::DEBUG, L"WinHTTP", L"Request data", o, ol);
            
            CreateAndSendEvent(ApiType::WinHttpSend, url, o, ol);
        } else {
            LOG_TRACE(L"WinHTTP", L"WinHttpSendRequest called with no data");
            
            // Even without data, we might want to capture the request
            std::wstring url = L"<no-data>";
            CreateAndSendEvent(ApiType::WinHttpSend, url, nullptr, 0);
        }
    } catch (...) {
        LOG_ERROR(L"WinHTTP", L"Unhandled exception in Mine_WinHttpSendRequest");
        EtwTraceMessage(L"Unhandled exception in Mine_WinHttpSendRequest. Passing through.");
    }
    return Real_WinHttpSendRequest(hRequest, h, hl, o, ol, tl, c);
}

BOOL WINAPI Mine_WinHttpReadData(HINTERNET hRequest, LPVOID b, DWORD br, LPDWORD brr) {
    LOG_TRACE_F(L"WinHTTP", L"WinHttpReadData called - hRequest: 0x%p, bufferSize: %d", hRequest, br);
    
    BOOL result = Real_WinHttpReadData(hRequest, b, br, brr);
    try {
        if (result && brr && *brr > 0) {
            std::wstring url = L"<unknown>";
            DWORD dwUrlLength = 0;
            
            // Try WINHTTP_QUERY_URI first
            if (WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_URI, WINHTTP_HEADER_NAME_BY_INDEX, NULL, &dwUrlLength, WINHTTP_NO_HEADER_INDEX) || 
                GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
                std::vector<wchar_t> urlBuffer(dwUrlLength / sizeof(wchar_t) + 1);
                if (WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_URI, WINHTTP_HEADER_NAME_BY_INDEX, urlBuffer.data(), &dwUrlLength, WINHTTP_NO_HEADER_INDEX)) {
                    url = std::wstring(urlBuffer.data());
                }
            }
            
            // If that didn't work, try to get the Host header
            if (url == L"<unknown>") {
                DWORD hostLength = 0;
                if (WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_HOST, WINHTTP_HEADER_NAME_BY_INDEX, NULL, &hostLength, WINHTTP_NO_HEADER_INDEX) || 
                    GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
                    std::vector<wchar_t> hostBuffer(hostLength / sizeof(wchar_t) + 1);
                    if (WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_HOST, WINHTTP_HEADER_NAME_BY_INDEX, hostBuffer.data(), &hostLength, WINHTTP_NO_HEADER_INDEX)) {
                        url = L"https://" + std::wstring(hostBuffer.data());
                    }
                }
            }
            
            LOG_INFO_F(L"WinHTTP", L"Intercepted WinHttpReadData - URL: %s, Read: %d bytes", url.c_str(), *brr);
            LOG_DATA(LogLevel::DEBUG, L"WinHTTP", L"Response data", b, *brr);
            
            CreateAndSendEvent(ApiType::WinHttpRead, url, b, *brr);
        } else if (!result) {
            LOG_DEBUG_F(L"WinHTTP", L"WinHttpReadData failed or returned no data (result: %d)", result);
        }
    } catch (...) {
        LOG_ERROR(L"WinHTTP", L"Unhandled exception in Mine_WinHttpReadData");
        EtwTraceMessage(L"Unhandled exception in Mine_WinHttpReadData. Passing through.");
    }
    return result;
}

DWORD WINAPI Mine_WinHttpWebSocketSend(HINTERNET h, WINHTTP_WEB_SOCKET_BUFFER_TYPE t, PVOID b, DWORD l) {
    try {
        if (b && l > 0) {
            // URL is not readily available on WebSocket handles, pass empty for now
            CreateAndSendEvent(ApiType::WebSocketSend, L"", b, l);
        }
    } catch (...) {
        EtwTraceMessage(L"Unhandled exception in Mine_WinHttpWebSocketSend. Passing through.");
    }
    return Real_WinHttpWebSocketSend(h, t, b, l);
}

DWORD WINAPI Mine_WinHttpWebSocketReceive(HINTERNET h, PVOID b, DWORD l, LPDWORD br, WINHTTP_WEB_SOCKET_BUFFER_TYPE* t) {
    DWORD result = Real_WinHttpWebSocketReceive(h, b, l, br, t);
    try {
        if (result == ERROR_SUCCESS && br && *br > 0) {
            CreateAndSendEvent(ApiType::WebSocketReceive, L"", b, *br);
        }
    } catch (...) {
        EtwTraceMessage(L"Unhandled exception in Mine_WinHttpWebSocketReceive. Passing through.");
    }
    return result;
}

// Key-log-only strategy: We don't hook SSL_write/SSL_read anymore to avoid
// interfering with the SSL handshake and certificate validation.
// Instead, we only use SSL_new to set up keylog callbacks.

// --- SSL Keylog Callback ---
// This callback is called by BoringSSL/OpenSSL when TLS session keys are generated.
// The format is compatible with Wireshark's SSL keylog file format.
void MyKeylogCallback(const SSL *ssl, const char *line) {
    try {
        if (line && strlen(line) > 0) {
            LOG_TRACE_F(L"SSL", L"Keylog callback invoked - line length: %d", strlen(line));
            
            std::string line_str(line);
            std::vector<unsigned char> data(line_str.begin(), line_str.end());
            
            std::wstring server_name_wstr = L"<unknown>";
            if (ssl && Real_SSL_get_servername) {
                const char* server_name_cstr = Real_SSL_get_servername(ssl, 0); // 0 for TLSEXT_NAMETYPE_host_name
                if (server_name_cstr) {
                    // Convert char* to wstring
                    int size_needed = MultiByteToWideChar(CP_UTF8, 0, server_name_cstr, (int)strlen(server_name_cstr), NULL, 0);
                    if (size_needed > 0) {
                        server_name_wstr.resize(size_needed);
                        MultiByteToWideChar(CP_UTF8, 0, server_name_cstr, (int)strlen(server_name_cstr), &server_name_wstr[0], size_needed);
                        LOG_INFO_F(L"SSL", L"SSL keylog for host: %s", server_name_wstr.c_str());
                    }
                }
            }
            
            // Send the keylog line to collector/file
            CreateAndSendEvent(ApiType::SslKeyLog, server_name_wstr, data.data(), data.size());
            
            // Also write to a local keylog file for Wireshark compatibility
            static bool keylogFileInitialized = false;
            static std::wstring keylogPath;
            if (!keylogFileInitialized) {
                wchar_t tempPath[MAX_PATH];
                GetTempPathW(MAX_PATH, tempPath);
                keylogPath = std::wstring(tempPath) + L"ai_hook_keylog.txt";
                keylogFileInitialized = true;
                LOG_INFO_F(L"SSL", L"SSL keylog file: %s", keylogPath.c_str());
            }
            
            // Append to keylog file
            FILE* keylogFile = nullptr;
            if (_wfopen_s(&keylogFile, keylogPath.c_str(), L"ab") == 0 && keylogFile) {
                fprintf(keylogFile, "%s\n", line);
                fclose(keylogFile);
            }
        }
    } catch (...) {
        LOG_ERROR(L"SSL", L"Unhandled exception in MyKeylogCallback");
        EtwTraceMessage(L"Unhandled exception in MyKeylogCallback. Ignoring.");
    }
}

// --- BoringSSL Detour for SSL_new (keylog-only strategy) ---
// This is the only SSL function we hook to enable keylogging without
// interfering with the handshake or data transfer.
SSL* Mine_SSL_new(SSL_CTX *ctx) {
    // Ensure 16-byte stack alignment for WoA compatibility
    volatile int dummy[4] = {0};
    (void)dummy; // Prevent optimization
    
    SSL* ssl_session = nullptr;
    try {
        // Call the original SSL_new first
        if (Real_SSL_new) {
            ssl_session = Real_SSL_new(ctx);
            LOG_TRACE_F(L"SSL", L"SSL_new called - ctx: 0x%p, ssl: 0x%p", ctx, ssl_session);
        }

        // Set up keylog callback if not already done for this context
        if (ctx && ssl_session && Real_SSL_CTX_set_keylog_callback) {
            if (g_processed_ssl_contexts.find(ctx) == g_processed_ssl_contexts.end()) {
                Real_SSL_CTX_set_keylog_callback(ctx, MyKeylogCallback);
                g_processed_ssl_contexts.insert(ctx);
                LOG_INFO_F(L"SSL", L"Registered SSL keylog callback for SSL_CTX: 0x%p", ctx);
                EtwTraceMessage(L"Registered SSL keylog callback for a new SSL_CTX.");
            }
        }
    } catch (...) {
        LOG_ERROR(L"SSL", L"Unhandled exception in Mine_SSL_new");
        EtwTraceMessage(L"Unhandled exception in Mine_SSL_new. Passing through.");
        // Return the SSL session if we got one, otherwise try calling original again
        if (!ssl_session && Real_SSL_new) {
            return Real_SSL_new(ctx);
        }
    }
    return ssl_session;
}

// --- Schannel Detours ---
SECURITY_STATUS SEC_ENTRY Mine_EncryptMessage(PCtxtHandle phContext, ULONG fQOP, PSecBufferDesc pMessage, ULONG MessageSeqNo) {
    // Ensure 16-byte stack alignment for WoA compatibility
    volatile int dummy[4] = {0};
    (void)dummy; // Prevent optimization
    
    try {
        std::wstring contextHandleStr = L"SchannelCtx_" + 
                                        std::to_wstring(reinterpret_cast<uintptr_t>(phContext));
        // Find the data buffer to log it before encryption
        for (ULONG i = 0; i < pMessage->cBuffers; ++i) {
            if (pMessage->pBuffers[i].BufferType == SECBUFFER_DATA) {
                CreateAndSendEvent(ApiType::SchannelEncrypt, contextHandleStr, pMessage->pBuffers[i].pvBuffer, pMessage->pBuffers[i].cbBuffer);
                break; // Assume only one data buffer
            }
        }
    } catch (...) {
        EtwTraceMessage(L"Unhandled exception in Mine_EncryptMessage. Passing through.");
    }
    return Real_EncryptMessage(phContext, fQOP, pMessage, MessageSeqNo);
}

SECURITY_STATUS SEC_ENTRY Mine_DecryptMessage(PCtxtHandle phContext, PSecBufferDesc pMessage, ULONG MessageSeqNo, PULONG pfQOP) {
    // Ensure 16-byte stack alignment for WoA compatibility
    volatile int dummy[4] = {0};
    (void)dummy; // Prevent optimization
    
    SECURITY_STATUS status = Real_DecryptMessage(phContext, pMessage, MessageSeqNo, pfQOP);
    try {
        if (status == SEC_E_OK) {
            // Find the data buffer to log it after decryption
            std::wstring contextHandleStr = L"SchannelCtx_" + 
                                            std::to_wstring(reinterpret_cast<uintptr_t>(phContext));
            // Find the data buffer to log it after decryption
            for (ULONG i = 0; i < pMessage->cBuffers; ++i) {
                if (pMessage->pBuffers[i].BufferType == SECBUFFER_DATA) {
                    CreateAndSendEvent(ApiType::SchannelDecrypt, contextHandleStr, pMessage->pBuffers[i].pvBuffer, pMessage->pBuffers[i].cbBuffer);
                    break; // Assume only one data buffer
                }
            }
        }
    } catch (...) {
        EtwTraceMessage(L"Unhandled exception in Mine_DecryptMessage. Passing through.");
    }
    return status;
}

// --- Electron Preload Hook --- 
BOOL WINAPI Mine_PostMessageW(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam) {
    try {
        if (Msg == WM_COPYDATA) {
            COPYDATASTRUCT* pcds = reinterpret_cast<COPYDATASTRUCT*>(lParam);
            if (pcds && pcds->cbData > 0 && pcds->lpData) {
                // Assuming the data is a UTF-8 string from preload.js
                std::string jsonData(static_cast<const char*>(pcds->lpData), pcds->cbData);

                // Check if it's our specific message format
                if (jsonData.rfind("{\"__aiti\":true", 0) == 0) { // Starts with {"__aiti":true
                    // For now, just capture the raw JSON data without parsing
                    CapturedEvent event;
                    event.timestamp = std::chrono::system_clock::now();
                    event.processId = GetCurrentProcessId();
                    event.threadId = GetCurrentThreadId();
                    event.apiType = ApiType::ElectronJs;
                    event.url = L"js-event";
                    event.data.assign(jsonData.begin(), jsonData.end());
                    
                    PipeSendEvent(event);
                }
            }
        }
    } catch (...) {
        EtwTraceMessage(L"Unhandled exception in Mine_PostMessageW. Passing through.");
    }
    return Real_PostMessageW(hWnd, Msg, wParam, lParam);
}

// Helper to get process name
std::wstring GetProcessName(DWORD pid) {
    wchar_t processPath[MAX_PATH] = L"";
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (hProcess) {
        DWORD size = MAX_PATH;
        QueryFullProcessImageNameW(hProcess, 0, processPath, &size);
        CloseHandle(hProcess);
    }
    
    std::wstring fullPath(processPath);
    size_t lastSlash = fullPath.find_last_of(L"\\");
    if (lastSlash != std::wstring::npos) {
        return fullPath.substr(lastSlash + 1);
    }
    return fullPath.empty() ? L"<unknown>" : fullPath;
}

// Helper to check if this is an Electron/Chromium process
bool IsElectronProcess() {
    // Check for Electron-specific modules and files
    HMODULE electronModules[] = {
        GetModuleHandleW(L"electron.exe"),
        GetModuleHandleW(L"chrome.dll"),
        GetModuleHandleW(L"chrome_elf.dll"),
        GetModuleHandleW(L"node.dll")
    };
    
    for (HMODULE mod : electronModules) {
        if (mod) {
            LOG_DEBUG(L"Electron", L"Electron/Chromium process detected");
            return true;
        }
    }
    
    // Check for VS Code specific indicators
    if (GetFileAttributesW(L"resources\\app\\package.json") != INVALID_FILE_ATTRIBUTES ||
        GetFileAttributesW(L"resources.pak") != INVALID_FILE_ATTRIBUTES ||
        GetFileAttributesW(L"chrome_100_percent.pak") != INVALID_FILE_ATTRIBUTES) {
        LOG_DEBUG(L"Electron", L"VS Code/Electron application detected via resource files");
        return true;
    }
    
    return false;
}

// Enhanced function to try BoringSSL/Electron specific exports
void TryElectronSslFunctions() {
    LOG_INFO(L"SSL", L"Attempting Electron/BoringSSL specific function discovery");
    
    // Electron/Chromium specific modules (prioritized order)
    const wchar_t* electronSslModules[] = {
        L"chrome.dll",         // Primary Chromium/BoringSSL location
        L"chrome_child.dll",   // Child process SSL functions
        L"node.dll",          // Node.js/BoringSSL in Electron
        L"electron.exe",      // Sometimes contains SSL symbols
        L"nw.dll",           // NW.js applications
        L"ffmpeg.dll",       // May contain SSL exports in some Electron apps
        L"libnode.dll",      // Alternative Node.js naming
        L"v8.dll"            // V8 engine may have SSL exports
    };
    
    // BoringSSL may use different export names
    const char* boringSSLExports[] = {
        "SSL_new",
        "SSL_CTX_set_keylog_callback", 
        "SSL_get_servername",
        // BoringSSL specific variants
        "SSL_get_servername_ex",
        "SSL_CTX_set_keylog_callback_ex",
        // Try mangled C++ names that might exist
        "?SSL_new@@YAPAUssl_st@@PAUssl_ctx_st@@@Z",
        "?SSL_CTX_set_keylog_callback@@YAXPAUssl_ctx_st@@P6AXPBUssl_st@@PEBD@Z@Z"
    };
    
    for (const wchar_t* moduleName : electronSslModules) {
        HMODULE hMod = GetModuleHandleW(moduleName);
        if (hMod) {
            LOG_INFO_F(L"SSL", L"Checking Electron module for SSL exports: %s", moduleName);
            EtwTraceMessage((std::wstring(L"Checking Electron module: ") + moduleName).c_str());
            
            wchar_t modulePath[MAX_PATH];
            GetModuleFileNameW(hMod, modulePath, MAX_PATH);
            LOG_DEBUG_F(L"SSL", L"Module path: %s", modulePath);
            
            // Try all possible export names
            for (const char* exportName : boringSSLExports) {
                void* func = GetProcAddress(hMod, exportName);
                if (func) {
                    LOG_INFO_F(L"SSL", L"Found %S in %s", exportName, moduleName);
                    
                    // Map to our function pointers
                    if (strstr(exportName, "SSL_new") && !Real_SSL_new) {
                        Real_SSL_new = (SSL_new_t)func;
                    }
                    else if (strstr(exportName, "SSL_CTX_set_keylog_callback") && !Real_SSL_CTX_set_keylog_callback) {
                        Real_SSL_CTX_set_keylog_callback = (SSL_CTX_set_keylog_callback_t)func;
                    }
                    else if (strstr(exportName, "SSL_get_servername") && !Real_SSL_get_servername) {
                        Real_SSL_get_servername = (SSL_get_servername_t)func;
                    }
                }
            }
            
            // Early exit if we found essential functions
            if (Real_SSL_new && Real_SSL_CTX_set_keylog_callback) {
                LOG_INFO_F(L"SSL", L"Found essential BoringSSL functions in %s", moduleName);
                return;
            }
        } else {
            LOG_TRACE_F(L"SSL", L"Electron module %s not loaded", moduleName);
        }
    }
    
    if (!Real_SSL_new || !Real_SSL_CTX_set_keylog_callback) {
        LOG_WARN(L"SSL", L"Could not find essential BoringSSL functions via exports");
    }
}

// --- Hook Installation ---
// Helper function to attempt to get SSL function addresses from common module names
void TryGetSslFunctionsFromExports() {
    LOG_INFO(L"SSL", L"Attempting to find SSL functions from module exports");
    
    // Check if this is an Electron process and use specialized detection
    if (IsElectronProcess()) {
        LOG_INFO(L"SSL", L"Detected Electron/Chromium process - using specialized BoringSSL detection");
        TryElectronSslFunctions();
        // If Electron-specific detection worked, return early
        if (Real_SSL_new && Real_SSL_CTX_set_keylog_callback) {
            return;
        }
        LOG_WARN(L"SSL", L"Electron-specific detection failed, falling back to standard detection");
    }
    
    // Standard SSL module detection (for non-Electron or fallback)
    const wchar_t* commonSslModuleNames[] = {
        L"node.dll",           // For VSCode/Electron's bundled Node.js/BoringSSL
        L"chrome.dll",        // Chromium core library (Electron)
        L"chrome_elf.dll",    // Chromium helper which also exports SSL symbols
        L"libssl-3-x64.dll",
        L"libssl-1_1-x64.dll",
        L"libssl.dll",
        L"boringssl.dll", 
        L"ssleay32.dll",
        L"libeay32.dll"
    };

    for (const wchar_t* moduleName : commonSslModuleNames) {
        HMODULE hMod = GetModuleHandleW(moduleName);
        if (!hMod) {
            LOG_TRACE_F(L"SSL", L"Module %s not loaded", moduleName);
            // Try LoadLibrary if not already loaded, though SSL libs are usually pre-loaded by apps using them
            // hMod = LoadLibraryW(moduleName);
            // if (hMod) { /* remember to FreeLibrary if we loaded it and aren't using it */ }
        }

        if (hMod) {
            LOG_DEBUG_F(L"SSL", L"Checking module for SSL exports: %s", moduleName);
            EtwTraceMessage((std::wstring(L"Checking module for SSL exports: ") + moduleName).c_str());
            
            // Key-log-only strategy: We only need SSL_new and SSL_CTX_set_keylog_callback
            if (!Real_SSL_get_servername) {
                Real_SSL_get_servername = (SSL_get_servername_t)GetProcAddress(hMod, "SSL_get_servername");
                if (Real_SSL_get_servername) LOG_INFO_F(L"SSL", L"Found SSL_get_servername in %s", moduleName);
            }
            if (!Real_SSL_CTX_set_keylog_callback) {
                Real_SSL_CTX_set_keylog_callback = (SSL_CTX_set_keylog_callback_t)GetProcAddress(hMod, "SSL_CTX_set_keylog_callback");
                if (Real_SSL_CTX_set_keylog_callback) LOG_INFO_F(L"SSL", L"Found SSL_CTX_set_keylog_callback in %s", moduleName);
            }
            if (!Real_SSL_new) {
                Real_SSL_new = (SSL_new_t)GetProcAddress(hMod, "SSL_new");
                if (Real_SSL_new) LOG_INFO_F(L"SSL", L"Found SSL_new in %s", moduleName);
            }
            
            // For keylog-only strategy, we need SSL_new and SSL_CTX_set_keylog_callback
            // SSL_get_servername is optional but helpful for host identification
            if (Real_SSL_CTX_set_keylog_callback && Real_SSL_new) {
                LOG_INFO(L"SSL", L"Found essential SSL functions for keylogging via GetProcAddress");
                EtwTraceMessage(L"Found essential SSL functions for keylogging via GetProcAddress.");
                if (Real_SSL_get_servername) {
                    LOG_INFO(L"SSL", L"Also found SSL_get_servername for host identification");
                }
                return;
            }
        }
    }
    
    LOG_WARN(L"SSL", L"Not all SSL functions found via exports");
}

void InstallSslHooks() {
    LOG_INFO(L"SSL", L"Installing SSL keylog-only hooks");
    
    // Check if SSL hooks are disabled via environment variable
    char* disableSslHooks = getenv("AITI_DISABLE_SSL_HOOKS");
    if (disableSslHooks && strcmp(disableSslHooks, "1") == 0) {
        LOG_INFO(L"SSL", L"SSL hooks disabled via AITI_DISABLE_SSL_HOOKS environment variable");
        EtwTraceMessage(L"SSL hooks disabled via AITI_DISABLE_SSL_HOOKS environment variable");
        return;
    }
    
    // Key-log-only strategy: We only hook SSL_new to set up keylog callbacks.
    // This avoids interfering with SSL handshakes and certificate validation.
    // The keylog file will be created at %TEMP%\ai_hook_keylog.txt
    // You can use this file with Wireshark: Edit -> Preferences -> Protocols -> TLS -> (Pre)-Master-Secret log filename
    
    // Check if SSL hooks should be skipped for this process based on config
    std::wstring currentProcessName = GetProcessName(GetCurrentProcessId());
    
    // Try to load config file from same directory as injector
    wchar_t configPath[MAX_PATH];
    GetModuleFileNameW(NULL, configPath, MAX_PATH);
    std::wstring configDir(configPath);
    size_t lastSlash = configDir.find_last_of(L"\\");
    if (lastSlash != std::wstring::npos) {
        configDir = configDir.substr(0, lastSlash);
    }
    std::wstring configFile = configDir + L"\\aiti_config.json";
    
    // Check parent directories for config file
    std::vector<std::wstring> configPaths = {
        configFile,
        configDir + L"\\..\\config\\aiti_config.json",
        configDir + L"\\..\\..\\config\\aiti_config.json"
    };
    
    for (const auto& path : configPaths) {
        std::ifstream file(path);
        if (file.is_open()) {
            try {
                // Simple parsing for our specific config format
                std::string line;
                bool inSkipSsl = false;
                
                while (std::getline(file, line)) {
                    // Remove whitespace
                    line.erase(0, line.find_first_not_of(" \t\r\n"));
                    line.erase(line.find_last_not_of(" \t\r\n") + 1);
                    
                    // Check if we're in the skip_ssl section
                    if (line.find("\"skip_ssl\"") != std::string::npos) {
                        inSkipSsl = true;
                        continue;
                    }
                    
                    // If we're in skip_ssl section and find a process name
                    if (inSkipSsl && line.find("\"Code.exe\"") != std::string::npos) {
                        if (_wcsicmp(currentProcessName.c_str(), L"Code.exe") == 0) {
                            LOG_INFO_F(L"SSL", L"SSL hooks disabled for process %s via config file", currentProcessName.c_str());
                            EtwTraceMessage((L"SSL hooks disabled for process " + currentProcessName + L" via config file").c_str());
                            return;
                        }
                    }
                    
                    // Check for any other process names in quotes
                    if (inSkipSsl && line.find("\"") != std::string::npos) {
                        size_t start = line.find("\"") + 1;
                        size_t end = line.find("\"", start);
                        if (end != std::string::npos) {
                            std::string processName = line.substr(start, end - start);
                            std::wstring wProcessName(processName.begin(), processName.end());
                            if (_wcsicmp(currentProcessName.c_str(), wProcessName.c_str()) == 0) {
                                LOG_INFO_F(L"SSL", L"SSL hooks disabled for process %s via config file", currentProcessName.c_str());
                                EtwTraceMessage((L"SSL hooks disabled for process " + currentProcessName + L" via config file").c_str());
                                return;
                            }
                        }
                    }
                    
                    // Exit skip_ssl section if we hit a closing bracket
                    if (inSkipSsl && line.find("]") != std::string::npos) {
                        inSkipSsl = false;
                    }
                }
            } catch (const std::exception& e) {
                LOG_WARN_F(L"SSL", L"Failed to parse config file: %S", e.what());
            }
            break; // Found a config file, don't check others
        }
    }
    
    // First, try to get functions from exports of common SSL libraries
    TryGetSslFunctionsFromExports();

    // If any are still null, fall back to pattern scanning in chrome.dll (or other target module)
    // For now, chrome.dll is the primary target for pattern scanning if exports fail.
    HMODULE hTargetModuleForScanning = GetModuleHandleW(L"chrome.dll"); 
    if (!hTargetModuleForScanning) {
         // If chrome.dll isn't there, and we haven't found functions by export, keylogging won't work.
        if (!Real_SSL_CTX_set_keylog_callback || !Real_SSL_new) {
            LOG_WARN(L"SSL", L"Target module (e.g., chrome.dll) not found, and essential SSL functions not found by export. Keylogging not available.");
            EtwTraceMessage(L"Target module (e.g., chrome.dll) not found, and essential SSL functions not found by export. Keylogging not available.");
            return;
        }
        // If essential functions were found by export, we don't need to scan chrome.dll
    }

    // Proceed with pattern scanning if essential functions are not yet found AND hTargetModuleForScanning is valid
    bool needsPatternScan = (!Real_SSL_CTX_set_keylog_callback || !Real_SSL_new || !Real_SSL_get_servername) && hTargetModuleForScanning;

    if (needsPatternScan) {
        LOG_INFO(L"SSL", L"Attempting SSL function pattern scanning in target module (e.g. chrome.dll)");
        EtwTraceMessage(L"Attempting SSL function pattern scanning in target module (e.g. chrome.dll).");
    
    // Key-log-only strategy: We only need patterns for SSL_new, SSL_CTX_set_keylog_callback, and optionally SSL_get_servername
    // We no longer hook SSL_write/SSL_read to avoid interfering with handshakes

    // SSL_get_servername: 48 83 EC 28 48 8B 49 10 48 85 C9 74 08 48 8B 01 FF 50 18
    const unsigned char ssl_get_servername_pattern[] = { 0x48, 0x83, 0xEC, 0x28, 0x48, 0x8B, 0x49, 0x10, 0x48, 0x85, 0xC9, 0x74, 0x08, 0x48, 0x8B, 0x01, 0xFF, 0x50, 0x18 };
    const char ssl_get_servername_mask[] = "xxxxxxxxxxxxxxxxxxxxx";

    // SSL_new: 48 89 5C 24 08 57 48 83 EC 20 48 8B F9 E8 ?? ?? ?? ?? 48 8B D8
    const unsigned char ssl_new_pattern[] = { 0x48, 0x89, 0x5C, 0x24, 0x08, 0x57, 0x48, 0x83, 0xEC, 0x20, 0x48, 0x8B, 0xF9, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8B, 0xD8 };
    const char ssl_new_mask[] = "xxxxxxxxxxxxx????xxxx";

    // SSL_CTX_set_keylog_callback: 48 89 5C 24 08 48 89 74 24 10 57 48 83 EC 20 48 8B D9 48 8B 49 08
    const unsigned char ssl_ctx_set_keylog_callback_pattern[] = { 0x48, 0x89, 0x5C, 0x24, 0x08, 0x48, 0x89, 0x74, 0x24, 0x10, 0x57, 0x48, 0x83, 0xEC, 0x20, 0x48, 0x8B, 0xD9, 0x48, 0x8B, 0x49, 0x08 };
    const char ssl_ctx_set_keylog_callback_mask[] = "xxxxxxxxxxxxxxxxxxxxxx";


    uintptr_t ssl_get_servername_addr = 0;
    uintptr_t ssl_ctx_set_keylog_callback_addr = 0, ssl_new_addr = 0;

    if (!Real_SSL_get_servername) {
        ssl_get_servername_addr = FindPattern(hTargetModuleForScanning, ssl_get_servername_pattern, ssl_get_servername_mask);
        if (ssl_get_servername_addr) Real_SSL_get_servername = (SSL_get_servername_t)ssl_get_servername_addr;
        else EtwTraceMessage(L"SSL_get_servername pattern not found.");
    }
    if (!Real_SSL_CTX_set_keylog_callback) {
        ssl_ctx_set_keylog_callback_addr = FindPattern(hTargetModuleForScanning, ssl_ctx_set_keylog_callback_pattern, ssl_ctx_set_keylog_callback_mask);
        if (ssl_ctx_set_keylog_callback_addr) Real_SSL_CTX_set_keylog_callback = (SSL_CTX_set_keylog_callback_t)ssl_ctx_set_keylog_callback_addr;
        else EtwTraceMessage(L"SSL_CTX_set_keylog_callback pattern not found.");
    }
    if (!Real_SSL_new) {
        ssl_new_addr = FindPattern(hTargetModuleForScanning, ssl_new_pattern, ssl_new_mask);
        if (ssl_new_addr) Real_SSL_new = (SSL_new_t)ssl_new_addr;
        else EtwTraceMessage(L"SSL_new pattern not found.");
    }

    } // End of if(needsPatternScan)

    // Key-log-only strategy: Only attach SSL_new hook for keylogging
    bool attachedAnySsl = false;

    if (Real_SSL_new && Real_SSL_CTX_set_keylog_callback) {
        DetourAttach(&(PVOID&)Real_SSL_new, Mine_SSL_new);
        LOG_INFO(L"SSL", L"Attached to SSL_new for keylog-only strategy");
        EtwTraceMessage(L"Attached to SSL_new (keylog-only strategy).");
        attachedAnySsl = true;
        
        // Log if we have SSL_get_servername for better host identification
        if (Real_SSL_get_servername) {
            LOG_INFO(L"SSL", L"SSL_get_servername available for host identification");
        } else {
            LOG_WARN(L"SSL", L"SSL_get_servername not found - hosts will be logged as <unknown>");
        }
    } else {
        if (!Real_SSL_new) {
            LOG_WARN(L"SSL", L"SSL_new not found - cannot enable keylogging");
            EtwTraceMessage(L"SSL_new not found. Cannot enable keylogging.");
        }
        if (!Real_SSL_CTX_set_keylog_callback) {
            LOG_WARN(L"SSL", L"SSL_CTX_set_keylog_callback not found - cannot enable keylogging");
            EtwTraceMessage(L"SSL_CTX_set_keylog_callback not found. Cannot enable keylogging.");
        }
    }

    if (attachedAnySsl) {
        LOG_INFO(L"SSL", L"SSL keylog-only hooks installed successfully");
        EtwTraceMessage(L"SSL keylog-only hooks installed.");
        g_sslHooksInstalled = true;
    } else {
        LOG_WARN(L"SSL", L"No SSL functions attached - keylogging NOT available");
        EtwTraceMessage(L"No SSL functions found/attached. SSL keylogging NOT available.");
    }
    // DetourTransactionCommit() will be called later in InstallHooks()
}

// --- LoadLibraryW Detour ---
HMODULE WINAPI Mine_LoadLibraryW(LPCWSTR lpLibFileName) {
    HMODULE hMod = Real_LoadLibraryW(lpLibFileName);
    if (!g_sslHooksInstalled && hMod) {
        // Attempt to install SSL hooks now that a new module has loaded
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        InstallSslHooks();
        DetourTransactionCommit();
    }
    return hMod;
}

// Enhanced Electron/VS Code process diagnostics
void DiagnoseElectronEnvironment() {
    LOG_INFO(L"Electron", L"=== Electron Process Diagnostics ===");
    
    std::wstring processName = GetProcessName(GetCurrentProcessId());
    LOG_INFO_F(L"Electron", L"Process: %s (PID: %d)", processName.c_str(), GetCurrentProcessId());
    
    // Check for Electron-specific modules
    struct ModuleInfo {
        const wchar_t* name;
        const wchar_t* description;
    };
    
    ModuleInfo electronModules[] = {
        {L"chrome.dll", L"Chromium core library (BoringSSL)"},
        {L"chrome_elf.dll", L"Chromium ELF helper"},
        {L"chrome_child.dll", L"Chromium child process"},
        {L"node.dll", L"Node.js runtime"},
        {L"electron.exe", L"Electron framework"},
        {L"v8.dll", L"V8 JavaScript engine"},
        {L"ffmpeg.dll", L"Media processing"},
        {L"libnode.dll", L"Alternative Node.js naming"}
    };
    
    bool electronDetected = false;
    for (const auto& module : electronModules) {
        HMODULE hMod = GetModuleHandleW(module.name);
        if (hMod) {
            wchar_t modulePath[MAX_PATH];
            GetModuleFileNameW(hMod, modulePath, MAX_PATH);
            LOG_INFO_F(L"Electron", L"✓ %s: %s", module.description, modulePath);
            electronDetected = true;
        } else {
            LOG_TRACE_F(L"Electron", L"✗ %s not loaded", module.description);
        }
    }
    
    if (electronDetected) {
        LOG_INFO(L"Electron", L"Electron/Chromium process confirmed");
        EtwTraceMessage(L"Electron/Chromium process confirmed via module detection");
    } else {
        LOG_INFO(L"Electron", L"Standard Windows process (non-Electron)");
    }
    
    // Check for VS Code specific resources and files
    std::vector<std::wstring> vscodeIndicators = {
        L"resources\\app\\package.json",
        L"resources.pak", 
        L"chrome_100_percent.pak",
        L"resources\\app\\out\\main.js",
        L"resources\\app\\extensions"
    };
    
    bool vscodeDetected = false;
    for (const auto& indicator : vscodeIndicators) {
        if (GetFileAttributesW(indicator.c_str()) != INVALID_FILE_ATTRIBUTES) {
            LOG_INFO_F(L"Electron", L"✓ VS Code indicator found: %s", indicator.c_str());
            vscodeDetected = true;
        }
    }
    
    if (vscodeDetected) {
        LOG_INFO(L"Electron", L"VS Code application confirmed");
        EtwTraceMessage(L"VS Code application confirmed via resource file detection");
    }
    
    // Check command line for process type
    wchar_t* cmdLine = GetCommandLineW();
    if (cmdLine) {
        std::wstring cmdLineStr(cmdLine);
        LOG_DEBUG_F(L"Electron", L"Command line: %s", cmdLineStr.c_str());
        
        if (cmdLineStr.find(L"--type=renderer") != std::wstring::npos) {
            LOG_INFO(L"Electron", L"Process type: Renderer (UI process)");
            EtwTraceMessage(L"Detected Electron renderer process");
        }
        else if (cmdLineStr.find(L"--type=extensionHost") != std::wstring::npos || 
                 cmdLineStr.find(L"--type=extension-host") != std::wstring::npos) {
            LOG_INFO(L"Electron", L"Process type: Extension Host (extensions run here)");
            EtwTraceMessage(L"Detected VS Code extension host process");
        }
        else if (cmdLineStr.find(L"--type=") != std::wstring::npos) {
            LOG_INFO(L"Electron", L"Process type: Worker/Utility process");
        }
        else if (electronDetected || vscodeDetected) {
            LOG_INFO(L"Electron", L"Process type: Main process");
            EtwTraceMessage(L"Detected Electron main process");
        }
    }
    
    // Architecture and compatibility info
    SYSTEM_INFO sysInfo;
    GetNativeSystemInfo(&sysInfo);
    std::wstring archStr;
    switch (sysInfo.wProcessorArchitecture) {
        case PROCESSOR_ARCHITECTURE_AMD64: archStr = L"x64"; break;
        case PROCESSOR_ARCHITECTURE_ARM64: archStr = L"ARM64"; break;
        case PROCESSOR_ARCHITECTURE_INTEL: archStr = L"x86"; break;
        default: archStr = L"Unknown"; break;
    }
    LOG_INFO_F(L"Electron", L"System architecture: %s", archStr.c_str());
    
    // Check if running under emulation
    BOOL isWow64 = FALSE;
    IsWow64Process(GetCurrentProcess(), &isWow64);
    if (isWow64) {
        LOG_INFO(L"Electron", L"Process running under WoW64 emulation");
        EtwTraceMessage(L"Process running under WoW64 emulation - may affect hook compatibility");
    }
    
    LOG_INFO(L"Electron", L"=== End Electron Diagnostics ===");
}

void InstallHooks() {
    LOG_INFO(L"Hooks", L"Beginning hook installation");
    LOG_INFO_F(L"Hooks", L"Process: %s (PID: %d)", GetProcessName(GetCurrentProcessId()).c_str(), GetCurrentProcessId());
    
    // Run Electron diagnostics first
    DiagnoseElectronEnvironment();
    
    EtwRegister();
    LOG_DEBUG(L"Hooks", L"ETW registered");
    
    PipeClientInit();
    LOG_DEBUG(L"Hooks", L"Pipe client initialized");

    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    
    LOG_INFO(L"Hooks", L"Installing WinHTTP hooks");
    DetourAttach(&(PVOID&)Real_WinHttpSendRequest, Mine_WinHttpSendRequest);
    DetourAttach(&(PVOID&)Real_WinHttpReadData, Mine_WinHttpReadData);
    DetourAttach(&(PVOID&)Real_WinHttpWebSocketSend, Mine_WinHttpWebSocketSend);
    DetourAttach(&(PVOID&)Real_WinHttpWebSocketReceive, Mine_WinHttpWebSocketReceive);
    
    LOG_INFO(L"Hooks", L"Installing Schannel hooks");
    DetourAttach(&(PVOID&)Real_EncryptMessage, Mine_EncryptMessage);
    DetourAttach(&(PVOID&)Real_DecryptMessage, Mine_DecryptMessage);
    DetourAttach(&(PVOID&)Real_AcquireCredentialsHandleW, Mine_AcquireCredentialsHandleW);
    
    LOG_INFO(L"Hooks", L"Installing PostMessage hook for Electron");
    DetourAttach(&(PVOID&)Real_PostMessageW, Mine_PostMessageW);
    
    LOG_INFO(L"Hooks", L"Installing LoadLibraryW hook for late SSL detection");
    DetourAttach(&(PVOID&)Real_LoadLibraryW, Mine_LoadLibraryW);

    InstallSslHooks();
    
    LONG error = DetourTransactionCommit();
    if (error != NO_ERROR) {
        LOG_ERROR_F(L"Hooks", L"DetourTransactionCommit failed with error: %ld", error);
        EtwTraceMessage(L"DetourTransactionCommit failed!");
    } else {
        LOG_INFO(L"Hooks", L"All hooks installed successfully");
        EtwTraceMessage(L"All hooks installed successfully.");
    }
}

void RemoveHooks() {
    LOG_INFO(L"Hooks", L"Beginning hook removal");
    
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    
    LOG_DEBUG(L"Hooks", L"Detaching WinHTTP hooks");
    DetourDetach(&(PVOID&)Real_WinHttpSendRequest, Mine_WinHttpSendRequest);
    DetourDetach(&(PVOID&)Real_WinHttpReadData, Mine_WinHttpReadData);
    DetourDetach(&(PVOID&)Real_WinHttpWebSocketSend, Mine_WinHttpWebSocketSend);
    DetourDetach(&(PVOID&)Real_WinHttpWebSocketReceive, Mine_WinHttpWebSocketReceive);
    
    LOG_DEBUG(L"Hooks", L"Detaching Schannel hooks");
    DetourDetach(&(PVOID&)Real_EncryptMessage, Mine_EncryptMessage);
    DetourDetach(&(PVOID&)Real_DecryptMessage, Mine_DecryptMessage);
    DetourDetach(&(PVOID&)Real_AcquireCredentialsHandleW, Mine_AcquireCredentialsHandleW);
    
    LOG_DEBUG(L"Hooks", L"Detaching PostMessage hook");
    DetourDetach(&(PVOID&)Real_PostMessageW, Mine_PostMessageW);
    
    LOG_DEBUG(L"Hooks", L"Detaching LoadLibraryW hook");
    DetourDetach(&(PVOID&)Real_LoadLibraryW, Mine_LoadLibraryW);

    if (Real_SSL_new) {
        LOG_DEBUG(L"Hooks", L"Detaching SSL_new (keylog-only)");
        DetourDetach(&(PVOID&)Real_SSL_new, Mine_SSL_new);
    }
    
    LONG error = DetourTransactionCommit();
    if (error != NO_ERROR) {
        LOG_ERROR_F(L"Hooks", L"DetourTransactionCommit failed during removal with error: %ld", error);
    } else {
        LOG_INFO(L"Hooks", L"All hooks removed successfully");
    }
    
    PipeClientShutdown();
    LOG_DEBUG(L"Hooks", L"Pipe client shut down");
    
    EtwUnregister();
    LOG_DEBUG(L"Hooks", L"ETW unregistered");
}

BOOL APIENTRY DllMain(HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
) {
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        LOG_INFO(L"DllMain", L"=== AI Hook DLL Attached ===");
        LOG_INFO_F(L"DllMain", L"Module handle: 0x%p", hModule);
        LOG_INFO_F(L"DllMain", L"Log file: %s", Logger::GetInstance()->GetLogFilePath().c_str());
        
        DisableThreadLibraryCalls(hModule);
        InstallHooks();
        break;
        
    case DLL_PROCESS_DETACH:
        LOG_INFO(L"DllMain", L"=== AI Hook DLL Detaching ===");
        RemoveHooks();
        break;
    }
    return TRUE;
}
