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

// --- BoringSSL Detour ---
// Ensure proper stack alignment for Windows on ARM compatibility
int __cdecl Mine_SSL_write(SSL* ssl, const void* buf, int num) {
    // Ensure 16-byte stack alignment for WoA compatibility
    volatile int dummy[4] = {0};
    (void)dummy; // Prevent optimization
    
    LOG_TRACE_F(L"SSL", L"SSL_write called - ssl: 0x%p, dataLen: %d", ssl, num);
    
    try {
        if (Real_SSL_get_servername && ssl) {
            const char* servername = Real_SSL_get_servername(ssl, 0); // 0 for TLSEXT_NAMETYPE_host_name
            if (servername) {
                // Convert char* to wstring
                int size_needed = MultiByteToWideChar(CP_UTF8, 0, servername, (int)strlen(servername), NULL, 0);
                std::wstring wServername(size_needed, 0);
                MultiByteToWideChar(CP_UTF8, 0, servername, (int)strlen(servername), &wServername[0], size_needed);
                
                LOG_INFO_F(L"SSL", L"Intercepted SSL_write - Server: %s, Size: %d bytes", wServername.c_str(), num);
                LOG_DATA(LogLevel::DEBUG, L"SSL", L"SSL write data", buf, num);
                
                CreateAndSendEvent(ApiType::SslWrite, wServername, buf, num);
            } else {
                LOG_DEBUG(L"SSL", L"SSL_write called but no servername available");
            }
        } else {
            LOG_WARN_F(L"SSL", L"SSL_write called but Real_SSL_get_servername is null (0x%p) or ssl is null", Real_SSL_get_servername);
        }
    } catch (...) {
        LOG_ERROR(L"SSL", L"Unhandled exception in Mine_SSL_write");
        EtwTraceMessage(L"Unhandled exception in Mine_SSL_write. Passing through.");
    }
    return Real_SSL_write(ssl, buf, num);
}

// --- BoringSSL Detour for SSL_read ---
int __cdecl Mine_SSL_read(SSL* ssl, void* buf, int num) {
    // Ensure 16-byte stack alignment for WoA compatibility
    volatile int dummy[4] = {0};
    (void)dummy; // Prevent optimization
    
    LOG_TRACE_F(L"SSL", L"SSL_read called - ssl: 0x%p, bufferSize: %d", ssl, num);
    
    int bytes_read = Real_SSL_read(ssl, buf, num);
    try {
        if (bytes_read > 0 && Real_SSL_get_servername && ssl) {
            const char* servername = Real_SSL_get_servername(ssl, 0); // 0 for TLSEXT_NAMETYPE_host_name
            if (servername) {
                // Convert char* to wstring
                int size_needed = MultiByteToWideChar(CP_UTF8, 0, servername, (int)strlen(servername), NULL, 0);
                std::wstring wServername(size_needed, 0);
                MultiByteToWideChar(CP_UTF8, 0, servername, (int)strlen(servername), &wServername[0], size_needed);
                
                LOG_INFO_F(L"SSL", L"Intercepted SSL_read - Server: %s, Read: %d bytes", wServername.c_str(), bytes_read);
                LOG_DATA(LogLevel::DEBUG, L"SSL", L"SSL read data", buf, bytes_read);
                
                CreateAndSendEvent(ApiType::SslRead, wServername, buf, bytes_read);
            } else {
                LOG_DEBUG(L"SSL", L"SSL_read returned data but no servername available");
            }
        } else if (bytes_read <= 0) {
            LOG_TRACE_F(L"SSL", L"SSL_read returned %d (no data or error)", bytes_read);
        }
    } catch (...) {
        LOG_ERROR(L"SSL", L"Unhandled exception in Mine_SSL_read");
        EtwTraceMessage(L"Unhandled exception in Mine_SSL_read. Passing through.");
    }
    return bytes_read;
}

// --- SSL Keylog Callback ---
void MyKeylogCallback(const SSL *ssl, const char *line) {
    try {
        if (line && strlen(line) > 0) {
            std::string line_str(line);
            std::vector<unsigned char> data(line_str.begin(), line_str.end());
            
            std::wstring server_name_wstr;
            if (ssl && Real_SSL_get_servername) {
                const char* server_name_cstr = Real_SSL_get_servername(ssl, 0); // 0 for TLSEXT_NAMETYPE_host_name
                if (server_name_cstr) {
                    // Convert char* to wstring
                    int size_needed = MultiByteToWideChar(CP_UTF8, 0, server_name_cstr, (int)strlen(server_name_cstr), NULL, 0);
                    server_name_wstr.resize(size_needed);
                    MultiByteToWideChar(CP_UTF8, 0, server_name_cstr, (int)strlen(server_name_cstr), &server_name_wstr[0], size_needed);
                }
            }
            if (server_name_wstr.empty()) {
                server_name_wstr = L"UnknownHost_KeyLog";
            }
            CreateAndSendEvent(ApiType::SslKeyLog, server_name_wstr, data.data(), data.size());
        }
    } catch (...) {
        EtwTraceMessage(L"Unhandled exception in MyKeylogCallback. Ignoring.");
    }
}

// --- BoringSSL Detour for SSL_new (to get SSL_CTX* for keylog callback) ---
SSL* Mine_SSL_new(SSL_CTX *ctx) {
    // Ensure 16-byte stack alignment for WoA compatibility
    volatile int dummy[4] = {0};
    (void)dummy; // Prevent optimization
    
    SSL* ssl_session = nullptr;
    try {
        if (Real_SSL_new) { // Ensure Real_SSL_new is resolved
            ssl_session = Real_SSL_new(ctx);
        }

        if (ctx && Real_SSL_CTX_set_keylog_callback && ssl_session) { // Check ssl_session too, SSL_new might fail
            // Check if we've already set the callback for this context
            if (g_processed_ssl_contexts.find(ctx) == g_processed_ssl_contexts.end()) {
                Real_SSL_CTX_set_keylog_callback(ctx, MyKeylogCallback);
                g_processed_ssl_contexts.insert(ctx);
                EtwTraceMessage(L"Registered SSL keylog callback for a new SSL_CTX.");
            }
        }
    } catch (...) {
        EtwTraceMessage(L"Unhandled exception in Mine_SSL_new. Passing through.");
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

// --- Hook Installation ---
// Helper function to attempt to get SSL function addresses from common module names
void TryGetSslFunctionsFromExports() {
    LOG_INFO(L"SSL", L"Attempting to find SSL functions from module exports");
    
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
            
            if (!Real_SSL_write) {
                Real_SSL_write = (SSL_write_t)GetProcAddress(hMod, "SSL_write");
                if (Real_SSL_write) LOG_INFO_F(L"SSL", L"Found SSL_write in %s", moduleName);
            }
            if (!Real_SSL_read) {
                Real_SSL_read = (SSL_read_t)GetProcAddress(hMod, "SSL_read");
                if (Real_SSL_read) LOG_INFO_F(L"SSL", L"Found SSL_read in %s", moduleName);
            }
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
            
            // If we found all essential functions, we can stop searching modules
            // SSL_get_servername is helpful but not strictly essential for keylogging if SSL_CTX_set_keylog_callback and SSL_new are found.
            if (Real_SSL_write && Real_SSL_read && Real_SSL_CTX_set_keylog_callback && Real_SSL_new && Real_SSL_get_servername) {
                LOG_INFO(L"SSL", L"Found all SSL functions via GetProcAddress");
                EtwTraceMessage(L"Found all SSL functions via GetProcAddress.");
                return;
            }
        }
    }
    
    LOG_WARN(L"SSL", L"Not all SSL functions found via exports");
}

void InstallSslHooks() {
    LOG_INFO(L"SSL", L"Installing SSL hooks");
    
    // Check if SSL hooks are disabled via environment variable
    char* disableSslHooks = getenv("AITI_DISABLE_SSL_HOOKS");
    if (disableSslHooks && strcmp(disableSslHooks, "1") == 0) {
        LOG_INFO(L"SSL", L"SSL hooks disabled via AITI_DISABLE_SSL_HOOKS environment variable");
        EtwTraceMessage(L"SSL hooks disabled via AITI_DISABLE_SSL_HOOKS environment variable");
        return;
    }
    
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
         // If chrome.dll isn't there, and we haven't found functions by export, SSL hooks won't work.
        if (!Real_SSL_write && !Real_SSL_read) { // Check if any essential func is missing
            LOG_WARN(L"SSL", L"Target module (e.g., chrome.dll) not found, and SSL functions not found by export. Skipping SSL pattern scan.");
            EtwTraceMessage(L"Target module (e.g., chrome.dll) not found, and SSL functions not found by export. Skipping SSL pattern scan.");
            return;
        }
        // If some were found by export, we might not need to scan chrome.dll
    }

    // Proceed with pattern scanning if functions are not yet found AND hTargetModuleForScanning is valid
    bool needsPatternScan = (!Real_SSL_write || !Real_SSL_read || !Real_SSL_get_servername || !Real_SSL_CTX_set_keylog_callback || !Real_SSL_new) && hTargetModuleForScanning;

    if (needsPatternScan) {
        LOG_INFO(L"SSL", L"Attempting SSL function pattern scanning in target module (e.g. chrome.dll)");
        EtwTraceMessage(L"Attempting SSL function pattern scanning in target module (e.g. chrome.dll).");
    
    // Validated patterns for x64 versions of BoringSSL found in recent Chrome/Electron.
    // SSL_write: 48 89 5C 24 08 48 89 6C 24 10 48 89 74 24 18 57 48 83 EC 20 48 8B F9
    const unsigned char ssl_write_pattern[] = { 0x48, 0x89, 0x5C, 0x24, 0x08, 0x48, 0x89, 0x6C, 0x24, 0x10, 0x48, 0x89, 0x74, 0x24, 0x18, 0x57, 0x48, 0x83, 0xEC, 0x20, 0x48, 0x8B, 0xF9 };
    const char ssl_write_mask[] = "xxxxxxxxxxxxxxxxxxxxxxx";
    
    // SSL_read: 48 89 5C 24 08 48 89 74 24 10 57 48 83 EC 20 48 8B DA
    const unsigned char ssl_read_pattern[] = { 0x48, 0x89, 0x5C, 0x24, 0x08, 0x48, 0x89, 0x74, 0x24, 0x10, 0x57, 0x48, 0x83, 0xEC, 0x20, 0x48, 0x8B, 0xDA };
    const char ssl_read_mask[] = "xxxxxxxxxxxxxxxxxx";

    // SSL_get_servername: 48 83 EC 28 48 8B 49 10 48 85 C9 74 08 48 8B 01 FF 50 18
    const unsigned char ssl_get_servername_pattern[] = { 0x48, 0x83, 0xEC, 0x28, 0x48, 0x8B, 0x49, 0x10, 0x48, 0x85, 0xC9, 0x74, 0x08, 0x48, 0x8B, 0x01, 0xFF, 0x50, 0x18 };
    const char ssl_get_servername_mask[] = "xxxxxxxxxxxxxxxxxxxxx";

    // SSL_new: 48 89 5C 24 08 57 48 83 EC 20 48 8B F9 E8 ?? ?? ?? ?? 48 8B D8
    const unsigned char ssl_new_pattern[] = { 0x48, 0x89, 0x5C, 0x24, 0x08, 0x57, 0x48, 0x83, 0xEC, 0x20, 0x48, 0x8B, 0xF9, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8B, 0xD8 };
    const char ssl_new_mask[] = "xxxxxxxxxxxxx????xxxx";

    // SSL_CTX_set_keylog_callback: 48 89 5C 24 08 48 89 74 24 10 57 48 83 EC 20 48 8B D9 48 8B 49 08
    const unsigned char ssl_ctx_set_keylog_callback_pattern[] = { 0x48, 0x89, 0x5C, 0x24, 0x08, 0x48, 0x89, 0x74, 0x24, 0x10, 0x57, 0x48, 0x83, 0xEC, 0x20, 0x48, 0x8B, 0xD9, 0x48, 0x8B, 0x49, 0x08 };
    const char ssl_ctx_set_keylog_callback_mask[] = "xxxxxxxxxxxxxxxxxxxxxx";


    uintptr_t ssl_write_addr = 0, ssl_get_servername_addr = 0, ssl_read_addr = 0;
    uintptr_t ssl_ctx_set_keylog_callback_addr = 0, ssl_new_addr = 0;

    if (!Real_SSL_write) {
        ssl_write_addr = FindPattern(hTargetModuleForScanning, ssl_write_pattern, ssl_write_mask);
        if (ssl_write_addr) Real_SSL_write = (SSL_write_t)ssl_write_addr;
        else EtwTraceMessage(L"SSL_write pattern not found.");
    }
    if (!Real_SSL_get_servername) {
        ssl_get_servername_addr = FindPattern(hTargetModuleForScanning, ssl_get_servername_pattern, ssl_get_servername_mask);
        if (ssl_get_servername_addr) Real_SSL_get_servername = (SSL_get_servername_t)ssl_get_servername_addr;
        else EtwTraceMessage(L"SSL_get_servername pattern not found.");
    }
    if (!Real_SSL_read) {
        ssl_read_addr = FindPattern(hTargetModuleForScanning, ssl_read_pattern, ssl_read_mask);
        if (ssl_read_addr) Real_SSL_read = (SSL_read_t)ssl_read_addr;
        else EtwTraceMessage(L"SSL_read pattern not found.");
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

    // Attach hooks if functions are found (either by export or pattern)
    bool attachedAnySsl = false;

    if (Real_SSL_write) {
        DetourAttach(&(PVOID&)Real_SSL_write, Mine_SSL_write);
        EtwTraceMessage(L"Attached to SSL_write.");
        attachedAnySsl = true;
    }
    if (Real_SSL_read) {
        DetourAttach(&(PVOID&)Real_SSL_read, Mine_SSL_read);
        EtwTraceMessage(L"Attached to SSL_read.");
        attachedAnySsl = true;
    }
    if (Real_SSL_new) { // Hook SSL_new to enable keylogging
        // Real_SSL_CTX_set_keylog_callback is called by Mine_SSL_new, not hooked itself
        if (Real_SSL_CTX_set_keylog_callback) {
            DetourAttach(&(PVOID&)Real_SSL_new, Mine_SSL_new);
            EtwTraceMessage(L"Attached to SSL_new (for keylogging).");
            attachedAnySsl = true; // Consider this part of SSL setup
        } else {
            EtwTraceMessage(L"SSL_new found, but SSL_CTX_set_keylog_callback not found. Cannot enable keylogging.");
        }
    }
    // Note: SSL_get_servername is used by Mine_SSL_write/read, not hooked itself.
    if (!Real_SSL_get_servername && (Real_SSL_write || Real_SSL_read)) {
         EtwTraceMessage(L"Warning: SSL_write/read hooked but SSL_get_servername not found. Hostname will be missing.");
    }

    if (attachedAnySsl) {
        EtwTraceMessage(L"SSL hooks attached.");
        g_sslHooksInstalled = true;
    } else {
        EtwTraceMessage(L"No SSL functions found/attached. SSL hooks NOT installed.");
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

void InstallHooks() {
    LOG_INFO(L"Hooks", L"Beginning hook installation");
    LOG_INFO_F(L"Hooks", L"Process: %s (PID: %d)", GetProcessName(GetCurrentProcessId()).c_str(), GetCurrentProcessId());
    
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

    if (Real_SSL_write) {
        LOG_DEBUG(L"Hooks", L"Detaching SSL_write");
        DetourDetach(&(PVOID&)Real_SSL_write, Mine_SSL_write);
    }
    if (Real_SSL_read) {
        LOG_DEBUG(L"Hooks", L"Detaching SSL_read");
        DetourDetach(&(PVOID&)Real_SSL_read, Mine_SSL_read);
    }
    if (Real_SSL_new) {
        LOG_DEBUG(L"Hooks", L"Detaching SSL_new");
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
