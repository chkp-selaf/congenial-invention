#include "hooks.h"
#include "pipe_client.h"
#include "pattern_scan.h"
#include "openssl_types.h"
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
    try {
        if (o && ol > 0) {
            DWORD dwUrlLength = 0;
            WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_URL, WINHTTP_HEADER_NAME_BY_INDEX, NULL, &dwUrlLength, WINHTTP_NO_HEADER_INDEX);
            if (dwUrlLength > 0) {
                std::vector<wchar_t> urlBuffer(dwUrlLength / sizeof(wchar_t));
                WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_URL, WINHTTP_HEADER_NAME_BY_INDEX, urlBuffer.data(), &dwUrlLength, WINHTTP_NO_HEADER_INDEX);
                CreateAndSendEvent(ApiType::WinHttpSend, std::wstring(urlBuffer.begin(), urlBuffer.end() - 1), o, ol);
            }
        }
    } catch (...) {
        EtwTraceMessage(L"Unhandled exception in Mine_WinHttpSendRequest. Passing through.");
    }
    return Real_WinHttpSendRequest(hRequest, h, hl, o, ol, tl, c);
}

BOOL WINAPI Mine_WinHttpReadData(HINTERNET hRequest, LPVOID b, DWORD br, LPDWORD brr) {
    BOOL result = Real_WinHttpReadData(hRequest, b, br, brr);
    try {
        if (result && brr && *brr > 0) {
            DWORD dwUrlLength = 0;
            WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_URL, WINHTTP_HEADER_NAME_BY_INDEX, NULL, &dwUrlLength, WINHTTP_NO_HEADER_INDEX);
            if (dwUrlLength > 0) {
                std::vector<wchar_t> urlBuffer(dwUrlLength / sizeof(wchar_t));
                WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_URL, WINHTTP_HEADER_NAME_BY_INDEX, urlBuffer.data(), &dwUrlLength, WINHTTP_NO_HEADER_INDEX);
                CreateAndSendEvent(ApiType::WinHttpRead, std::wstring(urlBuffer.begin(), urlBuffer.end() - 1), b, *brr);
            }
        }
    } catch (...) {
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
int __cdecl Mine_SSL_write(SSL* ssl, const void* buf, int num) {
    try {
        if (Real_SSL_get_servername && ssl) {
            const char* servername = Real_SSL_get_servername(ssl, 0); // 0 for TLSEXT_NAMETYPE_host_name
            if (servername) {
                // Convert char* to wstring
                int size_needed = MultiByteToWideChar(CP_UTF8, 0, servername, (int)strlen(servername), NULL, 0);
                std::wstring wServername(size_needed, 0);
                MultiByteToWideChar(CP_UTF8, 0, servername, (int)strlen(servername), &wServername[0], size_needed);
                CreateAndSendEvent(ApiType::SslWrite, wServername, buf, num);
            }
        }
    } catch (...) {
        EtwTraceMessage(L"Unhandled exception in Mine_SSL_write. Passing through.");
    }
    return Real_SSL_write(ssl, buf, num);
}

// --- BoringSSL Detour for SSL_read ---
int __cdecl Mine_SSL_read(SSL* ssl, void* buf, int num) {
    int bytes_read = Real_SSL_read(ssl, buf, num);
    try {
        if (bytes_read > 0 && Real_SSL_get_servername && ssl) {
            const char* servername = Real_SSL_get_servername(ssl, 0); // 0 for TLSEXT_NAMETYPE_host_name
            if (servername) {
                std::wstring wServername = StringToWstring(std::string(servername));
                CreateAndSendEvent(ApiType::SslRead, wServername, buf, bytes_read);
            }
        }
    } catch (...) {
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
                    server_name_wstr = StringToWstring(std::string(server_name_cstr));
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

// --- Hook Installation ---
// Helper function to attempt to get SSL function addresses from common module names
void TryGetSslFunctionsFromExports() {
    const wchar_t* commonSslModuleNames[] = {
        L"node.dll",           // For VSCode/Electron's bundled Node.js/BoringSSL
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
            // Try LoadLibrary if not already loaded, though SSL libs are usually pre-loaded by apps using them
            // hMod = LoadLibraryW(moduleName);
            // if (hMod) { /* remember to FreeLibrary if we loaded it and aren't using it */ }
        }

        if (hMod) {
            EtwTraceMessage((std::wstring(L"Checking module for SSL exports: ") + moduleName).c_str());
            if (!Real_SSL_write) Real_SSL_write = (SSL_write_t)GetProcAddress(hMod, "SSL_write");
            if (!Real_SSL_read) Real_SSL_read = (SSL_read_t)GetProcAddress(hMod, "SSL_read");
            if (!Real_SSL_get_servername) Real_SSL_get_servername = (SSL_get_servername_t)GetProcAddress(hMod, "SSL_get_servername");
            if (!Real_SSL_CTX_set_keylog_callback) Real_SSL_CTX_set_keylog_callback = (SSL_CTX_set_keylog_callback_t)GetProcAddress(hMod, "SSL_CTX_set_keylog_callback");
            if (!Real_SSL_new) Real_SSL_new = (SSL_new_t)GetProcAddress(hMod, "SSL_new");
            
            // If we found all essential functions, we can stop searching modules
            // SSL_get_servername is helpful but not strictly essential for keylogging if SSL_CTX_set_keylog_callback and SSL_new are found.
            if (Real_SSL_write && Real_SSL_read && Real_SSL_CTX_set_keylog_callback && Real_SSL_new && Real_SSL_get_servername) {
                EtwTraceMessage(L"Found all SSL functions via GetProcAddress.");
                return;
            }
        }
    }
}

void InstallSslHooks() {
    // First, try to get functions from exports of common SSL libraries
    TryGetSslFunctionsFromExports();

    // If any are still null, fall back to pattern scanning in chrome.dll (or other target module)
    // For now, chrome.dll is the primary target for pattern scanning if exports fail.
    HMODULE hTargetModuleForScanning = GetModuleHandleW(L"chrome.dll"); 
    if (!hTargetModuleForScanning) {
         // If chrome.dll isn't there, and we haven't found functions by export, SSL hooks won't work.
        if (!Real_SSL_write && !Real_SSL_read) { // Check if any essential func is missing
            EtwTraceMessage(L"Target module (e.g., chrome.dll) not found, and SSL functions not found by export. Skipping SSL pattern scan.");
            return;
        }
        // If some were found by export, we might not need to scan chrome.dll
    }

    // Proceed with pattern scanning if functions are not yet found AND hTargetModuleForScanning is valid
    bool needsPatternScan = (!Real_SSL_write || !Real_SSL_read || !Real_SSL_get_servername || !Real_SSL_CTX_set_keylog_callback || !Real_SSL_new) && hTargetModuleForScanning;

    if (needsPatternScan) {
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
    } else {
        EtwTraceMessage(L"No SSL functions found/attached. SSL hooks NOT installed.");
    }
    // DetourTransactionCommit() will be called later in InstallHooks()
}

void InstallHooks() {
    EtwTraceMessage(L"Attaching hooks...");
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());

    // WinHTTP
    DetourAttach(&(PVOID&)Real_WinHttpSendRequest, Mine_WinHttpSendRequest);
    DetourAttach(&(PVOID&)Real_WinHttpReadData, Mine_WinHttpReadData);
    DetourAttach(&(PVOID&)Real_WinHttpWebSocketSend, Mine_WinHttpWebSocketSend);
    DetourAttach(&(PVOID&)Real_WinHttpWebSocketReceive, Mine_WinHttpWebSocketReceive);

    // BoringSSL / OpenSSL
    InstallSslHooks(); // This function now tries GetProcAddress then pattern scanning.

    // Schannel
    DetourAttach(&(PVOID&)Real_EncryptMessage, Mine_EncryptMessage);
    EtwTraceMessage(L"Attached to EncryptMessage.");
    DetourAttach(&(PVOID&)Real_DecryptMessage, Mine_DecryptMessage);
    EtwTraceMessage(L"Attached to DecryptMessage.");
    DetourAttach(&(PVOID&)Real_AcquireCredentialsHandleW, Mine_AcquireCredentialsHandleW);
    EtwTraceMessage(L"Attached to AcquireCredentialsHandleW.");

    // Electron preload hook for PostMessageW
    DetourAttach(&(PVOID&)Real_PostMessageW, Mine_PostMessageW);
    EtwTraceMessage(L"Attached to PostMessageW for Electron preload.");

    DetourTransactionCommit();
    EtwTraceMessage(L"Hooks committed.");
}

void RemoveHooks() {
    EtwTraceMessage(L"Detaching hooks...");
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());

    DetourDetach(&(PVOID&)Real_WinHttpSendRequest, Mine_WinHttpSendRequest);
    DetourDetach(&(PVOID&)Real_WinHttpReadData, Mine_WinHttpReadData);
    DetourDetach(&(PVOID&)Real_WinHttpWebSocketSend, Mine_WinHttpWebSocketSend);
    DetourDetach(&(PVOID&)Real_WinHttpWebSocketReceive, Mine_WinHttpWebSocketReceive);
    // Detach SSL functions if they were hooked
    if (Real_SSL_write) {
        DetourDetach(&(PVOID&)Real_SSL_write, Mine_SSL_write);
        EtwTraceMessage(L"Detached SSL_write.");
    }
    if (Real_SSL_read) {
        DetourDetach(&(PVOID&)Real_SSL_read, Mine_SSL_read);
        EtwTraceMessage(L"Detached SSL_read.");
    }
    if (Real_SSL_new) { // Detach SSL_new if it was hooked
        DetourDetach(&(PVOID&)Real_SSL_new, Mine_SSL_new);
        EtwTraceMessage(L"Detached SSL_new.");
    }
    // Real_SSL_get_servername and Real_SSL_CTX_set_keylog_callback are not hooked, so no detach needed.
    g_processed_ssl_contexts.clear(); // Clear the set of processed contexts

    // Schannel
    DetourDetach(&(PVOID&)Real_EncryptMessage, Mine_EncryptMessage);
    DetourDetach(&(PVOID&)Real_DecryptMessage, Mine_DecryptMessage);
    DetourDetach(&(PVOID&)Real_AcquireCredentialsHandleW, Mine_AcquireCredentialsHandleW);

    // Detach from PostMessageW
    DetourDetach(&(PVOID&)Real_PostMessageW, Mine_PostMessageW);

    DetourTransactionCommit();
    EtwTraceMessage(L"Hooks detached.");
}

BOOL APIENTRY DllMain(HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
) {
    if (DetourIsHelperProcess()) {
        return TRUE;
    }

    switch (ul_reason_for_call) {
        case DLL_PROCESS_ATTACH:
            __try {
                DisableThreadLibraryCalls(hModule);
                
                // Delay initialization to avoid issues with early process startup
                // Some processes may not have all their dependencies loaded yet
                Sleep(100);
                
                EtwRegister();
                EtwTraceMessage(L"ai_hook.dll loaded into process.");
                
                // Initialize pipe client
                PipeClientInit();
                
                // Install hooks
                InstallHooks();
            } __except(EXCEPTION_EXECUTE_HANDLER) {
                // Log but don't fail DLL load
                OutputDebugStringW(L"[AI-Hook] Exception in DllMain, continuing without full initialization.");
            }
            break;
        case DLL_PROCESS_DETACH:
            EtwTraceMessage(L"ai_hook.dll detaching.");
            RemoveHooks();
            PipeClientShutdown();
            EtwUnregister();
            break;
        case DLL_THREAD_ATTACH:
        case DLL_THREAD_DETACH:
            break;
    }
    return TRUE;
}
