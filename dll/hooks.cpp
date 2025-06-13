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
#define SECURITY_WIN32
#include <sspi.h>
#include <schannel.h>

#pragma comment(lib, "secur32.lib")

// --- Function Pointers ---
// WinHTTP
static decltype(&WinHttpSendRequest) Real_WinHttpSendRequest = WinHttpSendRequest;
static decltype(&WinHttpReadData) Real_WinHttpReadData = WinHttpReadData;
static decltype(&WinHttpWebSocketSend) Real_WinHttpWebSocketSend = WinHttpWebSocketSend;
static decltype(&WinHttpWebSocketReceive) Real_WinHttpWebSocketReceive = WinHttpWebSocketReceive;

// OpenSSL/BoringSSL
static SSL_write_t Real_SSL_write = nullptr;
static SSL_get_servername_t Real_SSL_get_servername = nullptr;

// Schannel
static decltype(&EncryptMessage) Real_EncryptMessage = EncryptMessage;
static decltype(&DecryptMessage) Real_DecryptMessage = DecryptMessage;


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
    if (o && ol > 0) {
        DWORD dwUrlLength = 0;
        WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_URL, WINHTTP_HEADER_NAME_BY_INDEX, NULL, &dwUrlLength, WINHTTP_NO_HEADER_INDEX);
        std::vector<wchar_t> urlBuffer(dwUrlLength / sizeof(wchar_t));
        WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_URL, WINHTTP_HEADER_NAME_BY_INDEX, urlBuffer.data(), &dwUrlLength, WINHTTP_NO_HEADER_INDEX);
        CreateAndSendEvent(ApiType::WinHttpSend, std::wstring(urlBuffer.begin(), urlBuffer.end() - 1), o, ol);
    }
    return Real_WinHttpSendRequest(hRequest, h, hl, o, ol, tl, c);
}

BOOL WINAPI Mine_WinHttpReadData(HINTERNET hRequest, LPVOID b, DWORD br, LPDWORD brr) {
    BOOL result = Real_WinHttpReadData(hRequest, b, br, brr);
    if (result && brr && *brr > 0) {
        DWORD dwUrlLength = 0;
        WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_URL, WINHTTP_HEADER_NAME_BY_INDEX, NULL, &dwUrlLength, WINHTTP_NO_HEADER_INDEX);
        std::vector<wchar_t> urlBuffer(dwUrlLength / sizeof(wchar_t));
        WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_URL, WINHTTP_HEADER_NAME_BY_INDEX, urlBuffer.data(), &dwUrlLength, WINHTTP_NO_HEADER_INDEX);
        CreateAndSendEvent(ApiType::WinHttpRead, std::wstring(urlBuffer.begin(), urlBuffer.end() - 1), b, *brr);
    }
    return result;
}

DWORD WINAPI Mine_WinHttpWebSocketSend(HINTERNET h, WINHTTP_WEB_SOCKET_BUFFER_TYPE t, PVOID b, DQNORD l) {
    if (b && l > 0) {
        // URL is not readily available on WebSocket handles, pass empty for now
        CreateAndSendEvent(ApiType::WebSocketSend, L"", b, l);
    }
    return Real_WinHttpWebSocketSend(h, t, b, l);
}

DWORD WINAPI Mine_WinHttpWebSocketReceive(HINTERNET h, PVOID b, DWORD l, LPDWORD br, WINHTTP_WEB_SOCKET_BUFFER_TYPE* t) {
    DWORD result = Real_WinHttpWebSocketReceive(h, b, l, br, t);
    if (result == ERROR_SUCCESS && br && *br > 0) {
        CreateAndSendEvent(ApiType::WebSocketReceive, L"", b, *br);
    }
    return result;
}

// --- BoringSSL Detour ---
int __cdecl Mine_SSL_write(SSL* ssl, const void* buf, int num) {
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
    return Real_SSL_write(ssl, buf, num);
}

// --- Schannel Detours ---
SECURITY_STATUS SEC_ENTRY Mine_EncryptMessage(PCtxtHandle phContext, ULONG fQOP, PSecBufferDesc pMessage, ULONG MessageSeqNo) {
    // Find the data buffer to log it before encryption
    for (ULONG i = 0; i < pMessage->cBuffers; ++i) {
        if (pMessage->pBuffers[i].BufferType == SECBUFFER_DATA) {
            // URL is not available in this context, pass empty
            CreateAndSendEvent(ApiType::SchannelEncrypt, L"", pMessage->pBuffers[i].pvBuffer, pMessage->pBuffers[i].cbBuffer);
            break; // Assume only one data buffer
        }
    }
    return Real_EncryptMessage(phContext, fQOP, pMessage, MessageSeqNo);
}

SECURITY_STATUS SEC_ENTRY Mine_DecryptMessage(PCtxtHandle phContext, PSecBufferDesc pMessage, ULONG MessageSeqNo, PULONG pfQOP) {
    SECURITY_STATUS status = Real_DecryptMessage(phContext, pMessage, MessageSeqNo, pfQOP);
    if (status == SEC_E_OK) {
        // Find the data buffer to log it after decryption
        for (ULONG i = 0; i < pMessage->cBuffers; ++i) {
            if (pMessage->pBuffers[i].BufferType == SECBUFFER_DATA) {
                CreateAndSendEvent(ApiType::SchannelDecrypt, L"", pMessage->pBuffers[i].pvBuffer, pMessage->pBuffers[i].cbBuffer);
                break; // Assume only one data buffer
            }
        }
    }
    return status;
}

// --- Hook Installation ---
void InstallSslHooks() {
    HMODULE hChrome = GetModuleHandle(L"chrome.dll");
    if (!hChrome) {
        OutputDebugStringW(L"chrome.dll not found, skipping SSL hooks.");
        return;
    }

    // These patterns are highly version-specific and for demonstration only.
    // A robust implementation would use more stable signatures or offsets.
    // Example pattern for SSL_write (x64, might need adjustment):
    // 48 89 5C 24 ? 48 89 6C 24 ? 48 89 74 24 ? 57 48 83 EC ? 48 8B F9 48 8B DA
    const unsigned char ssl_write_pattern[] = { 0x48, 0x89, 0x5C, 0x24, 0x08, 0x48, 0x89, 0x6C, 0x24, 0x10, 0x48, 0x89, 0x74, 0x24, 0x18, 0x57, 0x48, 0x83, 0xEC, 0x20, 0x48, 0x8B, 0xF9, 0x48, 0x8B, 0xDA };
    const char ssl_write_mask[] = "xxxx?xxxx?xxxx?xxxxxxxxxxxx";
    
    // Example pattern for SSL_get_servername
    // 48 83 EC ? 48 8B 49 ? 48 85 C9 74 ? 48 8B 01 FF 50 ? 48 83 C4 ? C3
    const unsigned char ssl_get_servername_pattern[] = { 0x48, 0x83, 0xEC, 0x28, 0x48, 0x8B, 0x49, 0x10, 0x48, 0x85, 0xC9, 0x74, 0x08, 0x48, 0x8B, 0x01, 0xFF, 0x50, 0x18, 0x48, 0x83, 0xC4, 0x28, 0xC3 };
    const char ssl_get_servername_mask[] = "xxxx?xxx?xxx?xxxx?xxxx?xx";

    uintptr_t ssl_write_addr = FindPattern(hChrome, ssl_write_pattern, ssl_write_mask);
    uintptr_t ssl_get_servername_addr = FindPattern(hChrome, ssl_get_servername_pattern, ssl_get_servername_mask);

    if (ssl_write_addr && ssl_get_servername_addr) {
        Real_SSL_write = (SSL_write_t)ssl_write_addr;
        Real_SSL_get_servername = (SSL_get_servername_t)ssl_get_servername_addr;
        
        DetourAttach(&(PVOID&)Real_SSL_write, Mine_SSL_write);
        OutputDebugStringW(L"Attached to SSL_write via pattern scan.");
    } else {
        OutputDebugStringW(L"Could not find SSL_write or SSL_get_servername patterns in chrome.dll.");
    }
}

void InstallHooks() {
    OutputDebugStringW(L"Attaching hooks...");
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());

    // WinHTTP
    DetourAttach(&(PVOID&)Real_WinHttpSendRequest, Mine_WinHttpSendRequest);
    DetourAttach(&(PVOID&)Real_WinHttpReadData, Mine_WinHttpReadData);
    DetourAttach(&(PVOID&)Real_WinHttpWebSocketSend, Mine_WinHttpWebSocketSend);
    DetourAttach(&(PVOID&)Real_WinHttpWebSocketReceive, Mine_WinHttpWebSocketReceive);

    // BoringSSL
    InstallSslHooks();

    // Schannel
    DetourAttach(&(PVOID&)Real_EncryptMessage, Mine_EncryptMessage);
    DetourAttach(&(PVOID&)Real_DecryptMessage, Mine_DecryptMessage);

    if (DetourTransactionCommit() != NO_ERROR) {
        OutputDebugStringW(L"Error installing hooks.");
    }
}

void RemoveHooks() {
    OutputDebugStringW(L"Detaching hooks...");
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());

    DetourDetach(&(PVOID&)Real_WinHttpSendRequest, Mine_WinHttpSendRequest);
    DetourDetach(&(PVOID&)Real_WinHttpReadData, Mine_WinHttpReadData);
    DetourDetach(&(PVOID&)Real_WinHttpWebSocketSend, Mine_WinHttpWebSocketSend);
    DetourDetach(&(PVOID&)Real_WinHttpWebSocketReceive, Mine_WinHttpWebSocketReceive);
    if (Real_SSL_write) {
        DetourDetach(&(PVOID&)Real_SSL_write, Mine_SSL_write);
    }

    // Schannel
    DetourDetach(&(PVOID&)Real_EncryptMessage, Mine_EncryptMessage);
    DetourDetach(&(PVOID&)Real_DecryptMessage, Mine_DecryptMessage);

    DetourTransactionCommit();
}
