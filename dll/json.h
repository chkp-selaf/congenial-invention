#pragma once

#include <string>
#include <vector>
#include <chrono>
#include <cstdint>

// --- Base64 Encoding ---
std::string Base64Encode(const unsigned char* data, size_t in_len);

// --- Utility --- 
std::wstring StringToWstring(const std::string& str);

// --- JSON Event Structure ---

enum class ApiType {
    Unknown,
    WinHttpSend,
    WinHttpRead,
    WebSocketSend,
    WebSocketReceive,
    SslWrite,
    SchannelEncrypt,
    SchannelDecrypt,
    ElectronJs, // For messages from preload.js
    SslRead,
    SslKeyLog, // For SSL key log entries
    SchannelAcquireCred // For AcquireCredentialsHandle events
};

const char* ApiTypeToString(ApiType type);

struct CapturedEvent {
    std::chrono::system_clock::time_point timestamp;
    uint32_t processId;
    uint32_t threadId;
    ApiType apiType;
    std::wstring url;
    std::vector<unsigned char> data;

    // Optional fields for JS events or richer context
    std::wstring method; // e.g., GET, POST for fetch
    int status = 0;      // e.g., 200, 404 for fetch
    double duration = 0.0; // ms for fetch

    std::string ToJson() const;
};
