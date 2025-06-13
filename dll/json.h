#pragma once

#include <string>
#include <vector>
#include <chrono>
#include <cstdint>

// --- Base64 Encoding ---
std::string Base64Encode(const unsigned char* data, size_t in_len);

// --- JSON Event Structure ---

enum class ApiType {
    Unknown,
    WinHttpSend,
    WinHttpRead,
    WebSocketSend,
    WebSocketReceive
};

const char* ApiTypeToString(ApiType type);

struct CapturedEvent {
    std::chrono::system_clock::time_point timestamp;
    uint32_t processId;
    uint32_t threadId;
    ApiType apiType;
    std::wstring url;
    std::vector<unsigned char> data;

    std::string ToJson() const;
};
