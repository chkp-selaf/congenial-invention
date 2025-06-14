#include "json.h"
#include <windows.h>
#include <sstream>
#include <iomanip>
#include <vector>
#include <locale>  // For wstring_convert
#include <codecvt> // For wstring_convert (C++17 deprecated but often available)

// For older compilers that might not have std::from_chars for floating point
#if __cplusplus < 201703L || (!defined(__cpp_lib_to_chars) || __cpp_lib_to_chars < 201611L)
#include <cstdio> // For sprintf with floating point
#endif

// --- Base64 Encoding (from https://stackoverflow.com/a/34571089) ---
static const std::string base64_chars =
             "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
             "abcdefghijklmnopqrstuvwxyz"
             "0123456789+/";

std::string Base64Encode(const unsigned char* data, size_t in_len) {
    std::string ret;
    int i = 0;
    int j = 0;
    unsigned char char_array_3[3];
    unsigned char char_array_4[4];

    while (in_len--) {
        char_array_3[i++] = *(data++);
        if (i == 3) {
            char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
            char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
            char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
            char_array_4[3] = char_array_3[2] & 0x3f;

            for(i = 0; (i <4) ; i++)
                ret += base64_chars[char_array_4[i]];
            i = 0;
        }
    }

    if (i) {
        for(j = i; j < 3; j++)
            char_array_3[j] = '\0';

        char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
        char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
        char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);

        for (j = 0; (j < i + 1); j++)
            ret += base64_chars[char_array_4[j]];

        while((i++ < 3))
            ret += '=';
    }

    return ret;
}

// --- Utility Implementation ---
std::wstring StringToWstring(const std::string& str) {
    if (str.empty()) return std::wstring();
    // Consider using MultiByteToWideChar for more robust Windows-specific conversion
    // For simplicity here, using wstring_convert, but be mindful of its C++17 deprecation
    // and potential locale issues.
    try {
        std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
        return converter.from_bytes(str);
    } catch (const std::range_error& e) {
        // Handle conversion error, e.g., log or return a placeholder
        OutputDebugStringA(("StringToWstring range_error: " + std::string(e.what())).c_str());
        std::wstring result;
        // Fallback: simple ASCII to wide char if conversion fails (lossy)
        result.reserve(str.length());
        for (char c : str) {
            result += static_cast<wchar_t>(static_cast<unsigned char>(c));
        }
        return result;
    }
}

// --- JSON Serialization ---

namespace JsonUtil {
    // Basic JSON string escaping
    std::string EscapeJsonString(const std::wstring& s) {
        std::wstringstream o;
        for (auto c = s.cbegin(); c != s.cend(); c++) {
            switch (*c) {
                case L'\"': o << L"\\\""; break;
                case L'\\': o << L"\\\\"; break;
                case L'\b': o << L"\\b"; break;
                case L'\f': o << L"\\f"; break;
                case L'\n': o << L"\\n"; break;
                case L'\r': o << L"\\r"; break;
                case L'\t': o << L"\\t"; break;
                default:
                    if (L'\x00' <= *c && *c <= L'\x1f') {
                        o << L"\\u" << std::hex << std::setw(4) << std::setfill(L'0') << (int)*c;
                    } else {
                        o << *c;
                    }
            }
        }
        // convert wstring to string
        std::wstring ws = o.str();
        int size_needed = WideCharToMultiByte(CP_UTF8, 0, &ws[0], (int)ws.size(), NULL, 0, NULL, NULL);
        std::string strTo( size_needed, 0 );
        WideCharToMultiByte(CP_UTF8, 0, &ws[0], (int)ws.size(), &strTo[0], size_needed, NULL, NULL);
        return strTo;
    }
}

const char* ApiTypeToString(ApiType type) {
    switch (type) {
        case ApiType::WinHttpSend: return "WinHttpSend";
        case ApiType::WinHttpRead: return "WinHttpRead";
        case ApiType::WebSocketSend: return "WebSocketSend";
        case ApiType::WebSocketReceive: return "WebSocketReceive";
        case ApiType::SslWrite: return "SslWrite";
        case ApiType::SchannelEncrypt: return "SchannelEncrypt";
        case ApiType::SchannelDecrypt: return "SchannelDecrypt";
        case ApiType::ElectronJs: return "ElectronJs";
        case ApiType::SslRead: return "SslRead";
        case ApiType::SslKeyLog: return "SslKeyLog";
        case ApiType::SchannelAcquireCred: return "SchannelAcquireCred";
        default: return "Unknown";
    }
}

std::string CapturedEvent::ToJson() const {
    std::stringstream ss;
    auto time_t = std::chrono::system_clock::to_time_t(timestamp);
    auto tm = *std::gmtime(&time_t);
    std::stringstream ss_timestamp;
    ss_timestamp << std::put_time(&tm, "%Y-%m-%dT%H:%M:%SZ");

    ss << "{";
    ss << "\"timestamp\":\"" << ss_timestamp.str() << "\",";
    ss << "\"processId\":" << processId << ",";
    ss << "\"threadId\":" << threadId << ",";
    ss << "\"apiType\":\"" << ApiTypeToString(apiType) << "\",";
    ss << "\"url\":\"" << JsonUtil::EscapeJsonString(url) << "\""; // url is wstring

    if (!method.empty()) {
        ss << ",\"method\":\"" << JsonUtil::EscapeJsonString(method) << "\""; // method is wstring
    }
    if (status != 0) { // Assuming 0 is default/unset for status
        ss << ",\"status\":" << status;
    }
    // Ensure duration is formatted correctly, e.g., not in scientific notation for small values
    // and only include if it's non-zero (or some other sensible default check)
    if (duration != 0.0) { 
        ss << ",\"duration\":";
        // Temporary buffer for sprintf, as std::to_string can be problematic with precision/locale
        char duration_str[64]; 
        snprintf(duration_str, sizeof(duration_str), "%.3f", duration);
        ss << duration_str;
    }

    // Data is always present, even if empty
    ss << ",\"data\":\"" << Base64Encode(data.data(), data.size()) << "\"";
    ss << "}";
    return ss.str();
}
