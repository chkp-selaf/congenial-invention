#include "json.h"
#include <windows.h>
#include <sstream>
#include <iomanip>
#include <vector>

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

// --- JSON Serialization ---

namespace JsonUtil {
    // Basic JSON string escaping
    std::string Escape(const std::wstring& s) {
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
        default: return "Unknown";
    }
}

std::string CapturedEvent::ToJson() const {
    std::stringstream ss;
    auto time_t = std::chrono::system_clock::to_time_t(timestamp);
    auto tm = *std::gmtime(&time_t);

    ss << "{";
    ss << "\"timestamp\":\"" << std::put_time(&tm, "%Y-%m-%dT%H:%M:%SZ") << "\",";
    ss << "\"processId\":" << processId << ",";
    ss << "\"threadId\":" << threadId << ",";
    ss << "\"api\":\"" << ApiTypeToString(apiType) << "\",";
    ss << "\"url\":\"" << JsonUtil::Escape(url) << "\",";
    ss << "\"data_b64\":\"" << Base64Encode(data.data(), data.size()) << "\"";
    ss << "}";
    return ss.str();
}
