#include "pattern_scan.h"
#include <Psapi.h>

// Basic pattern scanner
// A '?' in the mask indicates a wildcard byte
uintptr_t FindPattern(HMODULE module, const unsigned char* pattern, const char* mask) {
    MODULEINFO moduleInfo = {};
    GetModuleInformation(GetCurrentProcess(), module, &moduleInfo, sizeof(MODULEINFO));

    uintptr_t base = (uintptr_t)moduleInfo.lpBaseOfDll;
    uintptr_t size = (uintptr_t)moduleInfo.SizeOfImage;

    size_t patternLength = strlen(mask);

    for (uintptr_t i = 0; i < size - patternLength; i++) {
        bool found = true;
        for (uintptr_t j = 0; j < patternLength; j++) {
            if (mask[j] != '?' && pattern[j] != *(unsigned char*)(base + i + j)) {
                found = false;
                break;
            }
        }
        if (found) {
            return base + i;
        }
    }
    return 0;
}
