#pragma once

#include <windows.h>
#include <vector>

// Finds a pattern in a module's memory
uintptr_t FindPattern(HMODULE module, const unsigned char* pattern, const char* mask);
