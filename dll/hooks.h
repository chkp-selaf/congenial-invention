#pragma once

#define HOOKS_H

#include <windows.h>  // For DWORD
#include "json.h"  // For ApiType and CapturedEvent
#include <string>

// json.h (which defines ApiType and CapturedEvent) should be included
// by files that use these types, like hooks.cpp (often via pipe_client.h).
// No need to redefine or directly include here if hooks.h itself doesn't use them in its declarations.

// Function declarations
void InstallHooks();
void RemoveHooks();
void CreateAndSendEvent(ApiType apiType, const std::wstring& url, const void* data, DWORD dataLength);
void TryGetSslFunctionsFromExports();
void InstallSslHooks();
