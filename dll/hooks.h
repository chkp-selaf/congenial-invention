#pragma once

#define HOOKS_H

#include <windows.h>  // For DWORD
#include "json.h"  // For ApiType and CapturedEvent
#include <string>
#include <winhttp.h>
#include <evntprov.h>
#include "openssl_types.h"
#include <vector>
#include <chrono>

// json.h (which defines ApiType and CapturedEvent) should be included
// by files that use these types, like hooks.cpp (often via pipe_client.h).
// No need to redefine or directly include here if hooks.h itself doesn't use them in its declarations.

// {5B369564-2403-4633-9122-5B4995A01646}
static const GUID AiTraceProviderId =
{ 0x5b369564, 0x2403, 0x4633, { 0x91, 0x22, 0x5b, 0x49, 0x95, 0xa0, 0x16, 0x46 } };

// ETW helper functions
void EtwRegister();
void EtwUnregister();
void EtwTraceMessage(PCWSTR message);

// Function declarations
void InstallHooks();
void RemoveHooks();
void CreateAndSendEvent(ApiType apiType, const std::wstring& url, const void* data, DWORD dataLength);
void TryGetSslFunctionsFromExports();
void InstallSslHooks();
