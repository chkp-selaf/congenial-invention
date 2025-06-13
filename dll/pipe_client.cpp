#include "pipe_client.h"
#include <windows.h>
#include <string>
#include <mutex>
#include <vector>

static HANDLE g_hPipe = INVALID_HANDLE_VALUE;
static std::mutex g_pipeMutex;
constexpr const wchar_t* kPipeName = L"\\\\.\\pipe\\ai-hook";

void PipeInitialize() {
    std::lock_guard<std::mutex> lock(g_pipeMutex);
    if (g_hPipe != INVALID_HANDLE_VALUE) {
        return; // Already initialized
    }

    while (true) {
        g_hPipe = CreateFileW(
            kPipeName,
            GENERIC_WRITE,
            0,              // no sharing
            NULL,           // default security attributes
            OPEN_EXISTING,  // opens existing pipe
            0,              // default attributes
            NULL);          // no template file

        if (g_hPipe != INVALID_HANDLE_VALUE) {
            break; // Success
        }

        // Exit if an error other than "not found" occurs.
        if (GetLastError() != ERROR_PIPE_BUSY) {
            // Log error (can't use pipe logger here!)
            OutputDebugStringW(L"Could not open pipe. GLE=");
            return;
        }

        // Wait for the pipe to be available.
        if (!WaitNamedPipeW(kPipeName, 20000)) { // 20-second timeout
            OutputDebugStringW(L"WaitNamedPipe timed out.");
            return;
        }
    }
}

void PipeShutdown() {
    std::lock_guard<std::mutex> lock(g_pipeMutex);
    if (g_hPipe != INVALID_HANDLE_VALUE) {
        CloseHandle(g_hPipe);
        g_hPipe = INVALID_HANDLE_VALUE;
    }
}

void PipeSendEvent(const CapturedEvent& event) {
    std::lock_guard<std::mutex> lock(g_pipeMutex);
    if (g_hPipe == INVALID_HANDLE_VALUE) {
        return;
    }

    std::string json = event.ToJson();
    json += "\n"; // Add newline as a message delimiter

    DWORD cbWritten;
    BOOL fSuccess = WriteFile(
        g_hPipe,
        json.c_str(),
        (DWORD)json.length(),
        &cbWritten,
        NULL);

    if (!fSuccess) {
        // Pipe may have been closed, try to reconnect
        PipeShutdown();
        PipeInitialize();
    }
}
