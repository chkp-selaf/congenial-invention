#include "pipe_client.h"
#include <windows.h>
#include <string>
#include <mutex>
#include <vector>

static HANDLE g_hPipe = INVALID_HANDLE_VALUE;
static std::mutex g_pipeMutex;
constexpr const wchar_t* kPipeName = L"\\\\.\\pipe\\ai-hook";

void PipeClientInit() {
    std::lock_guard<std::mutex> lock(g_pipeMutex);
    if (g_hPipe != INVALID_HANDLE_VALUE) {
        return; // Already initialized
    }

    // Try a few times with delays to avoid overwhelming the pipe server
    for (int attempts = 0; attempts < 3; attempts++) {
        g_hPipe = CreateFileW(
            kPipeName,
            GENERIC_WRITE,
            0,              // no sharing
            NULL,           // default security attributes
            OPEN_EXISTING,  // opens existing pipe
            0,              // default attributes
            NULL);          // no template file

        if (g_hPipe != INVALID_HANDLE_VALUE) {
            OutputDebugStringW(L"Pipe connected successfully.");
            break; // Success
        }

        DWORD error = GetLastError();
        if (error == ERROR_PIPE_BUSY) {
            // Wait for the pipe to be available.
            if (WaitNamedPipeW(kPipeName, 5000)) { // 5-second timeout
                continue; // Try again
            } else {
                OutputDebugStringW(L"WaitNamedPipe timed out.");
            }
        } else if (error == ERROR_FILE_NOT_FOUND) {
            OutputDebugStringW(L"Pipe not found. Collector may not be running.");
        } else {
            OutputDebugStringW(L"Could not open pipe. Unknown error.");
        }

        // Wait before retrying
        Sleep(1000 * (attempts + 1)); // 1s, 2s, 3s delays
    }

    if (g_hPipe == INVALID_HANDLE_VALUE) {
        OutputDebugStringW(L"Failed to connect to pipe after multiple attempts.");
    }
}

void PipeClientShutdown() {
    std::lock_guard<std::mutex> lock(g_pipeMutex);
    if (g_hPipe != INVALID_HANDLE_VALUE) {
        CloseHandle(g_hPipe);
        g_hPipe = INVALID_HANDLE_VALUE;
    }
}

void PipeSendEvent(const CapturedEvent& event) {
    std::lock_guard<std::mutex> lock(g_pipeMutex);
    if (g_hPipe == INVALID_HANDLE_VALUE) {
        return; // No pipe connection, silently drop the event
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
        // Pipe may have been closed, close our handle but don't try to reconnect immediately
        // to avoid loops. The next injection will trigger a new connection attempt.
        OutputDebugStringW(L"Pipe write failed. Closing connection.");
        CloseHandle(g_hPipe);
        g_hPipe = INVALID_HANDLE_VALUE;
    }
}
