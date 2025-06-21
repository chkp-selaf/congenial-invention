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

    // Don't try to connect immediately - the process might not be ready
    // Just mark as not connected and let the first event trigger connection
    OutputDebugStringW(L"[AI-Hook] Pipe client initialized (not connected yet).");
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
    
    // Try to connect if not connected
    if (g_hPipe == INVALID_HANDLE_VALUE) {
        g_hPipe = CreateFileW(
            kPipeName,
            GENERIC_WRITE,
            0,              // no sharing
            NULL,           // default security attributes
            OPEN_EXISTING,  // opens existing pipe
            0,              // default attributes
            NULL);          // no template file

        if (g_hPipe == INVALID_HANDLE_VALUE) {
            // Silently fail - no pipe server running
            return;
        }
        OutputDebugStringW(L"[AI-Hook] Pipe connected on first event.");
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
        OutputDebugStringW(L"[AI-Hook] Pipe write failed. Closing connection.");
        CloseHandle(g_hPipe);
        g_hPipe = INVALID_HANDLE_VALUE;
    }
}
