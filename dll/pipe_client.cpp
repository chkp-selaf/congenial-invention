#include "pipe_client.h"
#include "logging.h"
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
        LOG_DEBUG(L"PipeClient", L"Already initialized");
        return; // Already initialized
    }

    // Don't try to connect immediately - the process might not be ready
    // Just mark as not connected and let the first event trigger connection
    LOG_INFO(L"PipeClient", L"Pipe client initialized (not connected yet)");
    OutputDebugStringW(L"[AI-Hook] Pipe client initialized (not connected yet).");
}

void PipeClientShutdown() {
    std::lock_guard<std::mutex> lock(g_pipeMutex);
    if (g_hPipe != INVALID_HANDLE_VALUE) {
        LOG_INFO(L"PipeClient", L"Shutting down pipe client");
        CloseHandle(g_hPipe);
        g_hPipe = INVALID_HANDLE_VALUE;
    } else {
        LOG_DEBUG(L"PipeClient", L"Pipe client already shut down");
    }
}

void PipeSendEvent(const CapturedEvent& event) {
    std::lock_guard<std::mutex> lock(g_pipeMutex);
    
    // Try to connect if not connected
    if (g_hPipe == INVALID_HANDLE_VALUE) {
        LOG_DEBUG(L"PipeClient", L"Attempting to connect to named pipe");
        
        g_hPipe = CreateFileW(
            kPipeName,
            GENERIC_WRITE,
            0,              // no sharing
            NULL,           // default security attributes
            OPEN_EXISTING,  // opens existing pipe
            0,              // default attributes
            NULL);          // no template file

        if (g_hPipe == INVALID_HANDLE_VALUE) {
            DWORD error = GetLastError();
            LOG_TRACE_F(L"PipeClient", L"Failed to connect to pipe (error: %d) - collector may not be running", error);
            // Silently fail - no pipe server running
            return;
        }
        LOG_INFO(L"PipeClient", L"Pipe connected successfully on first event");
        OutputDebugStringW(L"[AI-Hook] Pipe connected on first event.");
    }

    std::string json = event.ToJson();
    json += "\n"; // Add newline as a message delimiter
    
    LOG_TRACE_F(L"PipeClient", L"Sending event: API=%d, URL=%s, DataSize=%zu", 
                (int)event.apiType, 
                std::string(event.url.begin(), event.url.end()).c_str(),
                event.data.size());

    DWORD cbWritten;
    BOOL fSuccess = WriteFile(
        g_hPipe,
        json.c_str(),
        (DWORD)json.length(),
        &cbWritten,
        NULL);

    if (!fSuccess) {
        DWORD error = GetLastError();
        LOG_WARN_F(L"PipeClient", L"Pipe write failed (error: %d). Closing connection.", error);
        // Pipe may have been closed, close our handle but don't try to reconnect immediately
        // to avoid loops. The next injection will trigger a new connection attempt.
        OutputDebugStringW(L"[AI-Hook] Pipe write failed. Closing connection.");
        CloseHandle(g_hPipe);
        g_hPipe = INVALID_HANDLE_VALUE;
    } else {
        LOG_TRACE_F(L"PipeClient", L"Successfully sent %d bytes", cbWritten);
    }
}
