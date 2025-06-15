#include <windows.h>
#include <tlhelp32.h>
#include <detours.h>
#include <string>
#include <vector>
#include <iostream>
#include <filesystem> // For path manipulation (C++17)
#include <algorithm>
#include <unordered_set>
#include <chrono>

// Helper to get process name from PID
static std::wstring GetProcessName(DWORD pid) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return L"<unknown>";

    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    if (Process32FirstW(snap, &entry)) {
        do {
            if (entry.th32ProcessID == pid) {
                CloseHandle(snap);
                return std::wstring(entry.szExeFile);
            }
        } while (Process32NextW(snap, &entry));
    }
    CloseHandle(snap);
    return L"<unknown>";
}

// Simple helper to collect all child PIDs of a given parent process
static std::vector<DWORD> CollectChildPids(DWORD parentPid) {
    std::vector<DWORD> children;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return children;

    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    if (Process32FirstW(snap, &entry)) {
        do {
            if (entry.th32ParentProcessID == parentPid) {
                children.push_back(entry.th32ProcessID);
            }
        } while (Process32NextW(snap, &entry));
    }
    CloseHandle(snap);
    return children;
}

static bool InjectIntoProcess(DWORD pid, const wchar_t* dllPath) {
    std::wstring processName = GetProcessName(pid);
    std::wcout << L"[Injector] Attempting injection into PID " << pid << L" (" << processName << L")" << std::endl;
    std::wcout << L"[Injector] Using DLL: " << dllPath << std::endl;
    
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) {
        std::wcerr << L"[Injector] Failed to open process " << pid << L": " << GetLastError() << std::endl;
        return false;
    }

    char dllPathA[MAX_PATH];
    WideCharToMultiByte(CP_ACP, 0, dllPath, -1, dllPathA, MAX_PATH, nullptr, nullptr);
    const char* dlls[] = { dllPathA };
    BOOL ok = DetourUpdateProcessWithDll(hProcess, dlls, 1);
    CloseHandle(hProcess);
    
    if (ok) {
        std::wcout << L"[Injector] ✓ Successfully injected into PID " << pid << L" (" << processName << L")" << std::endl;
    } else {
        std::wcerr << L"[Injector] ✗ Failed to inject into PID " << pid << L" (" << processName << L"): " << GetLastError() << std::endl;
    }
    
    return ok == TRUE;
}

// TODO: replace with configurable path or resource
constexpr const wchar_t* kDllPath = L"build\\dll\\Release\\ai_hook.dll";

// Helper to get absolute DLL path
static std::wstring GetAbsoluteDllPath() {
    wchar_t injectorPath[MAX_PATH];
    if (GetModuleFileNameW(NULL, injectorPath, MAX_PATH) == 0) {
        return L"build\\dll\\Release\\ai_hook.dll"; // fallback to relative
    }
    
    std::filesystem::path dllPath = std::filesystem::path(injectorPath).parent_path()
        / L".." / L".." / L".." / L"build" / L"dll" / L"Release" / L"ai_hook.dll";
    dllPath = std::filesystem::absolute(dllPath).lexically_normal();
    
    if (std::filesystem::exists(dllPath)) {
        return dllPath.wstring();
    }
    
    // Fallback: try relative path
    return L"build\\dll\\Release\\ai_hook.dll";
}

// Simple wrapper around CreateProcessW + DetourUpdateProcessWithDllW
bool StartProcessAndInject(const std::wstring& cmdline, DWORD* outPid) {
    STARTUPINFOW si{sizeof(si)};
    PROCESS_INFORMATION pi{};

    std::wcout << L"[Injector] Creating process..." << std::endl;
    if (!CreateProcessW(nullptr, const_cast<LPWSTR>(cmdline.c_str()), nullptr, nullptr,
                        FALSE, CREATE_SUSPENDED, nullptr, nullptr, &si, &pi)) {
        std::wcerr << L"[Injector] CreateProcess failed: " << GetLastError() << std::endl;
        return false;
    }

    std::wcout << L"[Injector] Process created with PID " << pi.dwProcessId << L", injecting DLL..." << std::endl;
    
    std::wstring absoluteDllPath = GetAbsoluteDllPath();
    std::wcout << L"[Injector] Using DLL: " << absoluteDllPath << std::endl;
    
    char dllPathA[MAX_PATH];
    WideCharToMultiByte(CP_ACP, 0, absoluteDllPath.c_str(), -1, dllPathA, MAX_PATH, nullptr, nullptr);
    const char* dlls[] = { dllPathA };
    if (!DetourUpdateProcessWithDll(pi.hProcess, dlls, 1)) {
        std::wcerr << L"[Injector] DetourUpdateProcessWithDll failed: " << GetLastError() << std::endl;
        TerminateProcess(pi.hProcess, 1);
        return false;
    }

    std::wcout << L"[Injector] ✓ Main process injection successful, resuming..." << std::endl;
    ResumeThread(pi.hThread);
    if (outPid) *outPid = pi.dwProcessId;

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return true;
}

int wmain(int argc, wchar_t* argv[]) {
    if (argc < 2) {
        std::wcerr << L"Usage: ai_injector [--with-children] <command line>" << std::endl;
        return 1;
    }

    bool withChildren = false;
    int firstCmdArg = 1;
    if (std::wstring_view(argv[1]) == L"--with-children") {
        withChildren = true;
        firstCmdArg = 2;
        if (argc < 3) {
            std::wcerr << L"Expected command line after --with-children" << std::endl;
            return 1;
        }
    }

    // The executable path is the first argument after options.
    std::wstring executable_path = argv[firstCmdArg];

    // Build the rest of the arguments string.
    std::wstring arguments;
    if (withChildren) {
        // Find preload.js relative to the injector's location.
        wchar_t raw_injector_path[MAX_PATH];
        if (GetModuleFileNameW(NULL, raw_injector_path, MAX_PATH) > 0) {
            std::filesystem::path preload_script_path = std::filesystem::path(raw_injector_path).parent_path() 
                / L".." / L".." / L".." / L"renderer" / L"preload.js";
            preload_script_path = std::filesystem::absolute(preload_script_path).lexically_normal();

            if (std::filesystem::exists(preload_script_path)) {
                arguments += L" --preload \"" + preload_script_path.wstring() + L"\"";
                std::wcout << L"[Injector] Using preload script: " << preload_script_path.wstring() << std::endl;
            } else {
                std::wcerr << L"[Injector] Preload script not found at: " << preload_script_path.wstring() << std::endl;
            }
        }
    }

    // Append any original arguments that came after the executable path.
    for (int i = firstCmdArg + 1; i < argc; ++i) {
        arguments += L" ";
        arguments += argv[i];
    }

    // For CreateProcess, the command line must start with the executable.
    // We quote the executable path to handle spaces correctly.
    std::wstring final_cmdline = L"\"" + executable_path + L"\"" + arguments;

    std::wcout << L"[Injector] Launching: " << final_cmdline << std::endl;
    // Launch main process and inject
    DWORD mainPid = 0;
    if (!StartProcessAndInject(final_cmdline, &mainPid)) return 1;

    if (!withChildren) {
        std::wcout << L"[Injector] Main process launched successfully. Not monitoring children." << std::endl;
        return 0;
    }

    // Monitor for new child processes for ~30 seconds after launch
    std::unordered_set<DWORD> injected{ mainPid };
    constexpr int kWatchSeconds = 30;
    constexpr int kPollIntervalMs = 1000;

    std::wcout << L"[Injector] Monitoring for child processes for " << kWatchSeconds << L" seconds..." << std::endl;

    auto injectDescendants = [&](DWORD rootPid) {
        std::vector<DWORD> queue{ rootPid };
        while (!queue.empty()) {
            DWORD parent = queue.back();
            queue.pop_back();
            auto kids = CollectChildPids(parent);
            for (DWORD kid : kids) {
                if (injected.insert(kid).second) { // newly discovered
                    if (InjectIntoProcess(kid, GetAbsoluteDllPath().c_str())) {
                        // Success already logged in InjectIntoProcess
                    }
                }
                queue.push_back(kid);
            }
        }
    };

    auto startTime = std::chrono::steady_clock::now();
    int elapsed = 0;
    int lastChildCount = 1; // Start with main process
    
    while (elapsed < kWatchSeconds * 1000) {
        injectDescendants(mainPid);
        
        // Log progress every 5 seconds or when child count changes
        if (elapsed % 5000 == 0 || injected.size() != lastChildCount) {
            std::wcout << L"[Injector] " << elapsed/1000 << L"s elapsed, " << injected.size() << L" processes injected" << std::endl;
            lastChildCount = injected.size();
        }
        
        Sleep(kPollIntervalMs);
        elapsed += kPollIntervalMs;
    }
    
    std::wcout << L"[Injector] Monitoring complete. Total processes injected: " << injected.size() << std::endl;
    return 0;
}
