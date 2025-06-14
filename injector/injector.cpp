#include <windows.h>
#include <tlhelp32.h>
#include <detours.h>
#include <string>
#include <vector>
#include <iostream>
#include <filesystem> // For path manipulation (C++17)
#include <algorithm>

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
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) return false;

    char dllPathA[MAX_PATH];
    WideCharToMultiByte(CP_ACP, 0, dllPath, -1, dllPathA, MAX_PATH, nullptr, nullptr);
    const char* dlls[] = { dllPathA };
    BOOL ok = DetourUpdateProcessWithDll(hProcess, dlls, 1);
    CloseHandle(hProcess);
    return ok == TRUE;
}

// TODO: replace with configurable path or resource
constexpr const wchar_t* kDllPath = L"build\\dll\\Release\\ai_hook.dll";

// Simple wrapper around CreateProcessW + DetourUpdateProcessWithDllW
bool StartProcessAndInject(const std::wstring& cmdline, DWORD* outPid) {
    STARTUPINFOW si{sizeof(si)};
    PROCESS_INFORMATION pi{};

    if (!CreateProcessW(nullptr, const_cast<LPWSTR>(cmdline.c_str()), nullptr, nullptr,
                        FALSE, CREATE_SUSPENDED, nullptr, nullptr, &si, &pi)) {
        std::wcerr << L"CreateProcess failed: " << GetLastError() << std::endl;
        return false;
    }

    char dllPathA[MAX_PATH];
    WideCharToMultiByte(CP_ACP, 0, kDllPath, -1, dllPathA, MAX_PATH, nullptr, nullptr);
    const char* dlls[] = { dllPathA };
    if (!DetourUpdateProcessWithDll(pi.hProcess, dlls, 1)) {
        std::wcerr << L"DetourUpdateProcessWithDll failed: " << GetLastError() << std::endl;
        TerminateProcess(pi.hProcess, 1);
        return false;
    }

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

    // Combine remaining arguments into single command line for CreateProcess
    std::wstring app_cmdline;
    for (int i = firstCmdArg; i < argc; ++i) {
        if (i > firstCmdArg) app_cmdline += L" ";
        app_cmdline += argv[i];
    }

    std::wstring final_cmdline = app_cmdline;
    if (withChildren) {
        wchar_t rawInjectorPath[MAX_PATH];
        if (GetModuleFileNameW(NULL, rawInjectorPath, MAX_PATH) == 0) {
            std::wcerr << L"Failed to get injector path: " << GetLastError() << std::endl;
            return 1; // Or handle error appropriately
        }

        std::filesystem::path injectorPath(rawInjectorPath);
        // Assuming injector is at <project_root>/build/injector/Release/ai_injector.exe
        // And preload.js is at <project_root>/renderer/preload.js
        std::filesystem::path preloadScriptPath = injectorPath.parent_path() / L".." / L".." / L".." / L"renderer" / L"preload.js";
        
        preloadScriptPath = std::filesystem::absolute(preloadScriptPath);
        preloadScriptPath = preloadScriptPath.lexically_normal();

        if (!std::filesystem::exists(preloadScriptPath)){
            std::wcerr << L"Preload script not found at: " << preloadScriptPath.wstring() << std::endl;
            // Decide if this is a fatal error or just a warning
        } else {
            std::wstring preloadArg = L"--preload \"";
            preloadArg += preloadScriptPath.wstring();
            preloadArg += L"\" ";

            final_cmdline.insert(0, preloadArg); // Prepend preload arg to the application's command line
        }
    }

    // Launch main process and inject
    DWORD mainPid = 0;
    if (!StartProcessAndInject(final_cmdline, &mainPid)) return 1;

    if (!withChildren) return 0;

    // Give the target some time to spawn renderer / extension host processes
    Sleep(1500);

    // Recursively collect child processes of the launched target
    std::vector<DWORD> queue{mainPid};
    std::vector<DWORD> allChildren;
    while (!queue.empty()) {
        DWORD parent = queue.back();
        queue.pop_back();
        auto kids = CollectChildPids(parent);
        for (DWORD kid : kids) {
            if (std::find(allChildren.begin(), allChildren.end(), kid) == allChildren.end()) {
                allChildren.push_back(kid);
                queue.push_back(kid); // depth-first traversal to capture nested children
            }
        }
    }

    for (DWORD pid : allChildren) {
        if (InjectIntoProcess(pid, kDllPath)) {
            std::wcout << L"Injected into child PID " << pid << std::endl;
        }
    }
    return 0;
}
