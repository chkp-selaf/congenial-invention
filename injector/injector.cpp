#include <windows.h>
#include <tlhelp32.h>
#include <detours.h>
#include <string>
#include <winternl.h> // NtQueryInformationProcess
#include <vector>
#include <iostream>
#include <filesystem> // For path manipulation (C++17)
#include <algorithm>
#include <unordered_set>
#include <chrono>
#include <fstream>      // For std::ifstream
#include <processthreadsapi.h> // For IsWow64Process2
#include "nlohmann/json.hpp" // For parsing config
#include <sstream>
#include <regex>
#include <psapi.h>
#include <iomanip>
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "psapi.lib")

// Define if not available in older SDKs
#ifndef PROCESSOR_ARCHITECTURE_ARM64
#define PROCESSOR_ARCHITECTURE_ARM64 12
#endif

// Simple logging for injector
static void LogInjector(const std::wstring& level, const std::wstring& message) {
    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);
    
    wchar_t timeBuffer[100];
    struct tm timeinfo;
    localtime_s(&timeinfo, &time_t);
    wcsftime(timeBuffer, sizeof(timeBuffer) / sizeof(wchar_t), L"%Y-%m-%d %H:%M:%S", &timeinfo);
    
    std::wcout << L"[" << timeBuffer << L"] [" << level << L"] " << message << std::endl;
    std::wcout.flush();
    
    // Also log to debug output
    std::wstringstream debugMsg;
    debugMsg << L"[AI-Injector] [" << level << L"] " << message;
    OutputDebugStringW(debugMsg.str().c_str());
}

// --- Globals for Configuration ---
static std::unordered_set<std::wstring> g_allowList;
static bool g_configLoaded = false;

// Helper to get a descriptive string for a machine architecture type
static std::string MachineTypeToString(WORD machine) {
    switch (machine) {
        case IMAGE_FILE_MACHINE_I386:  return "x86";
        case IMAGE_FILE_MACHINE_AMD64: return "x64 (AMD64)";
        case IMAGE_FILE_MACHINE_ARM64: return "ARM64";
        case IMAGE_FILE_MACHINE_ARM:   return "ARM";
        default: return "Unknown";
    }
}

// Get PE machine type by reading the file directly
static WORD GetPeMachineFromFile(const std::wstring& path) {
    std::ifstream file(path, std::ios::binary);
    if (!file) {
        std::wcout << L"[DEBUG] Cannot open file: " << path << std::endl;
        return 0;
    }
    
    // Read DOS header
    IMAGE_DOS_HEADER dosHeader{};
    file.read(reinterpret_cast<char*>(&dosHeader), sizeof(dosHeader));
    if (!file || dosHeader.e_magic != IMAGE_DOS_SIGNATURE) {
        std::wcout << L"[DEBUG] Invalid DOS header in: " << path << std::endl;
        return 0;
    }
    
    // Seek to NT headers
    file.seekg(dosHeader.e_lfanew, std::ios::beg);
    if (!file) {
        std::wcout << L"[DEBUG] Cannot seek to NT headers in: " << path << std::endl;
        return 0;
    }
    
    // Read NT headers
    IMAGE_NT_HEADERS ntHeaders{};
    file.read(reinterpret_cast<char*>(&ntHeaders), sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER));
    if (!file || ntHeaders.Signature != IMAGE_NT_SIGNATURE) {
        std::wcout << L"[DEBUG] Invalid NT signature in: " << path << std::endl;
        return 0;
    }
    
    WORD machine = ntHeaders.FileHeader.Machine;
    std::wcout << L"[DEBUG] File " << path << L" has machine type: 0x" 
              << std::hex << machine << std::dec 
              << L" (" << MachineTypeToString(machine).c_str() << L")" << std::endl;
    
    return machine;
}

// Gets the architecture of a running process. Returns 0 on failure.
static WORD GetProcessArchitecture(HANDLE hProcess) {
    USHORT processMachine = 0;
    USHORT nativeMachine = 0;
    BOOL result = IsWow64Process2(hProcess, &processMachine, &nativeMachine);
    
    std::wcout << L"[DEBUG] IsWow64Process2 result: " << result 
              << L", processMachine: 0x" << std::hex << processMachine 
              << L", nativeMachine: 0x" << std::hex << nativeMachine << std::dec << std::endl;
    
    if (result) {
        // If processMachine is IMAGE_FILE_MACHINE_UNKNOWN (0), it means the process
        // is running natively on the system. But we need to check what the actual
        // architecture of the process is, not what the native system is.
        
        // For x64 processes on ARM64 Windows, processMachine will be IMAGE_FILE_MACHINE_AMD64
        // For ARM64 processes on ARM64 Windows, processMachine will be IMAGE_FILE_MACHINE_UNKNOWN
        
        if (processMachine != IMAGE_FILE_MACHINE_UNKNOWN) {
            // Process is running under emulation/WOW
            std::wcout << L"[DEBUG] Process is emulated, returning processMachine" << std::endl;
            return processMachine;
        }
        
        // Process is running natively, but we need to determine its actual architecture
        // by reading the PE header
        std::wcout << L"[DEBUG] Process is native, checking PE header..." << std::endl;
    }
    
    // Read PE header directly to get the actual architecture
    std::wcout << L"[DEBUG] Reading PE header directly..." << std::endl;
    
    // Get the base address of the process
    HMODULE hMods[1024];
    DWORD cbNeeded;
    if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
        if (cbNeeded > 0) {
            // Read DOS header
            IMAGE_DOS_HEADER dosHeader;
            SIZE_T bytesRead;
            if (ReadProcessMemory(hProcess, hMods[0], &dosHeader, sizeof(dosHeader), &bytesRead)) {
                if (dosHeader.e_magic == IMAGE_DOS_SIGNATURE) {
                    // Read NT headers
                    IMAGE_NT_HEADERS ntHeaders;
                    LPVOID ntHeaderAddr = (LPBYTE)hMods[0] + dosHeader.e_lfanew;
                    if (ReadProcessMemory(hProcess, ntHeaderAddr, &ntHeaders, sizeof(ntHeaders), &bytesRead)) {
                        if (ntHeaders.Signature == IMAGE_NT_SIGNATURE) {
                            std::wcout << L"[DEBUG] PE header machine type: 0x" << std::hex << ntHeaders.FileHeader.Machine << std::dec << std::endl;
                            return ntHeaders.FileHeader.Machine;
                        }
                    }
                }
            }
        }
    }
    
    return 0; // Failed to get architecture
}

// Gets the architecture of the current injector process based on compile-time macros.
static WORD GetInjectorArchitecture() {
#if defined(_M_AMD64)
    return IMAGE_FILE_MACHINE_AMD64;
#elif defined(_M_ARM64)
    return IMAGE_FILE_MACHINE_ARM64;
#elif defined(_M_IX86)
    return IMAGE_FILE_MACHINE_I386;
#else
    return 0; // Unknown architecture
#endif
}

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

// Helper to load config from json file
static void LoadConfig() {
    wchar_t injectorPath[MAX_PATH];
    if (GetModuleFileNameW(NULL, injectorPath, MAX_PATH) == 0) {
        std::wcerr << L"[Injector] Could not get injector path. Allow-list will not be used." << std::endl;
        std::wcerr.flush();
        return;
    }

    std::filesystem::path configPath = std::filesystem::path(injectorPath).parent_path() / L".." / L"config" / L"aiti_config.json";
    configPath = std::filesystem::absolute(configPath).lexically_normal();
    
    if (!std::filesystem::exists(configPath)) {
        std::wcerr << L"[Injector] Config file not found at " << configPath << ". All processes will be allowed." << std::endl;
        std::wcerr.flush();
        return;
    }

    std::ifstream configFile(configPath);
    if (!configFile.is_open()) {
        std::wcerr << L"[Injector] Could not open config file. All processes will be allowed." << std::endl;
        std::wcerr.flush();
        return;
    }

    try {
        nlohmann::json configJson = nlohmann::json::parse(configFile);
        if (configJson.contains("process_allow_list")) {
            for (const auto& item : configJson["process_allow_list"]) {
                std::string s = item.get<std::string>();
                std::wstring ws(s.begin(), s.end());
                g_allowList.insert(ws);
            }
            std::wcout << L"[Injector] Loaded " << g_allowList.size() << L" processes into the allow-list." << std::endl;
            std::wcout.flush();
        }
    } catch (const nlohmann::json::parse_error& e) {
        std::wcerr << L"[Injector] Failed to parse config file: " << e.what() << ". All processes will be allowed." << std::endl;
        std::wcerr.flush();
        return;
    }
    
    g_configLoaded = true;
}

// Simple helper to collect all child PIDs of a given parent process
// Helper to get full command line of a process (best-effort). Returns empty string on failure.
static std::wstring GetProcessCommandLine(DWORD pid) {
    std::wstring result;
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProcess) return result;

    // NtQueryInformationProcess -> PROCESS_BASIC_INFORMATION to get PEB address
    PROCESS_BASIC_INFORMATION pbi{};
    ULONG returned = 0;
    using _NtQueryInformationProcess = NTSTATUS(WINAPI*)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
    static auto NtQueryInformationProcess = reinterpret_cast<_NtQueryInformationProcess>(
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationProcess"));
    if (!NtQueryInformationProcess) { CloseHandle(hProcess); return result; }

    if (NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), &returned) != 0) {
        CloseHandle(hProcess);
        return result;
    }

    // Read RTL_USER_PROCESS_PARAMETERS pointer from PEB
    PEB peb{};
    SIZE_T bytesRead = 0;
    if (!ReadProcessMemory(hProcess, pbi.PebBaseAddress, &peb, sizeof(peb), &bytesRead)) {
        CloseHandle(hProcess);
        return result;
    }

    RTL_USER_PROCESS_PARAMETERS params{};
    if (!ReadProcessMemory(hProcess, peb.ProcessParameters, &params, sizeof(params), &bytesRead)) {
        CloseHandle(hProcess);
        return result;
    }

    // CommandLine is UNICODE_STRING {Length, MaximumLength, Buffer}
    if (params.CommandLine.Length == 0 || !params.CommandLine.Buffer) {
        CloseHandle(hProcess);
        return result;
    }

    std::vector<wchar_t> buffer(params.CommandLine.Length / sizeof(wchar_t) + 1);
    if (!ReadProcessMemory(hProcess, params.CommandLine.Buffer, buffer.data(), params.CommandLine.Length, &bytesRead)) {
        CloseHandle(hProcess);
        return result;
    }
    buffer[params.CommandLine.Length / sizeof(wchar_t)] = L'\0';
    result.assign(buffer.data());
    CloseHandle(hProcess);
    return result;
}

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

    // --- Allow-list Check ---
    if (g_configLoaded && !g_allowList.empty()) {
        if (g_allowList.find(processName) == g_allowList.end()) {
            LogInjector(L"INFO", L"Skipping non-allowed process: " + processName);
            std::wcout << L"[Injector] Skipping non-allowed process: " << processName << std::endl;
            return false; // Not an error, just skipping
        }
    }
    
    LogInjector(L"INFO", L"Attempting injection into PID " + std::to_wstring(pid) + L" (" + processName + L")");
    LogInjector(L"DEBUG", L"Using DLL: " + std::wstring(dllPath));
    
    std::wcout << L"[Injector] Attempting injection into PID " << pid << L" (" << processName << L")" << std::endl;
    std::wcout << L"[Injector] Using DLL: " << dllPath << std::endl;
    
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) {
        DWORD error = GetLastError();
        LogInjector(L"ERROR", L"Failed to open process " + std::to_wstring(pid) + L": " + std::to_wstring(error));
        std::wcerr << L"[Injector] Failed to open process " << pid << L": " << error << std::endl;
        return false;
    }
    
    // Check process architecture
    WORD targetArch = GetProcessArchitecture(hProcess);
    if (targetArch != 0) {
        LogInjector(L"DEBUG", L"Target process architecture: " + std::wstring(MachineTypeToString(targetArch).begin(), MachineTypeToString(targetArch).end()));
    }

    char dllPathA[MAX_PATH];
    WideCharToMultiByte(CP_ACP, 0, dllPath, -1, dllPathA, MAX_PATH, nullptr, nullptr);
    const char* dlls[] = { dllPathA };
    
    LogInjector(L"DEBUG", L"Calling DetourUpdateProcessWithDll...");
    BOOL ok = DetourUpdateProcessWithDll(hProcess, dlls, 1);
    DWORD detourError = GetLastError();
    CloseHandle(hProcess);
    
    if (ok) {
        LogInjector(L"INFO", L"✓ Successfully injected into PID " + std::to_wstring(pid) + L" (" + processName + L")");
        std::wcout << L"[Injector] ✓ Successfully injected into PID " << pid << L" (" << processName << L")" << std::endl;
    } else {
        LogInjector(L"ERROR", L"✗ Failed to inject into PID " + std::to_wstring(pid) + L" (" + processName + L"): " + std::to_wstring(detourError));
        std::wcerr << L"[Injector] ✗ Failed to inject into PID " << pid << L" (" << processName << L"): " << detourError << std::endl;
    }
    
    return ok == TRUE;
}

// Helper to get absolute DLL path, matching the injector's build configuration.
static std::wstring GetAbsoluteDllPath() {
    // Detect build configuration of this injector.
#ifdef _DEBUG
    constexpr const wchar_t* kConfig = L"Debug";
#else
    constexpr const wchar_t* kConfig = L"Release";
#endif

#ifdef _DEBUG
    std::wcout << L"[Injector] (debug) Resolving DLL path for " << kConfig << L" build..." << std::endl;
#endif

    std::vector<std::filesystem::path> candidates;

    // 1. Based on injector location inside build_vs/<component>/<config>
    wchar_t injectorPath[MAX_PATH];
    if (GetModuleFileNameW(NULL, injectorPath, MAX_PATH) != 0) {
        std::filesystem::path base = std::filesystem::path(injectorPath).parent_path();
        
        // For build_x64/injector/Release/ai_injector.exe
        candidates.push_back(base.parent_path().parent_path() / L"dll" / kConfig / L"ai_hook.dll");
        
        // For build_vs/injector/Release/ai_injector.exe
        candidates.push_back(base.parent_path().parent_path() / L"dll" / kConfig / L"ai_hook.dll");
        
        // Non build_vs variant (build/)
        candidates.push_back(base.parent_path().parent_path().parent_path() / L"build" / L"dll" / kConfig / L"ai_hook.dll");
    }

    // 2. Same directory as injector
    candidates.push_back(std::filesystem::path(L"ai_hook.dll"));

    // 3. Common relative paths
    candidates.push_back(std::filesystem::path(L"build_vs") / L"dll" / kConfig / L"ai_hook.dll");
    candidates.push_back(std::filesystem::path(L"build") / L"dll" / kConfig / L"ai_hook.dll");
    candidates.push_back(std::filesystem::path(L"build_x64") / L"dll" / kConfig / L"ai_hook.dll");

    for (const auto& p : candidates) {
        std::error_code ec;
        auto full = std::filesystem::absolute(p, ec);
        if (!ec && std::filesystem::exists(full)) {
#ifdef _DEBUG
            std::wcout << L"[Injector] (debug) Found DLL candidate: " << full << std::endl;
#endif
            return full.lexically_normal().wstring();
        } else {
#ifdef _DEBUG
            std::wcout << L"[Injector] (debug) Candidate not found: " << p << std::endl;
#endif
        }
    }

    // Return first candidate even if missing
    return candidates.front().wstring();
}

static std::wstring Win32ErrorMessage(DWORD code)
{
    LPWSTR buf = nullptr;
    DWORD len = FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                               nullptr, code, 0, (LPWSTR)&buf, 0, nullptr);
    std::wstring msg = (len && buf) ? std::wstring(buf, len) : L"<no message>";
    if (buf) LocalFree(buf);
    // Trim trailing newlines
    while (!msg.empty() && (msg.back() == L'\r' || msg.back() == L'\n')) msg.pop_back();
    return msg;
}

static void LogCreateProcessDiagnostics(const std::wstring& cmdline, DWORD errorCode)
{
    std::wcerr << L"[Injector] ===== CreateProcess diagnostics =====" << std::endl;

    std::wcerr << L"  Error code: " << errorCode << L" (" << Win32ErrorMessage(errorCode) << L")" << std::endl;
    std::wcerr << L"  Full command line: " << cmdline << std::endl;

    // Current working directory
    wchar_t cwdBuf[MAX_PATH];
    if (GetCurrentDirectoryW(MAX_PATH, cwdBuf)) {
        std::wcerr << L"  Working directory: " << cwdBuf << std::endl;
    }

    // Extract executable token
    std::wstring exeToken;
    {
        size_t start = 0;
        while (start < cmdline.size() && iswspace(cmdline[start])) ++start;
        if (start >= cmdline.size()) goto afterToken;
        if (cmdline[start] == L'\"') {
            size_t end = cmdline.find(L'\"', start + 1);
            exeToken = cmdline.substr(start + 1, end != std::wstring::npos ? end - start - 1 : std::wstring::npos);
        } else {
            size_t endSpace = cmdline.find(L' ', start);
            exeToken = cmdline.substr(start, endSpace - start);
        }
    }
afterToken:
    if (!exeToken.empty()) {
        std::wcerr << L"  Executable token: " << exeToken << std::endl;

        // Check if file exists as-is (absolute or relative)
        std::error_code ec;
        auto absPath = std::filesystem::absolute(exeToken, ec);
        if (!ec && std::filesystem::exists(absPath)) {
            std::wcerr << L"  -> File exists at: " << absPath << std::endl;
        } else {
            std::wcerr << L"  -> File NOT found at token path." << std::endl;

            // If token has no path separators, try looking along PATH
            if (exeToken.find(L'\\') == std::wstring::npos && exeToken.find(L'/') == std::wstring::npos) {
                wchar_t found[MAX_PATH];
                if (SearchPathW(nullptr, exeToken.c_str(), L".exe", MAX_PATH, found, nullptr) > 0) {
                    std::wcerr << L"  -> Found via PATH at: " << found << std::endl;
                } else {
                    std::wcerr << L"  -> Not found via PATH." << std::endl;
                }
            }
        }
    }

    // Dump PATH env var (shortened if huge)
    DWORD needed = GetEnvironmentVariableW(L"PATH", nullptr, 0);
    if (needed) {
        std::wstring pathEnv(needed, L'\0');
        GetEnvironmentVariableW(L"PATH", pathEnv.data(), needed);
        pathEnv.resize(needed - 1);
        if (pathEnv.size() > 300) {
            pathEnv = pathEnv.substr(0, 300) + L"...";
        }
        std::wcerr << L"  PATH: " << pathEnv << std::endl;
    }

    std::wcerr << L"[Injector] =====================================" << std::endl;
}

// Manual DLL injection using CreateRemoteThread
bool InjectDllManually(HANDLE hProcess, const wchar_t* dllPath) {
    std::wcout << L"[Injector] Attempting manual injection using CreateRemoteThread..." << std::endl;
    std::wcout.flush();
    
    // Allocate memory in the target process for the DLL path
    size_t dllPathSize = (wcslen(dllPath) + 1) * sizeof(wchar_t);
    LPVOID remoteDllPath = VirtualAllocEx(hProcess, NULL, dllPathSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    
    if (!remoteDllPath) {
        std::wcerr << L"[Injector] VirtualAllocEx failed: " << GetLastError() << std::endl;
        std::wcerr.flush();
        return false;
    }
    
    // Write the DLL path to the allocated memory
    SIZE_T written;
    if (!WriteProcessMemory(hProcess, remoteDllPath, dllPath, dllPathSize, &written)) {
        std::wcerr << L"[Injector] WriteProcessMemory failed: " << GetLastError() << std::endl;
        std::wcerr.flush();
        VirtualFreeEx(hProcess, remoteDllPath, 0, MEM_RELEASE);
        return false;
    }
    
    // Get the address of LoadLibraryW in kernel32.dll
    HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
    if (!hKernel32) {
        std::wcerr << L"[Injector] GetModuleHandle(kernel32.dll) failed" << std::endl;
        std::wcerr.flush();
        VirtualFreeEx(hProcess, remoteDllPath, 0, MEM_RELEASE);
        return false;
    }
    
    LPTHREAD_START_ROUTINE loadLibraryAddr = (LPTHREAD_START_ROUTINE)GetProcAddress(hKernel32, "LoadLibraryW");
    if (!loadLibraryAddr) {
        std::wcerr << L"[Injector] GetProcAddress(LoadLibraryW) failed" << std::endl;
        std::wcerr.flush();
        VirtualFreeEx(hProcess, remoteDllPath, 0, MEM_RELEASE);
        return false;
    }
    
    // Create a remote thread to call LoadLibraryW
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, loadLibraryAddr, remoteDllPath, 0, NULL);
    if (!hThread) {
        std::wcerr << L"[Injector] CreateRemoteThread failed: " << GetLastError() << std::endl;
        std::wcerr.flush();
        VirtualFreeEx(hProcess, remoteDllPath, 0, MEM_RELEASE);
        return false;
    }
    
    // Wait for the thread to complete
    std::wcout << L"[Injector] Waiting for remote thread to complete..." << std::endl;
    std::wcout.flush();
    WaitForSingleObject(hThread, INFINITE);
    
    // Get the exit code (which should be the HMODULE of the loaded DLL)
    DWORD exitCode;
    GetExitCodeThread(hThread, &exitCode);
    CloseHandle(hThread);
    
    // Clean up
    VirtualFreeEx(hProcess, remoteDllPath, 0, MEM_RELEASE);
    
    if (exitCode != 0) {
        std::wcout << L"[Injector] LoadLibraryW returned: 0x" << std::hex << exitCode << std::dec << std::endl;
        std::wcout.flush();
        return true;
    } else {
        std::wcerr << L"[Injector] LoadLibraryW failed in target process" << std::endl;
        std::wcerr.flush();
        return false;
    }
}

// Simple wrapper around CreateProcessW + DetourUpdateProcessWithDllW
bool StartProcessAndInject(const std::wstring& commandLine, const std::wstring& dllPath, bool waitForExit, bool withChildren) {
    std::wcout << L"[Injector] Launching: \"" << commandLine << L"\"" << std::endl;

    // === Pre-flight Architecture Check ===
    // Try to determine the target architecture before launching
    WORD injectorArch = GetInjectorArchitecture();
    WORD targetArch = IMAGE_FILE_MACHINE_UNKNOWN;
    
    // Extract the executable path from the command line
    std::wstring exePath;
    if (!commandLine.empty() && commandLine.front() == L'"') {
        // Quoted path
        size_t endQuote = commandLine.find(L'"', 1);
        if (endQuote != std::wstring::npos) {
            exePath = commandLine.substr(1, endQuote - 1);
        }
    } else {
        // Unquoted path - take everything up to the first space
        size_t space = commandLine.find(L' ');
        exePath = (space != std::wstring::npos) ? commandLine.substr(0, space) : commandLine;
    }
    
    if (!exePath.empty()) {
        // Convert relative path to absolute if needed
        wchar_t absolutePath[MAX_PATH * 2] = {0};
        if (GetFullPathNameW(exePath.c_str(), sizeof(absolutePath) / sizeof(wchar_t), absolutePath, nullptr)) {
            std::wcout << L"[DEBUG] Checking architecture of: " << absolutePath << std::endl;
            targetArch = GetPeMachineFromFile(absolutePath);
        }
    }
    
    // Check for architecture mismatch before even launching
    if (injectorArch != 0 && targetArch != IMAGE_FILE_MACHINE_UNKNOWN && targetArch != 0 && injectorArch != targetArch) {
        std::wcerr << L"\n[Injector] ✗ CRITICAL: Architecture mismatch detected before launch!" << std::endl;
        std::wcerr << L"  Injector : " << MachineTypeToString(injectorArch).c_str() << std::endl;
        std::wcerr << L"  Target   : " << MachineTypeToString(targetArch).c_str() << std::endl;
        std::wcerr << L"  Build the injector / DLL for the same architecture." << std::endl;
        return false;
    }

    STARTUPINFOW si{};
    PROCESS_INFORMATION pi{};
    si.cb = sizeof(si);

    std::wcout << L"[Injector] Creating process..." << std::endl;
    std::wcout.flush();
    if (!CreateProcessW(nullptr, const_cast<LPWSTR>(commandLine.c_str()), nullptr, nullptr,
                        FALSE, CREATE_SUSPENDED, nullptr, nullptr, &si, &pi)) {
        DWORD err = GetLastError();
        std::wcerr << L"[Injector] CreateProcess failed with error " << err << L" (" << Win32ErrorMessage(err) << L")" << std::endl;
        std::wcerr.flush();
        LogCreateProcessDiagnostics(commandLine, err);
        return false;
    }

    std::wcout << L"[Injector] Process created with PID " << pi.dwProcessId << L", verifying architecture..." << std::endl;
    std::wcout.flush();
    
    // Add a small delay to let the process initialize
    std::wcout << L"[Injector] Waiting for process initialization..." << std::endl;
    std::wcout.flush();
    Sleep(100); // 100ms delay
    
    // === Architecture Mismatch Check – refuse to continue if injector and target don't match ===
    injectorArch = GetInjectorArchitecture();
    targetArch   = GetProcessArchitecture(pi.hProcess);
    
    // If we couldn't determine architecture from the process, try reading the file
    if (targetArch == 0 || targetArch == IMAGE_FILE_MACHINE_UNKNOWN) {
        // Get the actual executable path
        wchar_t exePath[MAX_PATH * 2] = {0};
        DWORD pathSize = sizeof(exePath) / sizeof(wchar_t);
        
        if (QueryFullProcessImageNameW(pi.hProcess, 0, exePath, &pathSize)) {
            std::wcout << L"[DEBUG] Process executable path: " << exePath << std::endl;
            targetArch = GetPeMachineFromFile(exePath);
        } else {
            std::wcout << L"[DEBUG] Failed to get process image path, error: " << GetLastError() << std::endl;
        }
    }

    if (injectorArch != 0                    // we know our own machine type
        && targetArch  != IMAGE_FILE_MACHINE_UNKNOWN   // we could query the target
        && targetArch  != 0                             // and it's valid
        && injectorArch != targetArch)                  // mismatch → abort
    {
        std::wcerr << L"\n[Injector] ✗ CRITICAL: Architecture mismatch!" << std::endl;
        std::wcerr << L"  Injector : " << MachineTypeToString(injectorArch).c_str() << std::endl;
        std::wcerr << L"  Target   : " << MachineTypeToString(targetArch ).c_str() << std::endl;
        std::wcerr << L"  Build the injector / DLL for the same architecture (use -A ARM64 for ARM native, -A x64 for emulated x64)." << std::endl;

        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return false;
    }
    // ===================================
    
    std::wstring absoluteDllPath = GetAbsoluteDllPath();

    if (!std::filesystem::exists(absoluteDllPath)) {
        std::wcerr << L"[Injector] ✗ CRITICAL: DLL not found at path: " << absoluteDllPath << std::endl;
        std::wcerr << L"[Injector] This path is calculated relative to the injector's location." << std::endl;
        std::wcerr << L"[Injector] Please ensure 'ai_hook.dll' exists and the build process places it correctly." << std::endl;
        std::wcerr.flush();
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return false;
    }
    
    std::wcout << L"[Injector] Found DLL at: " << absoluteDllPath << std::endl;
    std::wcout.flush();
    
    // Check if we're on ARM64 Windows trying to inject into x64 process
    bool isArm64Host = false;
    
    // Use IsWow64Process2 to detect if we're running on ARM64
    USHORT processMachine = IMAGE_FILE_MACHINE_UNKNOWN;
    USHORT nativeMachine = IMAGE_FILE_MACHINE_UNKNOWN;
    typedef BOOL (WINAPI *IsWow64Process2_t)(HANDLE, PUSHORT, PUSHORT);
    IsWow64Process2_t pIsWow64Process2 = (IsWow64Process2_t)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "IsWow64Process2");
    
    if (pIsWow64Process2 && pIsWow64Process2(GetCurrentProcess(), &processMachine, &nativeMachine)) {
        std::wcout << L"[DEBUG] Current process: processMachine=0x" << std::hex << processMachine 
                   << L", nativeMachine=0x" << nativeMachine << std::dec << std::endl;
        if (nativeMachine == IMAGE_FILE_MACHINE_ARM64) {
            isArm64Host = true;
            std::wcout << L"[Injector] Running on ARM64 Windows (detected via IsWow64Process2)" << std::endl;
        }
    } else {
        // Fallback to GetNativeSystemInfo
        SYSTEM_INFO sysInfo;
        GetNativeSystemInfo(&sysInfo);
        std::wcout << L"[DEBUG] Native system architecture (fallback): " << sysInfo.wProcessorArchitecture << std::endl;
        if (sysInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_ARM64) {
            isArm64Host = true;
            std::wcout << L"[Injector] Running on ARM64 Windows (detected via GetNativeSystemInfo)" << std::endl;
        }
    }
    
    bool useManualInjection = false;
    if (isArm64Host && targetArch == IMAGE_FILE_MACHINE_AMD64) {
        std::wcout << L"[Injector] x64 process on ARM64 host detected - using manual injection" << std::endl;
        useManualInjection = true;
    }
    
    if (!useManualInjection) {
        char dllPathA[MAX_PATH];
        WideCharToMultiByte(CP_ACP, 0, absoluteDllPath.c_str(), -1, dllPathA, MAX_PATH, nullptr, nullptr);
        const char* dlls[] = { dllPathA };
        
        std::wcout << L"[Injector] Calling DetourUpdateProcessWithDll..." << std::endl;
        std::wcout.flush();
        
        // Set last error to 0 to ensure we get the real error
        SetLastError(0);
        
        BOOL detourResult = DetourUpdateProcessWithDll(pi.hProcess, dlls, 1);
        DWORD detourError = GetLastError();
        
        std::wcout << L"[Injector] DetourUpdateProcessWithDll returned: " << (detourResult ? L"TRUE" : L"FALSE") 
                  << L", GetLastError: " << detourError << std::endl;
        std::wcout.flush();
        
        if (!detourResult) {
            std::wcerr << L"[Injector] DetourUpdateProcessWithDll failed with error: " << detourError << L" (" << Win32ErrorMessage(detourError) << L")" << std::endl;
            std::wcerr.flush();
            
            // Check if DLL exists and is accessible
            HMODULE testLoad = LoadLibraryExW(absoluteDllPath.c_str(), NULL, DONT_RESOLVE_DLL_REFERENCES);
            if (testLoad) {
                std::wcerr << L"[Injector] DLL can be loaded locally, issue might be with target process" << std::endl;
                std::wcerr.flush();
                FreeLibrary(testLoad);
            } else {
                DWORD loadError = GetLastError();
                std::wcerr << L"[Injector] DLL cannot be loaded locally, error: " << loadError << L" (" << Win32ErrorMessage(loadError) << L")" << std::endl;
                std::wcerr.flush();
            }
            
            TerminateProcess(pi.hProcess, 1);
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
            return false;
        }
    } else {
        // Use manual injection for x64 on ARM64
        std::wcout << L"[Injector] Resuming process for manual injection..." << std::endl;
        ResumeThread(pi.hThread);
        
        // Give process time to initialize
        Sleep(500);
        
        if (InjectDllManually(pi.hProcess, absoluteDllPath.c_str())) {
            std::wcout << L"[Injector] ✓ Manual injection successful!" << std::endl;
            std::wcout.flush();
        } else {
            std::wcerr << L"[Injector] ✗ Manual injection failed" << std::endl;
            std::wcerr.flush();
            TerminateProcess(pi.hProcess, 1);
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
            return false;
        }
    }

    if (!useManualInjection) {
        std::wcout << L"[Injector] ✓ Main process injection successful, resuming..." << std::endl;
        std::wcout.flush();
        ResumeThread(pi.hThread);
    }
    
    // Wait a bit to see if the process stays alive
    std::wcout << L"[Injector] Waiting for process to initialize with DLL..." << std::endl;
    std::wcout.flush();
    Sleep(1000);
    
    // Check if process is still alive
    DWORD exitCode;
    if (GetExitCodeProcess(pi.hProcess, &exitCode)) {
        if (exitCode != STILL_ACTIVE) {
            std::wcerr << L"[Injector] Process exited with code: " << exitCode << L" (0x" << std::hex << exitCode << std::dec << L")" << std::endl;
            std::wcerr.flush();
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
            return false;
        } else {
            std::wcout << L"[Injector] Process is still running after injection" << std::endl;
            std::wcout.flush();
        }
    }
    
    if (waitForExit) {
        std::wcout << L"[Injector] Waiting for process to exit..." << std::endl;
        WaitForSingleObject(pi.hProcess, INFINITE);
        std::wcout << L"[Injector] Process has exited" << std::endl;
    }
    
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return true;
}

int wmain(int argc, wchar_t* argv[]) {
    LogInjector(L"INFO", L"=== AI Traffic Injector Starting ===");
    LogInjector(L"INFO", L"Version: 1.0.0");
    LogInjector(L"DEBUG", L"Command line args: " + std::to_wstring(argc));
    
    if (argc < 2) {
        LogInjector(L"ERROR", L"Invalid arguments");
        std::wcerr << L"Usage: ai_injector [--with-children] <command line>" << std::endl;
        return 1;
    }

    LoadConfig(); // Load the allow-list at startup

    bool withChildren = false;
    int firstCmdArg = 1;
    if (std::wstring_view(argv[1]) == L"--with-children") {
        withChildren = true;
        firstCmdArg = 2;
        LogInjector(L"INFO", L"Child process monitoring enabled");
        if (argc < 3) {
            LogInjector(L"ERROR", L"Expected command line after --with-children");
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
                std::wcout.flush();
            } else {
                std::wcerr << L"[Injector] Preload script not found at: " << preload_script_path.wstring() << std::endl;
                std::wcerr.flush();
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
    std::wcout.flush();
#ifdef _DEBUG
    std::wcout << L"[Injector] (debug) Calling CreateProcessW..." << std::endl;
#endif
    // Launch main process and inject
    DWORD mainPid = 0;
    if (!StartProcessAndInject(final_cmdline, GetAbsoluteDllPath(), true, withChildren)) {
        std::wcerr << L"[Injector] ✗ Failed to start and inject into the main process." << std::endl;
        std::wcerr.flush();
        return 1;
    }

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
                    std::wstring cmd = GetProcessCommandLine(kid);
                    bool isRenderer = cmd.find(L"--type=renderer") != std::wstring::npos;
                    bool isNodeHost = cmd.find(L"node ") != std::wstring::npos || GetProcessName(kid) == L"node.exe";
                    bool isUtility = cmd.find(L"--type=utility") != std::wstring::npos || cmd.find(L"--type=gpu") != std::wstring::npos;

                    if (isUtility) {
                        std::wcout << L"[Injector] Skipping utility process PID " << kid << std::endl;
                        continue;
                    }

                    if (isRenderer || isNodeHost) {
                        if (InjectIntoProcess(kid, GetAbsoluteDllPath().c_str())) {
                            // Success logged inside
                        }
                    } else {
                        std::wcout << L"[Injector] Skipping unrelated child PID " << kid << std::endl;
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
