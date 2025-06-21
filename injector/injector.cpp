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
#pragma comment(lib, "shlwapi.lib")

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

// Gets the architecture of a running process. Returns 0 on failure.
static WORD GetProcessArchitecture(HANDLE hProcess) {
    USHORT processMachine = 0;
    USHORT nativeMachine = 0;
    if (IsWow64Process2(hProcess, &processMachine, &nativeMachine)) {
        if (processMachine == IMAGE_FILE_MACHINE_UNKNOWN) {
            return nativeMachine; // Process is running natively
        }
        return processMachine; // Process is running under WOW64
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
        return;
    }

    std::filesystem::path configPath = std::filesystem::path(injectorPath).parent_path() / L".." / L"config" / L"aiti_config.json";
    configPath = std::filesystem::absolute(configPath).lexically_normal();
    
    if (!std::filesystem::exists(configPath)) {
        std::wcerr << L"[Injector] Config file not found at " << configPath << ". All processes will be allowed." << std::endl;
        return;
    }

    std::ifstream configFile(configPath);
    if (!configFile.is_open()) {
        std::wcerr << L"[Injector] Could not open config file. All processes will be allowed." << std::endl;
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
        }
    } catch (const nlohmann::json::parse_error& e) {
        std::wcerr << L"[Injector] Failed to parse config file: " << e.what() << ". All processes will be allowed." << std::endl;
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
            std::wcout << L"[Injector] Skipping non-allowed process: " << processName << std::endl;
            return false; // Not an error, just skipping
        }
    }
    
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
        candidates.push_back(base.parent_path().parent_path() / L"dll" / kConfig / L"ai_hook.dll");
        // Non build_vs variant (build/)
        candidates.push_back(base.parent_path().parent_path().parent_path() / L"build" / L"dll" / kConfig / L"ai_hook.dll");
    }

    // 2. Same directory as injector
    candidates.push_back(std::filesystem::path(L"ai_hook.dll"));

    // 3. Common relative paths
    candidates.push_back(std::filesystem::path(L"build_vs") / L"dll" / kConfig / L"ai_hook.dll");
    candidates.push_back(std::filesystem::path(L"build") / L"dll" / kConfig / L"ai_hook.dll");

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

// Simple wrapper around CreateProcessW + DetourUpdateProcessWithDllW
bool StartProcessAndInject(const std::wstring& cmdline, DWORD* outPid) {
    STARTUPINFOW si{sizeof(si)};
    PROCESS_INFORMATION pi{};

    std::wcout << L"[Injector] Creating process..." << std::endl;
    if (!CreateProcessW(nullptr, const_cast<LPWSTR>(cmdline.c_str()), nullptr, nullptr,
                        FALSE, CREATE_SUSPENDED, nullptr, nullptr, &si, &pi)) {
        DWORD err = GetLastError();
        std::wcerr << L"[Injector] CreateProcess failed with error " << err << L" (" << Win32ErrorMessage(err) << L")" << std::endl;
        LogCreateProcessDiagnostics(cmdline, err);
        return false;
    }

    std::wcout << L"[Injector] Process created with PID " << pi.dwProcessId << L", verifying architecture..." << std::endl;
    
    // === Architecture Mismatch Check ===
    WORD injectorArch = GetInjectorArchitecture();
    WORD targetArch = GetProcessArchitecture(pi.hProcess);

    if (injectorArch != 0 && targetArch != 0 && injectorArch != targetArch) {
        fwprintf(stderr, L"\n[Injector] ✗ CRITICAL: Architecture Mismatch!\n");
        fwprintf(stderr, L"  Injector is: %hs\n", MachineTypeToString(injectorArch).c_str());
        fwprintf(stderr, L"  Target EXE is: %hs\n", MachineTypeToString(targetArch).c_str());
        fwprintf(stderr, L"  This is guaranteed to fail with a 0xc000007b error. Aborting.\n");
        fwprintf(stderr, L"  Please build the injector and DLL for the correct architecture (e.g., cmake -A ARM64 or -A x64).\n");
        fflush(stderr);

        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return false;
    } else if (targetArch == 0) {
        wprintf(L"[Injector] (warning) Could not determine target process architecture. Proceeding with caution.\n");
        fflush(stdout);
    } else {
        wprintf(L"[Injector] ✓ Architecture match validated (%hs).\n", MachineTypeToString(targetArch).c_str());
        fflush(stdout);
    }
    // ===================================
    
    std::wstring absoluteDllPath = GetAbsoluteDllPath();

    if (!std::filesystem::exists(absoluteDllPath)) {
        std::wcerr << L"[Injector] ✗ CRITICAL: DLL not found at path: " << absoluteDllPath << std::endl;
        std::wcerr << L"[Injector] This path is calculated relative to the injector's location." << std::endl;
        std::wcerr << L"[Injector] Please ensure 'ai_hook.dll' exists and the build process places it correctly." << std::endl;
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return false;
    }
    
    std::wcout << L"[Injector] Found DLL at: " << absoluteDllPath << std::endl;
    
    char dllPathA[MAX_PATH];
    WideCharToMultiByte(CP_ACP, 0, absoluteDllPath.c_str(), -1, dllPathA, MAX_PATH, nullptr, nullptr);
    const char* dlls[] = { dllPathA };
    if (!DetourUpdateProcessWithDll(pi.hProcess, dlls, 1)) {
        DWORD error = GetLastError();
        std::wcerr << L"[Injector] DetourUpdateProcessWithDll failed with error: " << error << std::endl;
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
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

    LoadConfig(); // Load the allow-list at startup

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
#ifdef _DEBUG
    std::wcout << L"[Injector] (debug) Calling CreateProcessW..." << std::endl;
#endif
    // Launch main process and inject
    DWORD mainPid = 0;
    if (!StartProcessAndInject(final_cmdline, &mainPid)) {
        std::wcerr << L"[Injector] ✗ Failed to start and inject into the main process." << std::endl;
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
