#include <windows.h>
#include <detours.h>
#include <string>
#include <vector>
#include <iostream>

// TODO: replace with configurable path or resource
constexpr const wchar_t* kDllPath = L"ai_hook.dll";

// Simple wrapper around CreateProcessW + DetourUpdateProcessWithDllW
bool StartProcessAndInject(const std::wstring& cmdline) {
    STARTUPINFOW si{sizeof(si)};
    PROCESS_INFORMATION pi{};

    // Create the target process in suspended mode so we can inject before it starts
    if (!CreateProcessW(nullptr, const_cast<LPWSTR>(cmdline.c_str()), nullptr, nullptr,
                        FALSE, CREATE_SUSPENDED, nullptr, nullptr, &si, &pi)) {
        std::wcerr << L"CreateProcess failed: " << GetLastError() << std::endl;
        return false;
    }

    // Inject DLL
    if (DetourUpdateProcessWithDllW(pi.hProcess, &kDllPath, 1)) {
        std::wcerr << L"DetourUpdateProcessWithDllW failed: " << GetLastError() << std::endl;
        TerminateProcess(pi.hProcess, 1);
        return false;
    }

    // Resume main thread
    ResumeThread(pi.hThread);

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return true;
}

int wmain(int argc, wchar_t* argv[]) {
    if (argc < 2) {
        std::wcerr << L"Usage: ai_injector <command line>" << std::endl;
        return 1;
    }

    // Combine arguments into single command line for CreateProcess
    std::wstring cmdline;
    for (int i = 1; i < argc; ++i) {
        if (i > 1) cmdline += L" ";
        cmdline += argv[i];
    }

    return StartProcessAndInject(cmdline) ? 0 : 1;
}
