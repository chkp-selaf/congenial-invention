#include <windows.h>
#include <psapi.h>
#include <iostream>
#include <iomanip>
#include <vector>
#include <filesystem>

static void print_last_error(const char* prefix)
{
    DWORD e = GetLastError();
    LPSTR buf = nullptr;
    FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER |
                   FORMAT_MESSAGE_FROM_SYSTEM     |
                   FORMAT_MESSAGE_IGNORE_INSERTS,
                   nullptr, e, 0,
                   (LPSTR)&buf, 0, nullptr);
    std::cerr << prefix << " (code " << std::hex << std::showbase
              << e << "): " << (buf ? buf : "") << "\n";
    LocalFree(buf);
}

static std::string machine_string(WORD m)
{
    switch (m) {
        case IMAGE_FILE_MACHINE_I386:  return "x86 (0x14C)";
        case IMAGE_FILE_MACHINE_AMD64: return "x64 (0x8664)";
        case IMAGE_FILE_MACHINE_ARM64: return "ARM64 (0xAA64)";
        default: return "unknown";
    }
}

static bool print_pe_headers(const std::wstring& path)
{
    HANDLE hFile = CreateFileW(path.c_str(), GENERIC_READ,
                               FILE_SHARE_READ, nullptr,
                               OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) { print_last_error("Open file"); return false; }

    HANDLE hMap  = CreateFileMappingW(hFile, nullptr, PAGE_READONLY, 0, 0, nullptr);
    if (!hMap) { print_last_error("CreateFileMapping"); CloseHandle(hFile); return false; }

    auto* base = (BYTE*)MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);
    if (!base) { print_last_error("MapViewOfFile"); CloseHandle(hMap); CloseHandle(hFile); return false; }

    auto* dos = (IMAGE_DOS_HEADER*)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) { std::cerr << "Not a PE file\n"; return false; }

    auto* nt  = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
    WORD machine = nt->FileHeader.Machine;
    std::cout << "PE machine: " << machine_string(machine) << "\n";

    UnmapViewOfFile(base); CloseHandle(hMap); CloseHandle(hFile);
    return true;
}

int wmain(int argc, wchar_t* argv[])
{
    if (argc != 2)
    {
        std::wcerr << L"Usage: dll_diag <path-to-dll>\n";
        return 1;
    }
    std::filesystem::path dllPath(argv[1]);
    dllPath = std::filesystem::absolute(dllPath);

    std::wcout << L"== Diagnosing: " << dllPath << L"\n";
    print_pe_headers(dllPath.wstring());

    HMODULE h = LoadLibraryExW(dllPath.c_str(), nullptr,
                               LOAD_LIBRARY_SEARCH_DEFAULT_DIRS);
    if (!h)
    {
        print_last_error("LoadLibraryExW");
        return 2;
    }
    std::cout << "DLL loaded successfully.\n";

    // List first-level dependencies
    std::vector<HMODULE> mods(128);
    DWORD needed = 0;
    if (EnumProcessModules(GetCurrentProcess(),
                           mods.data(), (DWORD)(mods.size()*sizeof(HMODULE)),
                           &needed))
    {
        mods.resize(needed/sizeof(HMODULE));
        TCHAR name[MAX_PATH];
        std::cout << "\nDirect dependencies resolved by the loader:\n";
        for (HMODULE m : mods)
        {
            if (GetModuleFileName(m, name, MAX_PATH))
                std::wcout << L"  " << name << L"\n";
        }
    }

    FreeLibrary(h);
    return 0;
} 