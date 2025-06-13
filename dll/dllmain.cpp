#include <windows.h>
#include "hooks.h"
#include "pipe_client.h"

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
        case DLL_PROCESS_ATTACH:
            // Disable DLL_THREAD_ATTACH and DLL_THREAD_DETACH notifications for performance
            DisableThreadLibraryCalls(hModule);
            PipeInitialize();
            InstallHooks();
            break;
        case DLL_PROCESS_DETACH:
            RemoveHooks();
            PipeShutdown();
            break;
    }
    return TRUE;
}
