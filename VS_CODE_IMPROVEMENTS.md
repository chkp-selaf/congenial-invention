# VS Code SSL Interception Improvements

## Overview

This commit implements comprehensive improvements for intercepting VS Code LLM communication, specifically targeting SSL/TLS failures with Electron applications that use BoringSSL instead of standard OpenSSL.

## Key Changes

### 1. Enhanced BoringSSL Module Detection (`dll/hooks.cpp`)

- **New Function**: `IsElectronProcess()` - Detects Electron/Chromium processes via module and file checks
- **New Function**: `TryElectronSslFunctions()` - Specialized BoringSSL function discovery
- **Enhanced Modules**: Added detection for `chrome.dll`, `chrome_child.dll`, `node.dll`, `electron.exe`, `v8.dll`, `ffmpeg.dll`, `libnode.dll`
- **BoringSSL Export Names**: Includes standard and BoringSSL-specific export variants
- **Fallback Strategy**: Falls back to standard SSL detection if Electron-specific detection fails

### 2. Multi-Process VS Code Injection (`injector/injector.cpp`)

- **New Flag**: `--vscode` - Inject into all running VS Code processes automatically
- **Process Classification**: Detects Main, Renderer, Extension Host, and Worker processes
- **VS Code Family Support**: Supports Code.exe, Code - Insiders.exe, VSCode.exe, VSCodium.exe, cursor.exe, windsurf.exe
- **Prioritized Injection**: Main → Extension Host → Renderer order for optimal interception
- **New Function**: `InjectAllVSCodeProcesses()` - Comprehensive VS Code process injection

### 3. Electron Diagnostics (`dll/hooks.cpp`)

- **New Function**: `DiagnoseElectronEnvironment()` - Comprehensive process analysis
- **Module Detection**: Identifies loaded Electron/Chromium modules with paths
- **VS Code Detection**: Checks for VS Code-specific resource files
- **Process Type**: Determines main/renderer/extension host/worker process types
- **Architecture Info**: Reports system architecture and WoW64 emulation status
- **ETW Integration**: Enhanced Event Tracing for Windows logging

### 4. Enhanced Configuration (`config/aiti_config.json`)

- **Electron Section**: Configuration for enhanced detection, BoringSSL support, multi-process injection
- **VS Code Section**: Auto-detection settings and supported variants
- **SSL Section**: Key-log-only strategy configuration and BoringSSL module list
- **Process Types**: Granular hook configuration per process type

## Build Instructions for Cursor AI Agent

### Prerequisites
```powershell
# Ensure you have these installed:
# - Windows 10/11 SDK
# - Visual Studio 2022 Build Tools
# - CMake ≥ 3.21
# - .NET 8 SDK
```

### Build Steps
```powershell
# 1. Configure the build (from repository root)
cmake -B build -DCMAKE_BUILD_TYPE=Release

# 2. Build all C++ components
cmake --build build --config Release

# 3. Build C# components
cmake --build build --target build_collector
cmake --build build --target build_proxy

# 4. Verify build artifacts
dir build\injector\Release\ai_injector.exe
dir build\dll\Release\ai_hook.dll
dir build\collector\ai_collector.exe
```

## Testing Instructions

### Test 1: Multi-Process VS Code Injection
```powershell
# Start VS Code first
# Then inject into all VS Code processes
.\build\injector\Release\ai_injector.exe --vscode
```

### Test 2: Enhanced SSL Detection
```powershell
# Start collector first
.\build\collector\ai_collector.exe --verbose

# In another terminal, inject into running VS Code
.\build\injector\Release\ai_injector.exe --vscode

# Or launch VS Code with injection
.\build\injector\Release\ai_injector.exe --with-children "C:\Program Files\Microsoft VS Code\Code.exe"
```

### Test 3: Verify Enhanced Diagnostics
```powershell
# Check hook DLL logs for Electron diagnostics
type "%TEMP%\ai_hook_*_*.log" | findstr "Electron"

# Look for these key indicators:
# - "Electron/Chromium process confirmed"
# - "VS Code application confirmed"
# - "Found essential BoringSSL functions"
# - Process type detection (Main/Renderer/Extension Host)
```

## Expected Improvements

### BoringSSL Function Discovery
- Should now find SSL functions in `chrome.dll` instead of failing pattern scans
- Logs should show "Found essential BoringSSL functions in chrome.dll"
- SSL keylogging should work with VS Code's BoringSSL implementation

### Multi-Process Coverage
- All VS Code processes (main, renderer, extension host) should be injected
- Extension host process is critical for Copilot/LLM extensions
- Logs should show successful injection into multiple process types

### Better Diagnostics
- Clear identification of Electron vs standard Windows processes  
- VS Code-specific resource detection
- Process type classification for targeted hook strategies

## Troubleshooting

### If SSL hooks still fail:
```powershell
# Try with SSL hooks disabled to test other components
set AITI_DISABLE_SSL_HOOKS=1
.\build\injector\Release\ai_injector.exe --vscode
```

### If no VS Code processes found:
- Ensure VS Code is running before using `--vscode` flag
- Check that process names match supported variants in config
- Verify VS Code processes are visible to the injector (run as admin if needed)

### Debug logging:
- Hook DLL logs: `%TEMP%\ai_hook_<PID>_<timestamp>.log`
- Collector logs: `logs\aiti-collector-<date>.log`
- Use DebugView (Sysinternals) for real-time debug output

## Architecture Notes

This implementation specifically targets the challenges with VS Code LLM interception:

1. **BoringSSL vs OpenSSL**: VS Code uses Chromium's BoringSSL, not standard OpenSSL
2. **Multi-Process Architecture**: VS Code extensions run in separate processes
3. **Extension Host**: LLM extensions like Copilot run in the extension host process
4. **Dynamic Loading**: SSL modules may be loaded after injection, requiring delayed hook installation

The enhanced detection and multi-process injection should significantly improve VS Code LLM traffic interception reliability.