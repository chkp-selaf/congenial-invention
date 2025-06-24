# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

AI Traffic Interceptor is a Windows-based system for capturing plaintext AI traffic from desktop applications (VS Code Copilot, ChatGPT Desktop, Claude Desktop) without breaking TLS or requiring kernel drivers. The system uses DLL injection to hook WinHTTP and SSL APIs.

## Build System

The project uses CMake with .NET components:

### Core Build Commands
```powershell
# Configure (x64 Release)
cmake -B build -DCMAKE_BUILD_TYPE=Release

# Build all C++ components
cmake --build build --config Release

# Build C# components
cmake --build build --target build_collector
cmake --build build --target build_proxy
```

### Additional Build Options
- `ENABLE_NATIVE_TESTS=ON/OFF` - Build GoogleTest unit tests (default ON, disabled on ARM64)
- ARM64 builds automatically include ARM64-specific injection tests
- WiX packaging targets included if WiX toolset is detected

## Architecture

### Component Structure
- **injector/** - C++ DLL injector that launches target processes and injects the hook DLL
- **dll/** - C++ hook DLL using Microsoft Detours to intercept WinHTTP and SSL APIs
- **collector/** - C# .NET 8 application that receives intercepted traffic via named pipes
- **proxy/** - C# .NET 8 OpenAI-compatible proxy server
- **tests/** - GoogleTest unit tests and integration test utilities
- **tools/** - Diagnostic utilities (log analyzer, DLL diagnostics)

### Key Technologies
- **Microsoft Detours** - API hooking framework
- **Named Pipes** - IPC between hook DLL and collector
- **ETW (Event Tracing for Windows)** - Event logging
- **Serilog** - Structured logging in C# components
- **GoogleTest** - C++ unit testing framework

## Testing

### C++ Tests (GoogleTest)
```powershell
# Run all C++ unit tests
cmake --build build --target unit_tests
./build/tests/Release/unit_tests.exe

# Run specific test components
./build/tests/Release/test_arm64_injection.exe
./build/tests/Release/mini_client.exe
```

### Python Integration Tests
```powershell
# Set up Python test environment
cmake --build build --target setup_python_test

# Run Python tests
cd tests/python
./venv/Scripts/activate  # Windows
python test_capture.py
```

## Configuration

### Config Files
- **config/aiti_config.json** - Main configuration for allowed processes and hooking behavior
- Configuration is automatically copied to build output during build

### Logging Configuration
- Hook DLL logs to `%TEMP%\ai_hook_<PID>_<timestamp>.log`
- Collector logs to `logs/aiti-collector-<date>.log`
- Use `--verbose` flag with collector for detailed output
- ETW tracing available via Windows Performance Analyzer

## Development Workflow

### Debugging
- Use `log_analyzer.exe` tool to find and analyze hook DLL logs
- Enable DebugView (Sysinternals) for real-time debug output
- Collector supports `--verbose` mode for detailed traffic analysis
- Comprehensive logging at TRACE/DEBUG/INFO/WARN/ERROR/CRITICAL levels

### Common Development Tasks
1. **Adding new API hooks**: Modify `dll/hooks.cpp` and update hook installation in `InstallHooks()`
2. **Updating traffic analysis**: Modify `collector/AnalysisEngine.cs`
3. **Testing injection**: Use `mini_client.exe` and `test_inject_self.exe` utilities

## Platform Considerations

### Windows Requirements
- Windows 10/11 SDK
- Visual Studio 2022 Build Tools
- CMake ≥ 3.21
- .NET 8 SDK
- vcpkg (optional, for GoogleTest and other dependencies)

### ARM64 Support
- ARM64 builds automatically disable problematic GoogleTest targets
- Special ARM64 injection tests included
- Cross-architecture injection supported (x64 DLL into ARM64 process and vice versa)

## Security Notes

This is a defensive security tool for intercepting AI traffic. The codebase includes:
- Process allowlisting via configuration
- Comprehensive audit logging
- ETW event tracing for security monitoring
- Safe DLL injection using Microsoft Detours