# AI Traffic Interceptor – Development Plan

**Last updated:** 2025-06-14

---

## 1. Milestones & Current Status

| ID | Milestone | Status | Notes |
|----|-----------|--------|-------|
| M1 | Repository scaffold, CMake, Detours submodule | ✅ Done |
| M2 | Injector (`ai_injector.exe`) | ✅ Done |
| M3 | WinHTTP / WebSocket hooks | ✅ Done |
| M3.5–3.7 | Electron & Node discovery/injection | ⚠️ Pending |
| M4 | OpenSSL/BoringSSL hooks (pattern-scan `SSL_write`) | ✅ Done |
| M5 | Schannel hooks (`EncryptMessage`, `DecryptMessage`, `AcquireCredentialsHandleW`) | ✅ Done | ALPN capture via AcquireCredentialsHandleW |
| M6 | Named-pipe IPC & C# collector | ✅ Done |
| M7 | Analysis PoC (PII & prompt-injection regex) | ✅ Done |
| M8 | End-to-end test script (Python) | ✅ Done (Windows run pending) |
| M9 | Packaging (WiX installer) | ⏳ Template added – build pending |
| M10 | Hardening / allow-lists / ETW logging | 🚧 Not started |

---

## 2. Repository Layout (key folders)

```
/collector          – .NET 8 console app (named-pipe server + analysis)
/dll                – `ai_hook.dll` (Detours + OpenSSL/SChannel hooks)
/injector           – `ai_injector.exe` (StartProcessAndInject)
/external/detours   – Microsoft Detours git submodule
/tests              – GoogleTest stubs + Python e2e script
/packaging          – WiX installer template (`Product.wxs`)
```

---

## 3. Build Instructions (Windows x64)

> These steps assume **Visual Studio 2022** is installed.  CMake is bundled with VS so you don't need a separate installation.

### 3.1 Configure (first time or after `git pull`)
```powershell
# Optional – start clean when switching Win32⇄x64 or after larger CMake edits
Remove-Item -Recurse -Force build   # or just delete in Explorer

# VS-bundled CMake path (kept on one line):
& "${Env:ProgramFiles}\Microsoft Visual Studio\2022\Enterprise\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe" `
    -S . -B build -G "Visual Studio 17 2022" -A x64 -DCMAKE_BUILD_TYPE=Release
```

### 3.2 Full build
```powershell
# Builds every native target *and* the .NET collector
& "${Env:ProgramFiles}\Microsoft Visual Studio\2022\Enterprise\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe" `
    --build build --config Release
```

### 3.3 Incremental component build
Sometimes it's faster to iterate on a single artefact:
```powershell
cmake --build build --target detours        --config Release  # static detours.lib
cmake --build build --target ai_injector    --config Release  # injector EXE
cmake --build build --target ai_hook        --config Release  # hook DLL
cmake --build build --target build_collector --config Release # dotnet publish
```

### 3.4 Packaging (WiX)
The WiX custom target is **commented-out** until WiX 4 is installed and on *PATH*.
Un-comment the block at the bottom of the root `CMakeLists.txt` once WiX is available:
```cmake
find_program(WIX_EXECUTABLE wix REQUIRED)
add_custom_target(package_msi …)
```
Then build:
```powershell
cmake --build build --target package_msi --config Release
```

### 3.5 Troubleshooting
* "platform Win32 vs x64" → delete **build/** and re-configure.
* Missing dependencies (googletest) → correct `GIT_TAG` in `tests/CMakeLists.txt` (now `v1.14.0`).
* WiX not found → ensure WiX 4 installed or keep packaging target disabled.

---

## 4. Run-Time Test Flow

1. Launch collector:
   ```powershell
   build\collector\bin\Release\net8.0\ai_collector.exe
   ```
2. Start target via injector, e.g. Python script:
   ```powershell
   build\injector\Release\ai_injector.exe ^
       "C:\Python\python.exe" tests\python\test_capture.py
   ```
3. Observe JSON events + analysis findings in collector console.

---

## 5. Next Development Steps (for the next AI Agent)

1. **Finalize M3.5–M3.7 – Electron/Node injection**
   * Enumerate VS Code/ChatGPT Desktop child PIDs.
   * Inject `ai_hook.dll` into Electron renderer & Node extension hosts.
   * Build renderer `preload.js` shim to patch `fetch` & `WebSocket.send`.
2. **Refine OpenSSL pattern scanning**
   * Replace brittle byte-patterns with IDA-verified signatures or export-table fall-backs.
   * Add `SSL_read` hook to capture responses.
3. **Packaging (M9)**
    * Ensure Release build pipeline produces all artifacts (CMake C++ targets and `dotnet build` for collector).
    * Finish WiX template: author shortcuts, uninstall flow, optional Windows service for collector, environment variables.
    * Sign binaries & MSI.
4. **Hardening (M10)**
   * Allow/deny-list of processes (config JSON file).
   * Fail-safe pass-through on hook errors.
   * ETW health logging & verbose tracing flag.
5. **Comprehensive Test Matrix**
   * Add GoogleTest for BoringSSL & Schannel hooks (mock DLL).
   * Extend Python script for WebSocket traffic.
6. **Security & Privacy**
   * Implement PII redaction options in collector.
   * Add SHA-256 hash whitelist for allowed hosts.
7. **CI/CD**
   * GitHub Actions or Azure Pipelines: Windows build, unit tests, MSI artifact.

---

### Contacts & Conventions
* Code style: modern C++17, `.clang-format` TBD.
* Log format: JSON one-line records over named pipe `\\.\pipe\ai-hook`.
* All timestamps are ISO 8601 / UTC in collector.

Happy hacking!
