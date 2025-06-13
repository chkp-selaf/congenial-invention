# AI Traffic Interceptor – Development Plan

**Last updated:** 2025-06-13

---

## 1. Milestones & Current Status

| ID | Milestone | Status | Notes |
|----|-----------|--------|-------|
| M1 | Repository scaffold, CMake, Detours submodule | ✅ Done |
| M2 | Injector (`ai_injector.exe`) | ✅ Done |
| M3 | WinHTTP / WebSocket hooks | ✅ Done |
| M3.5–3.7 | Electron & Node discovery/injection | ⚠️ Pending |
| M4 | OpenSSL/BoringSSL hooks (pattern-scan `SSL_write`) | ✅ Done |
| M5 | Schannel hooks (`EncryptMessage` / `DecryptMessage`) | ✅ Done |
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

1. **Prereqs**: Visual Studio 2022 C++, CMake ≥3.21, .NET 8 SDK, WiX 4.
2. `git clone <repo>` → `git submodule update --init --recursive`
3. Configure + build Release:
   ```powershell
   cmake -S . -B build -G "Visual Studio 17 2022" -A x64 -DCMAKE_BUILD_TYPE=Release
   cmake --build build --config Release
   ```
4. Optional Python test env:
   ```powershell
   cmake --build build --target setup_python_test --config Release
   ```
5. Package MSI:
   ```powershell
   wix build -o AIInterceptor.msi packaging\Product.wxs
   ```

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
   * Finish WiX template: author shortcuts, uninstall, optional Windows service for collector, environment variables.
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
