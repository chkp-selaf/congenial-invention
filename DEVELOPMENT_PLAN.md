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

## 6. AI Agent Hand-Off Plan

> **Purpose:** Provide incoming AI engineers (or automated agents) with a single, authoritative snapshot of the project's state, priorities, and gotchas. Update this section whenever handing the repo to a new owner.

### 6.1 High-Level Overview

*   Intercept outbound network traffic from Windows processes by injecting `ai_hook.dll` (Detours) and streaming structured JSON events to `ai_collector.exe` (named pipe).
*   Package DLL, injector, and collector into a signed MSI for friction-free installation.

### 6.2 Repository Snapshot (2025-06-14)

* **Build status:** `ai_hook.dll`, `ai_injector.exe`, and .NET collector build **clean** in Release.
* **Tests:** `tests/python/test_capture.py` passes – validates named-pipe handshake.
* **Electron:** Injector can spawn VS Code with `--preload`; renderer injection _partially_ implemented.
* **Packaging:** WiX target fails (`WIX0144` – `Wix.Util.dll` not found).

### 6.3 Environment Prerequisites

* Visual Studio 2022 (x64 workloads) – includes CMake.
* WiX 6.0.1 installed via `dotnet tool install ‑-global wix` → `wix.exe` on `%PATH%`.
* Python 3.12 for e2e script.
* Detours submodule already cloned under `external/detours`.

### 6.4 Build & Test Quickstart

```powershell
# Configure
$vsCmake = "$Env:ProgramFiles\Microsoft Visual Studio\2022\Enterprise\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe"
Remove-Item -Recurse -Force build
& $vsCmake -S . -B build -G "Visual Studio 17 2022" -A x64 -DCMAKE_BUILD_TYPE=Release

# Build all artefacts
& $vsCmake --build build --config Release

# Smoke test
build\collector\bin\Release\net8.0\ai_collector.exe      # terminal 1
build\injector\Release\ai_injector.exe \
    "C:\Python312\python.exe" tests\python\test_capture.py  # terminal 2
```

### 6.5 What's Done vs. Blocking

| Category | ✅ Completed | ⏳ Blocking / TODO |
|----------|-------------|-------------------|
| Core hooks | WinHTTP, WebSocket, OpenSSL (`SSL_write`), Schannel | Add `SSL_read`; robust Electron renderer detour |
| IPC | Named-pipe client (retry/back-off); collector supports 10 instances | Fail-safe pass-through on hook error |
| Packaging | WiX template & custom CMake target | Fix `WIX0144`; sign MSI |
| Tests | Python e2e verifies pipe traffic | GoogleTest for crypto hooks |

### 6.6 Next Steps (Priority Order)

1. **Packaging (Milestone M9)** – locate WiX extension path, patch `CMakeLists.txt`, build MSI, add shortcuts & service.
2. **Electron/Node Descendant Injection (M3.5-M3.7)** – monitor child PIDs for 30 s post-launch and inject on-the-fly.
3. **Add `SSL_read` Detour** – mirror pattern-scanner, emit response body.
4. **Security/Hardening (M10)** – allow/deny-list, ETW logging, config JSON.

### 6.7 Useful Commands

```powershell
# List WiX extensions with absolute paths
wix extension list

# Manual MSI build
wix build packaging\Product.wxs -arch x64 -out build\ai-traffic-interceptor.msi \
    -ext WixToolset.Util.wixext/6.0.1

# Inject into running PID (debug)
build\injector\Release\ai_injector.exe --pid 1234
```

### 6.8 Hand-Off Checklist

- [ ] `git status` clean (commit or stash local edits).
- [ ] Release build & Python e2e pass.
- [ ] WiX MSI builds and installs/uninstalls without error.
- [ ] Tag release (e.g. `v0.4.0-msi-alpha`).

---

> **Remember:** Keep this hand-off section concise but _current_. Future AI agents will look here first.

### Contacts & Conventions
* Code style: modern C++17, `.clang-format` TBD.
* Log format: JSON one-line records over named pipe `\\.\pipe\ai-hook`.
* All timestamps are ISO 8601 / UTC in collector.

Happy hacking!
