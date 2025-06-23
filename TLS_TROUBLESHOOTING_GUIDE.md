# TLS Troubleshooting Guide for Windows on ARM

## Quick Fixes

### 1. Test without SSL hooks
```bash
set AITI_DISABLE_SSL_HOOKS=1
.\ai_injector.exe "C:\Path\to\Code.exe"
```

### 2. Use configuration file
Place `aiti_config.json` in the same directory as `ai_injector.exe` or in `config/` directory:
```json
{
  "skip_ssl": ["Code.exe"]
}
```

### 3. Build ARM64 version
```bash
cmake -B build_arm64 -A ARM64 -DCMAKE_BUILD_TYPE=Release
cmake --build build_arm64 --config Release
```

## Understanding the Errors

| Error Code | Meaning | Cause |
|------------|---------|-------|
| -202 | ERR_CERT_AUTHORITY_INVALID | TLS validator cannot see system root store |
| -301 | ERR_DISALLOWED_URL_SCHEME | WinHTTP/WinINet blocked the AIA extension URL |

## What Was Fixed

1. **Stack Alignment**: Added 16-byte stack alignment to all SSL/Schannel hooks for WoA compatibility
2. **Environment Variable**: Added `AITI_DISABLE_SSL_HOOKS` support
3. **Config File**: Added per-process SSL hook skipping via `aiti_config.json`
4. **WinHTTP Context**: Preserved context values for WoA compatibility
5. **Error Handling**: Improved exception handling in all hooks

## Testing Procedure

1. **First test with SSL disabled**:
   ```bash
   set AITI_DISABLE_SSL_HOOKS=1
   .\build_x64\injector\Release\ai_injector.exe "C:\Program Files\Microsoft VS Code\Code.exe"
   ```
   If VS Code starts normally, the issue is confirmed to be SSL-related.

2. **Test with config file**:
   - Create `aiti_config.json` next to `ai_injector.exe`
   - Add VS Code to the skip list
   - Run normally without the environment variable

3. **Test ARM64 build**:
   ```bash
   .\build_arm64\injector\Release\ai_injector.exe "C:\Program Files\Microsoft VS Code\Code.exe"
   ```

## Log Files

Check logs in `%TEMP%\ai_hook_<PID>.log` for:
- "SSL hooks disabled" messages
- Stack traces from exceptions
- Pattern scan failures

## Architecture Support Matrix

| Host OS | Injector | Target | SSL Hooks | Status |
|---------|----------|---------|-----------|---------|
| x64 Windows | x64 | x64 | ✅ | Works |
| ARM64 Windows | x64 | x64 | ⚠️ | Works with fixes |
| ARM64 Windows | ARM64 | ARM64 | ✅ | Works |
| ARM64 Windows | ARM64 | x64 | ❌ | Not supported |

## Known Issues

- VS Code on ARM64 Windows running as x64 under emulation is sensitive to stack alignment
- Chrome.dll pattern scanning may fail if the module isn't loaded
- SSL hooks may interfere with certificate validation in some Chromium-based apps

## Debug Commands

Enable Schannel ETW tracing:
```bash
logman start schannel_trace -p "{1f93b400-5cd8-11d1-9f3c-0000f87571e3}" 0xFFFFFFFF 0xFF -ets
```

Stop and view:
```bash
logman stop schannel_trace -ets
# View with PerfView or WPA
``` 