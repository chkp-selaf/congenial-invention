# AI Traffic Interceptor - Debugging Guide

## Overview

This guide provides comprehensive information on debugging the AI Traffic Interceptor project. The project now includes extensive logging capabilities to help diagnose issues with DLL injection, API hooking, and traffic interception.

## Logging Architecture

### 1. DLL Hook Logging (ai_hook.dll)

The DLL uses a multi-target logging system:

- **File Logging**: Logs are written to `%TEMP%\ai_hook_<PID>_<timestamp>.log`
- **Debug Output**: All logs are sent to Windows Debug Output (viewable with DebugView)
- **ETW (Event Tracing for Windows)**: Critical events are traced via ETW
- **Console Output**: Error messages can be output to console (disabled by default)

#### Log Levels

- `TRACE`: Very detailed information for debugging
- `DEBUG`: Detailed information useful for diagnosing issues
- `INFO`: General informational messages
- `WARN`: Warning messages for potentially problematic situations
- `ERROR`: Error messages for failures
- `CRITICAL`: Critical errors that may cause system failure

#### Log Format

```
[2024-01-01 12:00:00.123] [LEVEL] [PID:1234] [TID:5678] [Component] Message
```

### 2. Injector Logging (ai_injector.exe)

The injector logs to:
- Console output (stdout/stderr)
- Windows Debug Output

### 3. Collector Logging (ai_collector.exe)

Uses Serilog with:
- Console output (INFO level and above)
- Rolling file logs in `logs/aiti-collector-YYYYMMDD.log`

## Finding Log Files

### Method 1: Using the Log Analyzer Tool

```bash
# Find all recent log files
log_analyzer.exe --find-logs

# Analyze a specific log file
log_analyzer.exe C:\Users\<username>\AppData\Local\Temp\ai_hook_1234_20240101_120000.log
```

### Method 2: Manual Search

1. Open `%TEMP%` in Windows Explorer
2. Search for files starting with `ai_hook_`
3. Sort by date modified to find recent logs

### Method 3: PowerShell

```powershell
# Find all AI hook log files
Get-ChildItem $env:TEMP -Filter "ai_hook_*.log" | Sort-Object LastWriteTime -Descending

# View the most recent log
Get-Content (Get-ChildItem $env:TEMP -Filter "ai_hook_*.log" | Sort-Object LastWriteTime -Descending | Select-Object -First 1).FullName
```

## Common Debugging Scenarios

### 1. DLL Injection Failures

**Symptoms**: Process starts but no interception occurs

**Debug Steps**:

1. Check injector output for errors:
   ```
   ai_injector.exe notepad.exe
   ```

2. Look for architecture mismatch warnings:
   ```
   [ERROR] CRITICAL: Architecture Mismatch!
   Injector is: x64
   Target EXE is: ARM64
   ```

3. Verify DLL exists at expected path:
   ```
   [ERROR] CRITICAL: DLL not found at path: C:\path\to\ai_hook.dll
   ```

4. Check Windows Event Log for loader errors

### 2. Hook Installation Failures

**Symptoms**: DLL loads but no API calls intercepted

**Debug Steps**:

1. Check DLL log file for hook installation:
   ```
   [INFO] [Hooks] Beginning hook installation
   [INFO] [Hooks] Installing WinHTTP hooks
   [ERROR] [Hooks] DetourTransactionCommit failed with error: 5
   ```

2. Verify target process uses expected APIs:
   - WinHTTP APIs for HTTP traffic
   - OpenSSL/BoringSSL for HTTPS in Chrome/Electron
   - Schannel for Windows native HTTPS

3. Check for SSL function discovery:
   ```
   [INFO] [SSL] Attempting to find SSL functions from module exports
   [WARN] [SSL] Not all SSL functions found via exports
   ```

### 3. Pipe Communication Failures

**Symptoms**: Hooks work but no data reaches collector

**Debug Steps**:

1. Ensure collector is running before target process:
   ```
   # Terminal 1
   ai_collector.exe --verbose
   
   # Terminal 2
   ai_injector.exe target.exe
   ```

2. Check pipe connection logs:
   ```
   [DEBUG] [PipeClient] Attempting to connect to named pipe
   [ERROR] [PipeClient] Failed to connect to pipe (error: 2) - collector may not be running
   ```

3. Verify pipe name matches (should be `\\.\pipe\ai-hook`)

### 4. SSL/TLS Interception Issues

**Symptoms**: HTTP traffic captured but not HTTPS

**Debug Steps**:

1. Check SSL hook status in logs:
   ```
   [INFO] [SSL] Found SSL_write in node.dll
   [INFO] [SSL] Installing SSL hooks
   ```

2. For Chrome/Electron, verify chrome.dll is loaded:
   ```
   [WARN] [SSL] Target module (e.g., chrome.dll) not found
   ```

3. Enable SSL keylogging:
   ```
   [INFO] [SSL] Registered SSL keylog callback for a new SSL_CTX
   ```

## Using Debug Tools

### 1. DebugView (Sysinternals)

1. Download DebugView from Microsoft Sysinternals
2. Run as Administrator
3. Enable "Capture Win32" and "Capture Global Win32"
4. Filter for `[AI-Hook]` or `[AI-Injector]`

### 2. Process Monitor

1. Filter for process name containing "ai_"
2. Look for:
   - DLL load events
   - Registry access
   - File access to config/DLLs

### 3. WPA (Windows Performance Analyzer)

For ETW traces:
1. Start trace: `wpr -start GeneralProfile`
2. Reproduce issue
3. Stop trace: `wpr -stop trace.etl`
4. Analyze with WPA

## Debugging Specific Components

### WinHTTP Hooks

Look for these log entries:
```
[TRACE] [WinHTTP] WinHttpSendRequest called - hRequest: 0x12345678, dataLength: 1024
[INFO] [WinHTTP] Intercepted WinHttpSendRequest - URL: https://api.openai.com/v1/chat/completions, Size: 1024 bytes
[DEBUG] [WinHTTP] Request data [Data: Length=1024, Hex=7b226d6f64656c223a...]
```

### SSL Hooks

Check for:
```
[TRACE] [SSL] SSL_write called - ssl: 0x12345678, dataLen: 512
[INFO] [SSL] Intercepted SSL_write - Server: api.openai.com, Size: 512 bytes
```

### Schannel Hooks

Monitor:
```
[INFO] [Hooks] Installing Schannel hooks
[INFO] [SchannelAcquireCred] grbitEnabledProtocols: 0x800, dwFlags: 0x4
```

## Performance Debugging

### 1. Check Log File Sizes

Large log files may impact performance:
```powershell
Get-ChildItem $env:TEMP -Filter "ai_hook_*.log" | Select-Object Name, @{Name="SizeMB";Expression={$_.Length/1MB}}
```

### 2. Adjust Log Levels

In code, modify minimum log level:
```cpp
Logger::GetInstance()->SetMinLevel(LogLevel::INFO); // Skip TRACE/DEBUG
```

### 3. Disable Specific Outputs

```cpp
Logger::GetInstance()->SetFileEnabled(false);      // Disable file logging
Logger::GetInstance()->SetDebugOutputEnabled(false); // Disable OutputDebugString
```

## Troubleshooting Checklist

- [ ] Correct architecture (x64/ARM64) for all components
- [ ] Collector running before injection
- [ ] Target process uses supported APIs (WinHTTP/OpenSSL/Schannel)
- [ ] No antivirus blocking DLL injection
- [ ] Sufficient permissions (may need elevation)
- [ ] Config file present and valid JSON
- [ ] DLL dependencies available (VCRUNTIME, etc.)

## Advanced Debugging

### 1. Enable Verbose Mode

For collector:
```bash
ai_collector.exe --verbose
```

### 2. Attach Debugger

1. Build in Debug configuration
2. Attach to target process after injection
3. Set breakpoints in hook functions

### 3. Custom Log Analysis

Use the log analyzer tool:
```bash
log_analyzer.exe <logfile>
```

Output includes:
- Log level distribution
- Component activity
- Error summary
- Hook call counts

## Getting Help

When reporting issues, include:

1. Log files from:
   - Injector console output
   - DLL hook log (`%TEMP%\ai_hook_*.log`)
   - Collector log (`logs\aiti-collector-*.log`)

2. System information:
   - Windows version
   - Process architecture
   - Target application

3. Steps to reproduce

4. Output from diagnostic tools:
   ```bash
   dll_diag.exe target_process.exe
   log_analyzer.exe --find-logs
   ``` 