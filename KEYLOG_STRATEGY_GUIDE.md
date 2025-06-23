# Key-Log-Only Strategy for SSL/TLS Interception

## Overview

The key-log-only strategy is a minimal, non-intrusive approach to capturing SSL/TLS traffic. Instead of hooking SSL_write/SSL_read functions (which can interfere with handshakes and certificate validation), we only hook SSL_new to set up keylog callbacks.

## How It Works

1. **Hook only SSL_new**: When a new SSL session is created, we register a keylog callback
2. **Capture session keys**: The callback receives TLS session keys in NSS Key Log Format
3. **Write to keylog file**: Keys are saved to `%TEMP%\ai_hook_keylog.txt`
4. **Use with Wireshark**: The keylog file can decrypt captured traffic in Wireshark

## Benefits

✅ **No handshake interference**: We don't touch SSL_write/SSL_read, avoiding certificate validation issues
✅ **Compatible with Windows on ARM**: Minimal hooks reduce compatibility problems
✅ **Standard format**: Uses NSS Key Log Format, compatible with Wireshark/Chrome DevTools
✅ **Reliable**: Works with all SSL/TLS versions supported by the application

## Usage

### 1. Run the application with injection
```bash
.\ai_injector.exe "C:\Path\to\application.exe"
```

### 2. Check the keylog file
The SSL keys are written to:
```
%TEMP%\ai_hook_keylog.txt
```

### 3. Capture network traffic
Use Wireshark or another packet capture tool to record the encrypted traffic.

### 4. Decrypt in Wireshark
1. Open the capture file in Wireshark
2. Go to: Edit → Preferences → Protocols → TLS
3. Set "(Pre)-Master-Secret log filename" to the keylog file path
4. Click OK - traffic will be decrypted automatically

## Log Output

When the key-log-only strategy is active, you'll see:
```
[SSL] Installing SSL keylog-only hooks
[SSL] Found essential SSL functions for keylogging via GetProcAddress
[SSL] Attached to SSL_new for keylog-only strategy
[SSL] SSL keylog-only hooks installed successfully
[SSL] SSL keylog file: C:\Users\...\AppData\Local\Temp\ai_hook_keylog.txt
```

## Keylog File Format

The file contains lines in NSS Key Log Format:
```
CLIENT_RANDOM <client_random> <master_secret>
CLIENT_TRAFFIC_SECRET_0 <client_random> <secret>
SERVER_TRAFFIC_SECRET_0 <client_random> <secret>
```

## Environment Variables

- `AITI_DISABLE_SSL_HOOKS=1` - Completely disable SSL hooks (including keylogging)

## Configuration

Add process names to `config/aiti_config.json` to skip SSL hooks entirely:
```json
{
  "skip_ssl": ["problematic_app.exe"]
}
```

## Troubleshooting

### No keylog entries
- Check if the application uses SSL/TLS
- Verify SSL functions were found in the log
- Ensure the process has write access to %TEMP%

### Wireshark doesn't decrypt
- Verify the keylog file path is correct
- Check that the keylog file contains entries
- Ensure you captured the full TLS handshake

### Application crashes
- Use `AITI_DISABLE_SSL_HOOKS=1` to test without SSL hooks
- Add the application to the skip_ssl list in config

## Technical Details

### Functions Hooked
- `SSL_new` - To register keylog callback via SSL_CTX_set_keylog_callback

### Functions Used (not hooked)
- `SSL_get_servername` - For host identification in logs
- `SSL_CTX_set_keylog_callback` - To register our callback

### Functions NOT Hooked (key-log-only)
- `SSL_write` - Avoided to prevent handshake interference
- `SSL_read` - Avoided to prevent certificate validation issues

## Comparison with Full SSL Hooks

| Feature | Full Hooks | Key-Log-Only |
|---------|------------|--------------|
| Real-time data capture | ✅ Yes | ❌ No |
| Requires packet capture | ❌ No | ✅ Yes |
| Certificate validation issues | ⚠️ Possible | ✅ None |
| Windows on ARM compatibility | ⚠️ Issues | ✅ Works |
| Performance impact | Medium | Minimal |
| Wireshark integration | ❌ Manual | ✅ Native | 