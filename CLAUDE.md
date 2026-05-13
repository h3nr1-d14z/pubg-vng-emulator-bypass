# PUBG Mobile VNG - Frida Emulator Bypass

## Project Overview

This project contains a Frida-based bypass script to evade emulator detection in PUBG Mobile VNG (`com.vng.pubgmobile`) running on LD Player. The script intercepts system calls, file reads, property lookups, and network traffic to spoof a real Samsung S24 Ultra device.

## Architecture

- `frida_bypass_diag.js` — Main Frida script (diagnostic version with error wrapping)
- `spawn_game.py` — Python launcher that spawns the game and attaches the bypass script to both main and plugin processes
- `frida_bypass.js` — Backup/original script without diagnostic wrappers

## Key Components

### 1. System Property Spoofing (`hookPropertyGet`)
Intercepts `__system_property_get` to return fake Samsung S24 Ultra properties (e.g., `ro.product.model=SM-S928B`, `ro.hardware=qcom`).

### 2. File Path Redirection (`redirectPath`)
Redirects reads from:
- `/proc/cpuinfo` → `/data/local/tmp/fake_cpuinfo`
- `/system/build.prop` → `/data/local/tmp/fake_build.prop`
- `/proc/self/status` → `/data/local/tmp/fake_status`
- `/proc/self/maps` → `/data/local/tmp/fake_maps`

Hooks: `fopen`, `fopen64`, `open`, `openat`, `access`, `faccessat`, `stat`, `lstat`.

### 3. GPU Spoofing (`hookGlGetString`, `hookEglQueryString`)
Fakes OpenGL/EGL vendor and renderer strings to report Qualcomm / Adreno (TM) 750.

### 4. Network Interception (`hookSend`, `hookRecv`, `hookWriteRead`, `hookSSL`)
- Intercepts `send`/`recv`, `write`/`read`, and `SSL_write`/`SSL_read`
- Detects ANOGS protocol packets (magic `0x3366`)
- Extracts AES key from `0x1002` auth response
- Decrypts, patches, and re-encrypts `0x4013` telemetry packets

### 5. Java Hooks (`installJavaHooks`)
Modifies `android.os.Build` fields (MODEL, DEVICE, MANUFACTURER, etc.) and `SystemProperties.get()`.

## Prerequisites

- Android emulator (LD Player) with PUBG Mobile VNG installed
- Frida server running on the emulator (`frida-server` binary pushed and executed)
- Python 3 + `frida` pip package (`pip install frida`)
- Fake files prepared on emulator:
  ```bash
  adb shell "echo 'ARM CPU info' > /data/local/tmp/fake_cpuinfo"
  adb shell "echo 'ro.product.model=SM-S928B' > /data/local/tmp/fake_build.prop"
  adb shell "echo 'Name:   pubgmobile' > /data/local/tmp/fake_status"
  adb shell "echo 'fake maps' > /data/local/tmp/fake_maps"
  ```

## How to Run

### Local (Windows/Mac where emulator is running)
```bash
python spawn_game.py
```

The script will:
1. Spawn `com.vng.pubgmobile`
2. Attach `frida_bypass_diag.js` to the main process
3. Resume the game
4. Detect and attach to the `:plugin` process automatically
5. Keep running until Ctrl+C

### Remote Debugging (Advanced)
If running Frida from a different machine than the emulator, ensure adb over network is configured and the emulator is discoverable via `adb connect <IP>:5555`.

## Important Notes

- The script is designed for **spawn mode** (`device.spawn`). Do not attach after the game has fully loaded, or Java hooks may miss the initialization window.
- If `Java.available` never becomes true in spawn mode, Java hooks will be skipped. This is a known limitation.
- LD Player runs arm64 apps via `libhoudini`/`libnb` on x86_64. Only one `libc.so` exists (`/system/lib64/libc.so`).
- The game links with `libssl.so` and `libcrypto.so` for TLS.

## Troubleshooting

| Issue | Cause | Fix |
|-------|-------|-----|
| `device not found` | No emulator connected | Check `adb devices` |
| `emulator-5554 offline` | ADB daemon issue | `adb kill-server && adb start-server` |
| `TypeError: not a function` | Invalid memory read | Fixed by `readBufferSafe()` wrapper |
| Emulator dialog still appears | Detection vector not covered | Check GPU hooks, SSL hooks, or server-side detection |
| `Java never became available` | JVM not initialized yet | Normal in spawn mode; hooks will be skipped |

## File Layout

```
/
├── frida_bypass_diag.js   # Main bypass script (use this)
├── spawn_game.py          # Launcher for main + plugin processes
├── frida_bypass.js        # Original script (backup)
├── fake_cpuinfo           # Fake /proc/cpuinfo content
├── fake_build.prop        # Fake /system/build.prop content
├── fake_status            # Fake /proc/self/status content
└── fake_maps              # Fake /proc/self/maps content
```

## Root Detection & Network Error

In addition to emulator detection, PUBG Mobile VNG checks for root access. If root is detected, the server may return a network error instead of showing the emulator dialog. The bypass script must hide root indicators.

### Root Detection Vectors to Hide

- **SU binaries**: `/system/bin/su`, `/system/xbin/su`, `/sbin/su`, `/su/bin/su`, `/data/local/xbin/su`, `/data/local/bin/su`
- **Root apps**: `/system/app/Superuser.apk`, `/system/priv-app/Superuser.apk`
- **Magisk paths**: `/data/adb/magisk/`, `/sbin/.magisk/`
- **System properties**: `ro.secure=1`, `ro.debuggable=0`
- **Build tags**: `ro.build.tags=release-keys` (must not contain "test-keys")

### How to Hide Root in Frida

Extend `redirectPath()` in `frida_bypass_diag.js` to intercept `access`/`faccessat`/`stat`/`lstat` for the above paths and return `ENOENT` (file not found). Also extend `hookPropertyGet()` to return the safe values for `ro.secure` and `ro.debuggable`.

If using Magisk, enable **Magisk Hide** or **Zygisk DenyList** for `com.vng.pubgmobile` alongside the Frida bypass.

## Next Steps / TODO

- [ ] Verify network hooks actually intercept ANOGS 0x4013 packets
- [ ] Add syscall-based `connect`/`send`/`recv` bypass if libc hooks miss
- [ ] Test against updated game versions
- [ ] Investigate plugin-process-specific detection vectors (SMInterceptor)
- [ ] Add root-hide hooks (`su` binaries, Magisk paths) to prevent network error
