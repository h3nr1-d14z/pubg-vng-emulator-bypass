# PUBG Mobile VNG - Frida Emulator Bypass

## Project Overview

This project contains a Frida-based bypass script to evade emulator detection in PUBG Mobile VNG (`com.vng.pubgmobile`) running on LD Player. The script intercepts system calls, file reads, property lookups, and GPU queries to spoof a real Samsung S24 Ultra device.

## Architecture

- **`frida_bypass_stealth.js`** — Main working bypass script (stealth version with thread rename, file hooks, ptrace block)
- **`spawn_game.py`** — Python launcher using **late attach** (game launches normally, then Frida attaches after main menu)
- `frida_bypass_diag.js` — Diagnostic/original script with network hooks (unstable, crashes at ~25s)
- `frida_bypass_final.js` — Combined stealth + network hooks (network hooks detected by anti-cheat)
- `frida_bypass_minimal.js` — Minimal test script (property + GPU only)
- `frida_empty.js` — Empty script for baseline detection testing
- `frida_block_crash.js` — Crash blocker (abort/exit/tgkill/raise hooks)

## Key Components

### 1. System Property Spoofing (`hookPropertyGet`)
Intercepts `__system_property_get` to return fake Samsung S24 Ultra properties (e.g., `ro.product.model=SM-S928B`, `ro.hardware=qcom`).

### 2. File Path Redirection (`redirectPath`)
Redirects reads from:
- `/proc/cpuinfo` → `/data/local/tmp/fake_cpuinfo`
- `/system/build.prop` → `/data/local/tmp/fake_build.prop`
- `/proc/self/status` → `/data/local/tmp/fake_status`
- `/proc/self/maps` → clean captured maps file

Hooks: `fopen`, `fopen64`, `open`, `openat`, `open64`, `openat64`, `access`, `faccessat`, `stat`, `fstatat`, `lstat`, `stat64`, `lstat64`.

### 3. GPU Spoofing (`hookGlGetString`, `hookEglQueryString`)
Fakes OpenGL/EGL vendor and renderer strings to report Qualcomm / Adreno (TM) 750.

### 4. Ptrace Anti-Debug Block (`hookPtrace`)
Blocks `ptrace(PTRACE_TRACEME)` by returning 0, preventing anti-cheat from detecting debugger attachment.

### 5. Thread Renaming (`renameFridaThreads`)
Renames Frida/agent threads to normal Android thread names (e.g., `RenderThread`, `WorkerThread`) to evade thread-name scanning.

## Anti-Cheat Detection Vectors (Documented)

| Vector | Detection Method | Bypass |
|--------|-----------------|--------|
| `frida-server` process name | Scans running processes | Rename to `system_daemon` via symlink |
| `/proc/self/maps` | Reads via `open`/`fopen` | File hooks redirect to clean fake maps |
| `/proc/self/status` | Checks `TracerPid` | File hooks redirect to fake status |
| `ptrace(PTRACE_TRACEME)` | Fails if already traced | Hook `ptrace` and return 0 |
| Root paths (`/system/bin/su`, etc.) | `access`/`stat` checks | Redirect to non-existent path |
| `libc.so` `send`/`recv` hooks | Prologue/timing scan | **Detected** — do not use |
| Thread names (`gum-js-loop`) | `/proc/self/task` scan | Rename threads periodically |

**Kill mechanism:** When detected, anti-cheat jumps to `0x76388e9830e6` causing an access violation (SIGSEGV). This address is consistent across all crash instances.

## Prerequisites

- Android emulator (LD Player) with PUBG Mobile VNG installed
- **Hidden Frida server** running on the emulator:
  ```bash
  adb shell "ln -s /data/local/tmp/frida-server /data/local/tmp/system_daemon"
  adb shell "nohup /data/local/tmp/system_daemon >/dev/null 2>&1 &"
  adb forward tcp:27042 tcp:27042
  ```
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
1. Verify hidden `system_daemon` (frida-server) is running
2. Launch `com.vng.pubgmobile` via `adb monkey` (NO spawn mode — anti-cheat detects startup suspension)
3. Wait **20 seconds** for the game to initialize
4. Capture clean `/proc/<pid>/maps` from the running process
5. Attach `frida_bypass_stealth.js` to the main process
6. Detect and attach to the `:plugin` process automatically
7. Keep running until Ctrl+C

### Why Late Attach?

**Spawn mode (`device.spawn`) is detected by the anti-cheat** — the game either times out or crashes during startup when launched in a suspended state. The anti-cheat likely checks for `TracerPid` or ptrace suspension during early init.

Late attach (after the game has naturally started) bypasses this because:
- Frida is not present during the anti-cheat's early initialization
- The process is not in a suspended/ptraced state when the game starts
- Our hooks are installed before the periodic scan at ~18-25s

## Important Notes

- **Do NOT use spawn mode**. The launcher uses `adb monkey` to start the game normally, then attaches Frida after a delay.
- If `Java.available` is false, Java hooks are skipped. This is **normal on LD Player** — libhoudini breaks Frida's Java bridge. Native hooks handle all spoofing.
- LD Player runs arm64 apps via `libhoudini`/`libnb` on x86_64. Only one `libc.so` exists (`/system/lib64/libc.so`).
- The game links with `libssl.so` and `libcrypto.so` for TLS.
- Frida reports the main process as `PUBG MOBILE`, not `com.vng.pubgmobile`.

## Troubleshooting

| Issue | Cause | Fix |
|-------|-------|-----|
| `device not found` | No emulator connected | Check `adb devices` |
| `emulator-5554 offline` | ADB daemon issue | `adb kill-server && adb start-server` |
| `need Gadget to attach on jailed Android` | frida-server not found or not hidden | Start `system_daemon` and set port forward |
| Game dies at ~18s after attach | Bare Frida detected via maps/ptrace | Use `frida_bypass_stealth.js` with file hooks + ptrace hook |
| Game dies at ~22s with network hooks | `send`/`recv` hooks detected by anti-cheat | Remove libc network hooks from script |
| Emulator dialog still appears | Client-side detection bypassed but server-side detected | Network telemetry patching not yet implemented (send/recv hooks unstable) |
| `Java never became available` | JVM not initialized or libhoudini incompatibility | Normal on LD Player; native hooks handle spoofing |
| Plugin process not found | Wrong process name in detection logic | Plugin is `com.vng.pubgmobile:plugin`, not `PUBG MOBILE` |

## Root Detection & Network Error

In addition to emulator detection, PUBG Mobile VNG checks for root access. If root is detected, the server may return a network error instead of showing the emulator dialog.

### Root Detection Vectors to Hide

- **SU binaries**: `/system/bin/su`, `/system/xbin/su`, `/sbin/su`, `/su/bin/su`
- **Root apps**: `/system/app/Superuser.apk`, `/system/priv-app/Superuser.apk`
- **Magisk paths**: `/data/adb/magisk/`, `/sbin/.magisk/`
- **System properties**: `ro.secure=1`, `ro.debuggable=0`
- **Build tags**: `ro.build.tags=release-keys` (must not contain "test-keys")

### How to Hide Root in Frida

The `redirectPath()` function in `frida_bypass_stealth.js` already intercepts `access`/`faccessat`/`stat`/`lstat` for root paths and redirects them to `/data/local/tmp/.nonexistent_root_hide`, causing `ENOENT` (file not found). `hookPropertyGet()` returns safe values for `ro.secure` and `ro.debuggable`.

If using Magisk, enable **Magisk Hide** or **Zygisk DenyList** for `com.vng.pubgmobile` alongside the Frida bypass.

## File Layout

```
/
├── frida_bypass_stealth.js   # Main working bypass script (USE THIS)
├── spawn_game.py             # Launcher for late attach to main + plugin
├── frida_bypass_diag.js      # Diagnostic script with network hooks (unstable)
├── frida_bypass_final.js     # Combined stealth + network (network detected)
├── frida_bypass_minimal.js   # Minimal test script
├── frida_empty.js            # Empty script for baseline testing
├── frida_block_crash.js      # Crash blocker
├── memory/                   # Documented findings from debugging
│   ├── MEMORY.md
│   ├── project_frida_agent_detection.md
│   ├── project_frida_server_detection.md
│   ├── project_ldplayer_java_broken.md
│   ├── project_network_hooks_detected.md
│   ├── project_process_naming.md
│   └── project_working_bypass.md
├── fake_cpuinfo              # Fake /proc/cpuinfo content
├── fake_build.prop           # Fake /system/build.prop content
├── fake_status               # Fake /proc/self/status content
└── fake_maps                 # Fake /proc/self/maps content
```

## Next Steps / TODO

- [x] Fix game crash after main menu (stable with late attach + stealth bypass)
- [x] Hide frida-server process name (`system_daemon` symlink)
- [x] Block `/proc/self/maps` detection with clean fake maps + file hooks
- [x] Block `ptrace` anti-debug
- [x] Detect and attach to `:plugin` process
- [ ] **Find alternative to `send`/`recv` hooks for ANOGS telemetry patching** (libc hooks detected)
  - Option A: Hook `SSL_write`/`SSL_read` in `libssl.so` instead of raw sockets
  - Option B: Hook game's internal ANOGS packet builder (requires RE)
  - Option C: Java-level socket hooks (blocked by broken Java bridge on LD Player)
- [ ] Test actual gameplay to verify no emulator dialog or network error
- [ ] Test against updated game versions
- [ ] Investigate if 20s wait can be reduced further (attach earlier for more protection)
