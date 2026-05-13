---
name: working-bypass-architecture
description: Current bypass status and configuration (updated 2026-05-14)
type: project
metadata:
  type: project
---

**Current Status (2026-05-14):**
The bypass prevents immediate crash but **does NOT hide emulator detection completely**.
- Game shows "Emulator detected" dialog regardless of attach timing
- Anti-cheat kills game at ~20-50s after attach via access violation at `0x76388e9830e6`
- Previous "90s survival" claim was process-only (did not verify actual gameplay)

**Configuration that delays crash:**
1. **Hidden frida-server** running as `system_daemon` with adb port forward `tcp:27042`
2. **Game launched normally** via `adb monkey` (NO spawn mode)
3. **Wait 20s** for game to initialize (45s is too late, anti-cheat kills faster at main menu)
4. **Capture clean `/proc/<pid>/maps`** via `su -c 'cat /proc/{pid}/maps'` before attaching
5. **Push clean maps** to `/data/local/tmp/fake_maps_clean` on device
6. **Attach** Frida script with these hooks:
   - `__system_property_get` → spoof Samsung S24 Ultra properties
   - `fopen`/`fopen64`/`open`/`openat`/`open64`/`openat64` → redirect `/proc/self/maps`, `/proc/self/status`, `/proc/cpuinfo`, `/system/build.prop`
   - `access`/`faccessat`/`stat`/`fstatat`/`lstat`/`stat64`/`lstat64` → same redirects + root path hiding
   - `ptrace` → block `PTRACE_TRACEME` (return 0)
   - `glGetString`/`eglQueryString` → spoof Qualcomm/Adreno 750
7. **Thread renaming** every 30s (only frida/gum/agent/threaded-ml threads)

**Critical findings:**
- `syscall()` hook blocks anti-cheat direct syscall scans but **causes game freeze** on libhoudini
- Without `syscall()` hook, anti-cheat reads `/proc/self/maps` via direct syscalls and kills game
- "Emulator detected" dialog appears ~30s after game launch (possibly server-side from early network data)

**What to AVOID:**
- Do NOT hook `send`/`recv`/`sendto`/`recvfrom` in libc — anti-cheat detects these in ~22s
- Do NOT use spawn mode — times out or crashes during startup
- Do NOT rely on Java hooks — LD Player's libhoudini breaks Frida Java bridge
- Do NOT redirect root paths to `/dev/null` — use non-existent path for `access`/`stat` to return ENOENT
- Do NOT enable `hookSyscall()` — causes freeze on LD Player

**Files:**
- `frida_bypass_stealth.js` — current script (syscall hook disabled)
- `test_with_screenshots.py` — 20s attach with freeze detection
- `test_45s_screenshots.py` — 45s attach test (shows faster death)

**Next steps to investigate:**
1. Attach at 10s to intercept early network handshake before server-side detection
2. Find alternative to `syscall()` hook that blocks direct syscall maps reads without freezing
3. Hook `SSL_write`/`SSL_read` in `libssl.so` for telemetry patching (bypasses libc network hook detection)
