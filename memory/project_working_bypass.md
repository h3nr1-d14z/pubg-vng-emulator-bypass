---
name: working-bypass-architecture
description: Stable late-attach bypass configuration that prevents game crash
type: project
metadata:
  type: project
---

**Stable configuration (survives 90s+ test):**
1. **Hidden frida-server** running as `system_daemon` with adb port forward `tcp:27042`
2. **Game launched normally** via `adb monkey` (NO spawn mode)
3. **Wait 45s** for game to reach main menu
4. **Capture clean `/proc/<pid>/maps`** via `su -c 'cat /proc/{pid}/maps'` before attaching
5. **Push clean maps** to `/data/local/tmp/fake_maps_clean` on device
6. **Late attach** Frida script with these hooks:
   - `__system_property_get` → spoof Samsung S24 Ultra properties
   - `fopen`/`fopen64`/`open`/`openat`/`open64`/`openat64` → redirect `/proc/self/maps`, `/proc/self/status`, `/proc/cpuinfo`, `/system/build.prop`
   - `access`/`faccessat`/`stat`/`fstatat`/`lstat`/`stat64`/`lstat64` → same redirects + root path hiding
   - `ptrace` → block `PTRACE_TRACEME` (return 0)
   - `glGetString`/`eglQueryString` → spoof Qualcomm/Adreno 750
7. **Thread renaming** every 5s (rename pool/agent/gum/frida threads to normal names)

**What to AVOID:**
- Do NOT hook `send`/`recv`/`sendto`/`recvfrom` in libc — anti-cheat detects these in ~22s
- Do NOT use spawn mode — times out or crashes during startup
- Do NOT rely on Java hooks — LD Player's libhoudini breaks Frida Java bridge
- Do NOT redirect root paths to `/dev/null` — use non-existent path for `access`/`stat` to return ENOENT

**Files:**
- `frida_bypass_stealth.js` — stable script without network hooks
- `test_late_attach_stealth.py` — working test launcher
