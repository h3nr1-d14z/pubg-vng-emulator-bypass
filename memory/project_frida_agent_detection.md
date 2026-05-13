---
name: frida-agent-detection
description: Anti-cheat detects injected Frida agent via procfs scans; bypassed with file hooks + ptrace hook + late attach
type: project
metadata:
  type: project
---

Anti-cheat does periodic scans (~18-25s interval) to detect Frida agent injection. Even bare `attach()` with empty script kills the game in ~18s.

**Detection vectors blocked:**
1. `/proc/self/maps` showing `frida-agent.so` → redirect to clean fake maps via `open`/`openat`/`fopen` hooks
2. `/proc/self/status` showing `TracerPid != 0` → redirect to fake status
3. `ptrace(PTRACE_TRACEME)` failing → hook `ptrace` and return 0 for `PTRACE_TRACEME`
4. Root paths (`/system/bin/su`, `/magisk`, etc.) → redirect to non-existent path

**Kill mechanism:** When detected, anti-cheat jumps to `0x76388e9830e6` causing access violation. This address is consistent across crashes.

**Working approach:**
- **Late attach** (wait 45s for game to reach main menu, then attach)
- **Clean fake maps** captured from suspended process BEFORE Frida injects
- **File redirection hooks** for `/proc/self/maps`, `/proc/self/status`, `/proc/cpuinfo`, `/system/build.prop`
- **ptrace hook** to block anti-debug
- **Thread renaming** (effect uncertain, but included in working config)

**What does NOT work:**
- Spawn mode (`device.spawn`) — times out or detected during startup
- Bare attach without hiding hooks — detected in ~18s
- Minimal script (property + GPU only, no file hooks) — detected in ~18s

**How to apply:** Always use late attach with file hooks active. Capture clean maps before attaching.
