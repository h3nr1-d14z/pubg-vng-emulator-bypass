---
name: frida-server-detection
description: Anti-cheat detects frida-server by process name; bypassed via symlink rename + remote device
metadata:
  type: project
---

Anti-cheat scans running processes for `frida-server` by name. If found, game refuses to start or crashes immediately.

**Bypass:**
1. Rename `frida-server` binary or create symlink: `/data/local/tmp/system_daemon -> /data/local/tmp/frida-server`
2. Launch hidden server: `nohup /data/local/tmp/system_daemon >/dev/null 2>&1 &`
3. Connect Frida client via `add_remote_device("127.0.0.1:27042")` instead of `get_usb_device()`
4. Set up adb port forward: `adb forward tcp:27042 tcp:27042`

**Why:** Direct `get_usb_device()` connects via ADB which may interact with the visible frida-server process. Remote device connection goes through localhost forward and doesn't expose the process name.

**Verification:** Game survives 60s+ with hidden frida-server and NO Frida attachment. Empty script attachment still crashes (agent injection is separately detected).
