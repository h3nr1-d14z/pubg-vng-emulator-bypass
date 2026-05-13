---
name: process-naming-discrepancy
description: Frida enumerate_processes reports main process as 'PUBG MOBILE' not package name
metadata:
  type: project
---

**Finding:** Frida's `device.enumerate_processes()` reports the main game process as `PUBG MOBILE` rather than `com.vng.pubgmobile`. The `:plugin` sub-process is also reported as `PUBG MOBILE`.

**Impact:** Scripts checking for `p.name == "com.vng.pubgmobile"` fail to find the process. This caused false "process died" reports in early tests.

**Fix:** Search for processes containing `PUBG` or matching `PUBG MOBILE` exactly:
```python
def find_pubg(device):
    for p in device.enumerate_processes():
        if p.name == "PUBG MOBILE":
            return p.pid
    return None
```

**How to apply:** Always use `PUBG MOBILE` as the process name for Frida operations on this game.
