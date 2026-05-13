---
name: ldplayer-java-broken
description: Frida Java bridge is completely unavailable on LD Player; all Java hooks fail silently
metadata:
  type: project
---

**Finding:** On LD Player with libhoudini ARM64-to-x86_64 translation, `Java.available` is always false. `Java.perform` throws errors. The Frida Java bridge is non-functional.

**Impact:**
- Cannot hook `android.os.Build` fields
- Cannot hook `SystemProperties.get()` Java implementation
- Cannot use `javax.crypto.Cipher` for AES operations in script
- All Java-layer anti-cheat hooks (HawkNative, PackageManager, Telephony) are inactive

**Workaround:** All bypass logic must be implemented via native libc hooks (`__system_property_get`, `fopen`, `open`, `glGetString`, etc.).

**How to apply:** Design bypass scripts assuming Java is unavailable. Use native property hooks as the primary spoofing mechanism. Pre-calculate any values that would require Java (e.g., device hash) and hardcode them.
