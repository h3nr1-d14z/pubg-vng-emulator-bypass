---
name: network-hooks-detected
description: libc send/recv hooks trigger anti-cheat kill at ~22s; stealth without network hooks survives 90s+
metadata:
  type: project
---

**Finding:** Adding `send`/`recv`/`connect` libc hooks to the working stealth bypass causes the game to crash at ~22s (same kill address `0x76388e9830e6`). Without network hooks, the game survives 90s+.

**Evidence:**
- Bare attach: crash at 18s
- Minimal bypass (prop + GPU, no file hooks): crash at 18s
- Full bypass (prop + GPU + file + network): crash at 25s
- **Stealth bypass (prop + GPU + file + ptrace, NO network): survives 90s**
- Final bypass (stealth + network hooks): crash at 22s

**Likely cause:** Anti-cheat detects `send`/`recv` hook prologues via integrity scan, OR timing analysis on network calls detects hook overhead.

**Alternatives to explore:**
1. Hook `SSL_write`/`SSL_read` in `libssl.so` instead of raw socket functions
2. Hook game's internal ANOGS packet builder (requires RE)
3. Java-level socket hooks (if Java bridge worked)
4. Optimize network hooks with minimal memory reads (early magic byte check without full `readByteArray`)

**How to apply:** For a stable bypass, omit libc `send`/`recv` hooks. Focus on client-side detection vectors (properties, files, GPU, ptrace). Server-side telemetry patching may require a different interception method.
