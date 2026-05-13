# Memory Index

## Project Context
- [Anti-cheat detects frida-server by process name](project_frida_server_detection.md) — Hidden server via symlink to `system_daemon`
- [Frida agent injection detected via file/ptrace scans](project_frida_agent_detection.md) — Late attach + file hooks + ptrace hook bypasses detection
- [Network hooks trigger anti-cheat kill](project_network_hooks_detected.md) — `send`/`recv` libc hooks detected; need alternative
- [Java bridge broken on LD Player](project_ldplayer_java_broken.md) — Frida Java unavailable; use native hooks only
- [Process naming discrepancy](project_process_naming.md) — Frida reports `PUBG MOBILE` not `com.vng.pubgmobile`
- [Working bypass architecture](project_working_bypass.md) — Late attach + clean fake maps + property/GPU/file/ptrace hooks
