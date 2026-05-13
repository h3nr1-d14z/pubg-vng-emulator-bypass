# PUBG Mobile VNG Emulator Bypass

Bypass emulator detection for PUBG Mobile VNG on LD Player using Frida.

## Quick Start

1. **Prepare fake files on emulator:**
   ```bash
   adb shell "echo 'ARM CPU info' > /data/local/tmp/fake_cpuinfo"
   adb shell "echo 'ro.product.model=SM-S928B' > /data/local/tmp/fake_build.prop"
   adb shell "echo 'Name:   pubgmobile' > /data/local/tmp/fake_status"
   adb shell "echo 'fake maps' > /data/local/tmp/fake_maps"
   ```

2. **Start Frida server on emulator:**
   ```bash
   adb shell "/data/local/tmp/frida-server &"
   ```

3. **Run the bypass:**
   ```bash
   pip install frida
   python spawn_game.py
   ```

## Requirements

- LD Player (or Android emulator) with PUBG Mobile VNG installed
- `frida-server` binary matching your Frida client version on the emulator
- Python 3.8+ with `frida` package
- `adb` accessible in PATH

## Files

| File | Description |
|------|-------------|
| `frida_bypass_diag.js` | Main Frida bypass script with diagnostic logging |
| `spawn_game.py` | Python launcher attaching to main + plugin processes |
| `frida_bypass.js` | Original script (backup without diagnostics) |

## How It Works

The script intercepts multiple detection vectors:

- **System Properties** — Fakes `ro.product.model`, `ro.hardware`, etc.
- **File Reads** — Redirects `/proc/cpuinfo`, `/system/build.prop`, `/proc/self/status`, `/proc/self/maps`
- **GPU Strings** — Spoofs OpenGL/EGL vendor/renderer to Qualcomm/Adreno
- **Network** — Patches ANOGS telemetry packet `0x4013` with fake device data
- **Java Build** — Modifies `android.os.Build` fields at runtime

## Known Limitations

- Spawn mode only; attaching after game load may miss hooks
- Java hooks require JVM to initialize; may be skipped in spawn mode
- Emulator dialog may still appear if server-side detection is not covered by local patches

## Troubleshooting

- `adb devices` must show the emulator before running `spawn_game.py`
- If Frida disconnects immediately, ensure `frida-server` version matches client
- Run `adb logcat` in parallel to catch native crashes

## License

For educational and research purposes only.
