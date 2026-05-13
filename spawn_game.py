#!/usr/bin/env python3
"""Launch PUBG Mobile VNG with Frida stealth bypass (late-attach mode).

Key findings driving this architecture:
- Spawn mode times out / crashes during startup on this game
- Anti-cheat detects bare Frida attach in ~18s via /proc/self/maps + ptrace scans
- Late attach (after main menu) + file hooks + ptrace hook = stable 90s+ survival
- libc send/recv hooks trigger anti-cheat kill at ~22s - excluded from stable script
- Java bridge broken on LD Player - native hooks only
- Frida reports process as 'PUBG MOBILE' not 'com.vng.pubgmobile'
- frida-server must be hidden (renamed to system_daemon) to avoid process-name scan
"""
import frida
import sys
import time
import subprocess
import tempfile
import os

ADB = r"C:\Users\h3nr1-d14z\Desktop\platform-tools\adb.exe"
DEVICE_SERIAL = "emulator-5556"
FRIDA_PORT = 27042
SCRIPT_PATH = "frida_bypass_stealth.js"
WAIT_SECONDS = 20  # Attach before anti-cheat's ~18s scan, but after process is stable


def adb_shell(cmd):
    result = subprocess.run([ADB, "-s", DEVICE_SERIAL, "shell", cmd],
                          capture_output=True, text=True)
    return result.stdout, result.stderr, result.returncode


def adb_push(local_path, remote_path):
    result = subprocess.run([ADB, "-s", DEVICE_SERIAL, "push", local_path, remote_path],
                          capture_output=True, text=True)
    return result.returncode == 0


def capture_clean_maps(pid, output_path):
    """Read the real maps of a running process and save it before Frida injects."""
    stdout, stderr, rc = adb_shell(f"su -c 'cat /proc/{pid}/maps'")
    if rc != 0:
        print(f"[WARN] Failed to read maps for PID {pid}: {stderr}", flush=True)
        return False
    lines = stdout.splitlines()
    filtered = [line for line in lines if "frida" not in line.lower() and "gum" not in line.lower()]
    if len(filtered) != len(lines):
        print(f"[WARN] Removed {len(lines)-len(filtered)} frida/gum lines from clean maps", flush=True)
    content = "\n".join(filtered) + "\n"
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.maps') as f:
        f.write(content)
        local_path = f.name
    success = adb_push(local_path, output_path)
    os.unlink(local_path)
    if success:
        print(f"[MAPS] Captured {len(filtered)} lines from PID {pid} -> {output_path}", flush=True)
    else:
        print(f"[WARN] Failed to push maps to {output_path}", flush=True)
    return success


def get_remote_device():
    return frida.get_device_manager().add_remote_device(f"127.0.0.1:{FRIDA_PORT}")


def find_pubg_process(device):
    """Frida reports the process as 'PUBG MOBILE', not the package name."""
    for p in device.enumerate_processes():
        if p.name == "PUBG MOBILE":
            return p.pid
    return None


def find_plugin_process(device, main_pid):
    """Plugin process reports as 'com.vng.pubgmobile:plugin' in Frida."""
    for p in device.enumerate_processes():
        if p.name == "com.vng.pubgmobile:plugin":
            return p.pid
    return None


def on_message(tag):
    def handler(message, data):
        if message['type'] == 'send':
            print(f"[{tag}] [SEND]", message['payload'], flush=True)
        elif message['type'] == 'error':
            print(f"[{tag}] [ERROR]", message['description'], flush=True)
        else:
            print(f"[{tag}] [MSG]", message, flush=True)
    return handler


def attach_script(device, pid, tag, script_path, fake_maps_path):
    session = device.attach(pid)
    with open(script_path, "r") as f:
        script_source = f.read()
    script_source = script_source.replace('"/data/local/tmp/fake_maps"', f'"{fake_maps_path}"')
    script = session.create_script(script_source)
    script.on('message', on_message(tag))
    script.on('destroyed', lambda t=tag: print(f"[{t}] Script destroyed", flush=True))
    script.load()
    return session, script


def main():
    print("=== PUBG Mobile VNG Stealth Bypass Launcher ===", flush=True)

    # Verify hidden frida-server is running
    stdout, _, _ = adb_shell("ps -A | grep system_daemon")
    if "system_daemon" not in stdout:
        print("[FATAL] Hidden frida-server (system_daemon) not running. Start it first:", flush=True)
        print("  adb shell 'nohup /data/local/tmp/system_daemon > /dev/null 2>&1 &'", flush=True)
        sys.exit(1)

    # Ensure port forward is active
    subprocess.run([ADB, "-s", DEVICE_SERIAL, "forward", f"tcp:{FRIDA_PORT}", f"tcp:{FRIDA_PORT}"],
                   capture_output=True)

    device = get_remote_device()
    print(f"[DEVICE] Connected to {device}", flush=True)

    # Kill existing game
    print("[ADB] Force-stopping game...", flush=True)
    adb_shell("am force-stop com.vng.pubgmobile")
    time.sleep(2)

    # Launch game normally (NO spawn mode - anti-cheat detects startup suspension)
    print("[ADB] Launching game via monkey...", flush=True)
    adb_shell("monkey -p com.vng.pubgmobile -c android.intent.category.LAUNCHER 1")

    # Wait for game to reach main menu
    print(f"[WAIT] Waiting {WAIT_SECONDS}s for main menu...", flush=True)
    main_pid = None
    for i in range(WAIT_SECONDS):
        time.sleep(1)
        main_pid = find_pubg_process(device)
        if (i + 1) % 5 == 0:
            status = f"PID={main_pid}" if main_pid else "NOT FOUND"
            print(f"[WAIT] T+{i+1}s: PUBG MOBILE {status}", flush=True)

    if not main_pid:
        print("[FATAL] Game process not found after wait - likely crashed before attach", flush=True)
        sys.exit(1)

    print(f"[MAIN] Game alive at PID {main_pid}. Capturing clean maps...", flush=True)
    if not capture_clean_maps(main_pid, "/data/local/tmp/fake_maps_main"):
        print("[WARN] Failed to capture clean maps, proceeding anyway...", flush=True)

    print(f"[MAIN] Attaching stealth bypass to PID {main_pid}...", flush=True)
    try:
        session_main, script_main = attach_script(device, main_pid, "MAIN", SCRIPT_PATH, "/data/local/tmp/fake_maps_main")
        print("[MAIN] Stealth bypass loaded successfully.", flush=True)
    except Exception as e:
        print(f"[FATAL] Failed to attach to main process: {e}", flush=True)
        sys.exit(1)

    # Monitor and attach to plugin process
    plugin_session = None
    plugin_script = None
    plugin_pid = None
    plugin_attempts = 0

    print("[PLUGIN] Monitoring for plugin process...", flush=True)

    try:
        while True:
            time.sleep(1)

            # Check main process still alive
            current_main = find_pubg_process(device)
            if current_main is None:
                print("[FATAL] Main process died!", flush=True)
                break

            # Look for plugin process
            current_plugin_pid = find_plugin_process(device, current_main)

            if current_plugin_pid is None:
                plugin_attempts += 1
                if plugin_attempts % 10 == 0:
                    print(f"[PLUGIN] Not found after {plugin_attempts}s...", flush=True)
                continue

            if current_plugin_pid == plugin_pid and plugin_session is not None:
                continue

            # Plugin PID changed or first detection
            if plugin_session is not None:
                print(f"[PLUGIN] Changed from {plugin_pid} to {current_plugin_pid}, reattaching...", flush=True)
                try:
                    plugin_session.detach()
                except Exception as e:
                    print(f"[PLUGIN] Old detach error: {e}", flush=True)
            else:
                print(f"[PLUGIN] Found at PID {current_plugin_pid}. Capturing maps...", flush=True)

            capture_clean_maps(current_plugin_pid, "/data/local/tmp/fake_maps_plugin")

            try:
                plugin_session, plugin_script = attach_script(device, current_plugin_pid, "PLUGIN", SCRIPT_PATH, "/data/local/tmp/fake_maps_plugin")
                plugin_pid = current_plugin_pid
                print("[PLUGIN] Stealth bypass loaded.", flush=True)
                plugin_attempts = 0
            except Exception as e:
                print(f"[PLUGIN] Attach error: {e}", flush=True)
                plugin_session = None
                plugin_script = None

    except KeyboardInterrupt:
        print("\n[INFO] Ctrl+C received, shutting down...", flush=True)
    finally:
        if plugin_session:
            try:
                plugin_session.detach()
            except Exception:
                pass
        if session_main:
            try:
                session_main.detach()
            except Exception:
                pass
        print("[INFO] Detached. Exiting.", flush=True)


if __name__ == "__main__":
    main()
