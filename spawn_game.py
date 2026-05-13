#!/usr/bin/env python3
"""Spawn PUBG Mobile VNG with Frida stealth bypass script.
Captures clean /proc/<pid>/maps before Frida injects to avoid detection."""
import frida
import sys
import time
import subprocess
import tempfile
import os

ADB = r"C:\Users\h3nr1-d14z\Desktop\platform-tools\adb.exe"
DEVICE_SERIAL = "emulator-5556"

def adb_shell(cmd):
    result = subprocess.run([ADB, "-s", DEVICE_SERIAL, "shell", cmd],
                          capture_output=True, text=True)
    return result.stdout, result.stderr, result.returncode

def adb_push(local_path, remote_path):
    result = subprocess.run([ADB, "-s", DEVICE_SERIAL, "push", local_path, remote_path],
                          capture_output=True, text=True)
    return result.returncode == 0

def capture_clean_maps(pid, output_path):
    """Read the real maps of a suspended process and save it."""
    stdout, stderr, rc = adb_shell(f"su -c 'cat /proc/{pid}/maps'")
    if rc != 0:
        print(f"[WARN] Failed to read maps for PID {pid}: {stderr}", flush=True)
        return False
    # Filter out any frida lines just in case (shouldn't be present in clean maps)
    lines = stdout.splitlines()
    filtered = [line for line in lines if "frida" not in line.lower()]
    if len(filtered) != len(lines):
        print(f"[WARN] Removed {len(lines)-len(filtered)} frida lines from clean maps", flush=True)
    content = "\n".join(filtered) + "\n"
    # Write to local temp file and push via adb
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
    # Inject the correct fake maps path for this process
    script_source = script_source.replace('"/data/local/tmp/fake_maps"', f'"{fake_maps_path}"')
    script = session.create_script(script_source)
    script.on('message', on_message(tag))
    script.on('destroyed', lambda t=tag: print(f"[{t}] Script destroyed", flush=True))
    script.load()
    return session, script

def main():
    device = frida.get_usb_device(timeout=5)

    # Spawn main process (suspended)
    pid = device.spawn(["com.vng.pubgmobile"])
    print(f"Spawned main PID: {pid}", flush=True)

    # Capture clean maps BEFORE attaching Frida
    capture_clean_maps(pid, "/data/local/tmp/fake_maps_main")

    session_main, script_main = attach_script(device, pid, "MAIN", "frida_bypass_diag.js", "/data/local/tmp/fake_maps_main")
    device.resume(pid)
    print("Main script loaded. Resuming...", flush=True)

    # Continuously monitor plugin process and re-attach if it changes
    plugin_session = None
    plugin_script = None
    plugin_pid = None
    attempts = 0

    while True:
        time.sleep(1)
        try:
            processes = device.enumerate_processes()
            current_plugin_pid = None
            for p in processes:
                if p.name == "com.vng.pubgmobile:plugin":
                    current_plugin_pid = p.pid
                    break

            if current_plugin_pid is None:
                attempts += 1
                if attempts % 10 == 0:
                    print(f"Plugin process not found after {attempts}s...", flush=True)
                continue

            if current_plugin_pid == plugin_pid and plugin_session is not None:
                continue

            # Plugin PID changed or we aren't attached yet
            if plugin_session is not None:
                print(f"Plugin process changed from {plugin_pid} to {current_plugin_pid}, reattaching...", flush=True)
                try:
                    plugin_session.detach()
                except Exception as e:
                    print(f"Old plugin detach error: {e}", flush=True)
            else:
                print(f"Attaching to plugin PID: {current_plugin_pid}", flush=True)

            # Capture clean maps for plugin BEFORE attaching
            capture_clean_maps(current_plugin_pid, "/data/local/tmp/fake_maps_plugin")

            try:
                plugin_session, plugin_script = attach_script(device, current_plugin_pid, "PLUGIN", "frida_bypass_diag.js", "/data/local/tmp/fake_maps_plugin")
                plugin_pid = current_plugin_pid
                print("Plugin script loaded.", flush=True)
                attempts = 0
            except Exception as e:
                print(f"Plugin attach error: {e}", flush=True)
                plugin_session = None
                plugin_script = None

        except Exception as e:
            print(f"Plugin monitor error: {e}", flush=True)

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nDetaching...", flush=True)
        if plugin_session:
            plugin_session.detach()
        session_main.detach()

if __name__ == "__main__":
    main()
