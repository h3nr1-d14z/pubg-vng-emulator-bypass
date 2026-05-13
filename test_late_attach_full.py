#!/usr/bin/env python3
"""Late attach with FULL bypass script to test if hooks hide Frida."""
import frida
import time
import subprocess
import tempfile
import os

ADB = r"C:\Users\h3nr1-d14z\Desktop\platform-tools\adb.exe"
DEVICE_SERIAL = "emulator-5556"

def adb_shell(cmd):
    result = subprocess.run([ADB, "-s", DEVICE_SERIAL, "shell", cmd], capture_output=True, text=True)
    return result.stdout, result.stderr, result.returncode

def get_remote_device():
    return frida.get_device_manager().add_remote_device("127.0.0.1:27042")

def find_pubg(device):
    for p in device.enumerate_processes():
        if p.name == "PUBG MOBILE":
            return p.pid
    return None

def capture_clean_maps(pid, output_path):
    stdout, stderr, rc = adb_shell(f"su -c 'cat /proc/{pid}/maps'")
    if rc != 0:
        print(f"Failed to capture maps: {stderr}")
        return False
    lines = stdout.splitlines()
    filtered = [line for line in lines if "frida" not in line.lower() and "gum" not in line.lower()]
    with open(output_path, "w", encoding="utf-8") as f:
        f.write("\n".join(filtered))
    return True

def main():
    print("Force-stopping game...")
    adb_shell("am force-stop com.vng.pubgmobile")
    time.sleep(1)

    device = get_remote_device()
    print("Launching game...")
    adb_shell("monkey -p com.vng.pubgmobile -c android.intent.category.LAUNCHER 1")

    print("Waiting 45s for main menu...")
    pid = None
    for i in range(45):
        time.sleep(1)
        pid = find_pubg(device)
        if (i + 1) % 5 == 0:
            print(f"T+{i+1}s: PID={pid}")

    pid = find_pubg(device)
    if not pid:
        print("Game not running")
        return

    # Capture clean maps before attaching
    with tempfile.NamedTemporaryFile(mode="w", suffix="_maps.txt", delete=False) as tmp:
        tmp_path = tmp.name
    if not capture_clean_maps(pid, tmp_path):
        print("Failed to capture clean maps")
        return

    fake_maps_remote = "/data/local/tmp/fake_maps_clean"
    subprocess.run([ADB, "-s", DEVICE_SERIAL, "push", tmp_path, fake_maps_remote], capture_output=True)
    os.unlink(tmp_path)
    print(f"Pushed clean maps to {fake_maps_remote}")

    # Load and inject full bypass script
    with open("frida_bypass_diag.js", "r") as f:
        script_src = f.read()
    script_src = script_src.replace('"/data/local/tmp/fake_maps"', f'"{fake_maps_remote}"')

    print(f"Attaching FULL bypass to PID {pid}...")
    try:
        session = device.attach(pid)
        script = session.create_script(script_src)
        def on_msg(message, data):
            if message['type'] == 'send':
                print(f"[BYPASS] {message['payload']}")
            elif message['type'] == 'error':
                print(f"[BYPASS ERROR] {message['description']}")
        script.on('message', on_msg)
        script.on('destroyed', lambda reason="": print(f"Script destroyed: {reason}"))
        script.load()
        print("Loaded! Monitoring for 90s...")
    except Exception as e:
        print(f"Attach/load failed: {e}")
        return

    for i in range(90):
        time.sleep(1)
        if find_pubg(device) is None:
            print(f"Game DIED {i+1}s after full bypass attach")
            return
        if (i + 1) % 10 == 0:
            print(f"Post-attach T+{i+1}s: alive")

    print("Game survived 90s with full bypass - hooks are working!")

if __name__ == "__main__":
    main()
