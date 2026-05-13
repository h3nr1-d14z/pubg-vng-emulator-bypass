#!/usr/bin/env python3
"""Test 45s late attach stealth bypass with periodic screenshots."""
import frida
import time
import subprocess
import tempfile
import os

ADB = r"C:\Users\h3nr1-d14z\Desktop\platform-tools\adb.exe"
DEVICE_SERIAL = "emulator-5556"
SCREENSHOT_DIR = r"C:\Users\h3nr1-d14z\Projects\pubg-vng-emulator-bypass\screenshots"

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

def capture_screenshot(filename):
    remote_path = "/data/local/tmp/screenshot.png"
    local_path = os.path.join(SCREENSHOT_DIR, filename)
    adb_shell(f"screencap -p {remote_path}")
    subprocess.run([ADB, "-s", DEVICE_SERIAL, "pull", remote_path, local_path], capture_output=True)
    return os.path.exists(local_path)

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
    os.makedirs(SCREENSHOT_DIR, exist_ok=True)

    print("Force-stopping game...")
    adb_shell("am force-stop com.vng.pubgmobile")
    time.sleep(1)

    device = get_remote_device()
    print("Launching game...")
    adb_shell("monkey -p com.vng.pubgmobile -c android.intent.category.LAUNCHER 1")

    print("Waiting 45s...")
    for i in range(45):
        time.sleep(1)
        if (i + 1) % 5 == 0:
            pid = find_pubg(device)
            print(f"T+{i+1}s: PID={pid}")
            capture_screenshot(f"wait_{i+1}s.png")

    pid = find_pubg(device)
    if not pid:
        print("Game not running")
        return

    with tempfile.NamedTemporaryFile(mode="w", suffix="_maps.txt", delete=False) as tmp:
        tmp_path = tmp.name
    if not capture_clean_maps(pid, tmp_path):
        print("Failed to capture clean maps")
        return
    fake_maps_remote = "/data/local/tmp/fake_maps_clean"
    subprocess.run([ADB, "-s", DEVICE_SERIAL, "push", tmp_path, fake_maps_remote], capture_output=True)
    os.unlink(tmp_path)

    with open("frida_bypass_stealth.js", "r") as f:
        script_src = f.read()
    script_src = script_src.replace('"/data/local/tmp/fake_maps"', f'"{fake_maps_remote}"')

    print(f"Attaching STEALTH bypass to PID {pid}...")
    try:
        session = device.attach(pid)
        script = session.create_script(script_src)
        def on_msg(message, data):
            if message['type'] == 'send':
                print(f"[STEALTH] {message['payload']}")
            elif message['type'] == 'error':
                print(f"[STEALTH ERROR] {message['description']}")
        script.on('message', on_msg)
        script.on('destroyed', lambda reason="": print(f"Script destroyed: {reason}"))
        script.load()
        print("Loaded! Capturing screenshots every 10s for 90s...")
    except Exception as e:
        print(f"Attach/load failed: {e}")
        return

    for i in range(9):
        time.sleep(10)
        fname = f"post_attach_{(i+1)*10}s.png"
        if capture_screenshot(fname):
            print(f"  Screenshot: {fname}")
        else:
            print(f"  Failed to capture {fname}")
        if find_pubg(device) is None:
            print(f"Game DIED at {(i+1)*10}s")
            capture_screenshot(f"died_{(i+1)*10}s.png")
            return

    print("Test complete. Check screenshots/ directory.")
    session.detach()

if __name__ == "__main__":
    main()
