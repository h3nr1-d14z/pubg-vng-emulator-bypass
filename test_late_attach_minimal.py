#!/usr/bin/env python3
"""Late attach with MINIMAL bypass script (property + GPU only)."""
import frida
import time
import subprocess

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

def main():
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

    pid = find_pubg(device)
    if not pid:
        print("Game not running")
        return

    with open("frida_bypass_minimal.js", "r") as f:
        script_src = f.read()

    print(f"Attaching MINIMAL bypass to PID {pid}...")
    try:
        session = device.attach(pid)
        script = session.create_script(script_src)
        def on_msg(message, data):
            if message['type'] == 'send':
                print(f"[MIN] {message['payload']}")
            elif message['type'] == 'error':
                print(f"[MIN ERROR] {message['description']}")
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
            print(f"Game DIED {i+1}s after minimal attach")
            return
        if (i + 1) % 10 == 0:
            print(f"Post-attach T+{i+1}s: alive")

    print("Game survived 90s with minimal bypass")

if __name__ == "__main__":
    main()
