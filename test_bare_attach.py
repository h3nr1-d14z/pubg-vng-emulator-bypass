#!/usr/bin/env python3
"""Test if bare Frida attach (no script) kills the game."""
import frida
import time
import subprocess
import sys

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

    print(f"Attaching bare (no script) to PID {pid}...")
    try:
        session = device.attach(pid)
        print(f"Attached! session={session}")
    except Exception as e:
        print(f"Attach failed: {e}")
        return

    print("Monitoring for 60s...")
    for i in range(60):
        time.sleep(1)
        if find_pubg(device) is None:
            print(f"Game DIED {i+1}s after bare attach")
            return
        if (i + 1) % 10 == 0:
            print(f"T+{i+1}s: alive")

    print("Game survived 60s with bare attach")

if __name__ == "__main__":
    main()
