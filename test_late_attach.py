#!/usr/bin/env python3
"""Start hidden frida-server, launch game, wait for main menu, then attach Frida."""
import frida
import time
import subprocess
import sys

ADB = r"C:\Users\h3nr1-d14z\Desktop\platform-tools\adb.exe"
DEVICE_SERIAL = "emulator-5556"
FRIDA_PORT = 27042

def adb_shell(cmd):
    result = subprocess.run([ADB, "-s", DEVICE_SERIAL, "shell", cmd],
                          capture_output=True, text=True)
    return result.stdout, result.stderr, result.returncode

def start_hidden_frida():
    stdout, _, _ = adb_shell("ps -A | grep system_daemon")
    if "system_daemon" in stdout:
        print("Hidden frida-server already running")
        return True
    print("Starting hidden frida-server...")
    adb_shell("nohup /data/local/tmp/system_daemon >/dev/null 2>&1 &")
    time.sleep(2)
    stdout, _, _ = adb_shell("ps -A | grep system_daemon")
    if "system_daemon" not in stdout:
        print("Failed to start hidden frida-server")
        return False
    print("Hidden frida-server started")
    return True

def setup_port_forward():
    subprocess.run([ADB, "-s", DEVICE_SERIAL, "forward", f"tcp:{FRIDA_PORT}", f"tcp:{FRIDA_PORT}"],
                   capture_output=True)
    print(f"Port forward tcp:{FRIDA_PORT} set up")

def get_remote_device():
    return frida.get_device_manager().add_remote_device(f"127.0.0.1:{FRIDA_PORT}")

def on_message(tag):
    def handler(message, data):
        if message['type'] == 'send':
            print(f"[{tag}] [SEND]", message['payload'], flush=True)
        elif message['type'] == 'error':
            print(f"[{tag}] [ERROR]", message['description'], flush=True)
        else:
            print(f"[{tag}] [MSG]", message, flush=True)
    return handler

def find_pubg_process(device):
    for p in device.enumerate_processes():
        if p.name == "PUBG MOBILE":
            return p.pid
    return None

def main():
    # Kill existing game
    print("Force-stopping game...")
    adb_shell("am force-stop com.vng.pubgmobile")
    time.sleep(1)

    # Start hidden frida-server
    if not start_hidden_frida():
        sys.exit(1)

    setup_port_forward()
    time.sleep(1)

    device = get_remote_device()
    print(f"Connected to remote device: {device}")

    # Launch game without Frida
    print("Launching game via adb monkey...")
    adb_shell("monkey -p com.vng.pubgmobile -c android.intent.category.LAUNCHER 1")

    # Wait for game to reach main menu
    print("Waiting 45s for main menu...")
    main_pid = None
    for i in range(45):
        time.sleep(1)
        main_pid = find_pubg_process(device)
        if main_pid is None and i > 5:
            # Check if process died
            pass
        if (i + 1) % 5 == 0:
            status = f"PID={main_pid}" if main_pid else "NOT FOUND"
            print(f"T+{i+1}s: PUBG MOBILE {status}")

    main_pid = find_pubg_process(device)
    if not main_pid:
        print("PUBG MOBILE process not found after wait - game likely crashed")
        return

    print(f"Game alive at PID {main_pid}. Attaching empty Frida script...")
    try:
        session = device.attach(main_pid)
        with open("frida_empty.js", "r") as f:
            script = session.create_script(f.read())
        script.on('message', on_message("MAIN"))
        script.on('destroyed', lambda reason="": print(f"[MAIN] Script destroyed: {reason}", flush=True))
        script.load()
        print("Attached! Monitoring for 60s...")
    except Exception as e:
        print(f"Attach failed: {e}")
        return

    for i in range(60):
        time.sleep(1)
        pid = find_pubg_process(device)
        if pid is None:
            print(f"Game DIED {i+1}s after attachment")
            return
        if (i + 1) % 10 == 0:
            print(f"Post-attach T+{i+1}s: PUBG MOBILE alive (PID {pid})")

    print("SUCCESS: Game survived 60s after late attach - anti-cheat does not detect agent injection post-startup")

if __name__ == "__main__":
    main()
