#!/usr/bin/env python3
"""Launch game normally, wait for main menu, then attach Frida."""
import frida
import time
import subprocess

def on_message(tag):
    def handler(message, data):
        if message['type'] == 'send':
            print(f"[{tag}] [SEND]", message['payload'], flush=True)
        elif message['type'] == 'error':
            print(f"[{tag}] [ERROR]", message['description'], flush=True)
        else:
            print(f"[{tag}] [MSG]", message, flush=True)
    return handler

def main():
    device = frida.get_usb_device(timeout=5)

    # Launch game via adb without Frida
    subprocess.run([r"C:\Users\h3nr1-d14z\Desktop\platform-tools\adb.exe", "-s", "emulator-5556",
                   "shell", "am", "force-stop", "com.vng.pubgmobile"])
    time.sleep(2)
    subprocess.run([r"C:\Users\h3nr1-d14z\Desktop\platform-tools\adb.exe", "-s", "emulator-5556",
                   "shell", "monkey", "-p", "com.vng.pubgmobile", "-c", "android.intent.category.LAUNCHER", "1"])
    print("Game launched without Frida. Waiting 45s for main menu...", flush=True)

    # Wait for game to fully load
    for i in range(45):
        time.sleep(1)
        try:
            processes = device.enumerate_processes()
            has_main = any(p.name == "com.vng.pubgmobile" for p in processes)
            has_plugin = any(p.name == "com.vng.pubgmobile:plugin" for p in processes)
            if not has_main:
                print(f"Game died before attach (after {i+1}s)", flush=True)
                return
            if (i + 1) % 5 == 0:
                print(f"T+{i+1}s: main={'YES' if has_main else 'NO'} plugin={'YES' if has_plugin else 'NO'}", flush=True)
        except Exception as e:
            print(f"Monitor error: {e}", flush=True)

    # Find main PID
    processes = device.enumerate_processes()
    main_pid = None
    for p in processes:
        if p.name == "com.vng.pubgmobile":
            main_pid = p.pid
            break

    if not main_pid:
        print("Main process not found after wait", flush=True)
        return

    print(f"Attaching empty Frida script to main PID {main_pid}...", flush=True)
    try:
        session = device.attach(main_pid)
        with open("frida_empty.js", "r") as f:
            script = session.create_script(f.read())
        script.on('message', on_message("MAIN"))
        script.on('destroyed', lambda: print("[MAIN] Script destroyed", flush=True))
        script.load()
        print("Attached! Monitoring for 60s...", flush=True)
    except Exception as e:
        print(f"Attach failed: {e}", flush=True)
        return

    for i in range(60):
        time.sleep(1)
        try:
            processes = device.enumerate_processes()
            has_main = any(p.name == "com.vng.pubgmobile" for p in processes)
            has_plugin = any(p.name == "com.vng.pubgmobile:plugin" for p in processes)
            if not has_main and not has_plugin:
                print(f"Game died after attach (at {i+1}s)", flush=True)
                return
            if (i + 1) % 10 == 0:
                print(f"Post-attach T+{i+1}s: main={'YES' if has_main else 'NO'} plugin={'YES' if has_plugin else 'NO'}", flush=True)
        except Exception as e:
            print(f"Monitor error: {e}", flush=True)

    print("Game survived 60s after late attach", flush=True)

if __name__ == "__main__":
    main()
