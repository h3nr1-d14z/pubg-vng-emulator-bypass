#!/usr/bin/env python3
"""Test attaching Frida ONLY to main process, not plugin."""
import frida
import sys
import time

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
    pid = device.spawn(["com.vng.pubgmobile"])
    print(f"Spawned main PID: {pid}", flush=True)

    session = device.attach(pid)
    with open("frida_empty.js", "r") as f:
        script = session.create_script(f.read())
    script.on('message', on_message("MAIN"))
    script.on('destroyed', lambda: print("[MAIN] Script destroyed", flush=True))
    script.load()
    device.resume(pid)
    print("Main script loaded. Resuming...", flush=True)

    # Monitor if game stays alive WITHOUT attaching to plugin
    for i in range(120):
        time.sleep(1)
        try:
            processes = device.enumerate_processes()
            has_main = any(p.name == "com.vng.pubgmobile" for p in processes)
            has_plugin = any(p.name == "com.vng.pubgmobile:plugin" for p in processes)
            if not has_main and not has_plugin:
                print(f"Game died after {i+1}s", flush=True)
                return
            if (i + 1) % 10 == 0:
                print(f"T+{i+1}s: main={'YES' if has_main else 'NO'} plugin={'YES' if has_plugin else 'NO'}", flush=True)
        except Exception as e:
            print(f"Monitor error: {e}", flush=True)

    print("Game survived 120s with Frida on main process only", flush=True)

if __name__ == "__main__":
    main()
