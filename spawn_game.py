#!/usr/bin/env python3
"""Spawn PUBG Mobile VNG with Frida stealth bypass script."""
import frida
import sys
import time
import os

def on_message(tag):
    def handler(message, data):
        if message['type'] == 'send':
            print(f"[{tag}] [SEND]", message['payload'], flush=True)
        elif message['type'] == 'error':
            print(f"[{tag}] [ERROR]", message['description'], flush=True)
        else:
            print(f"[{tag}] [MSG]", message, flush=True)
    return handler

def attach_script(device, pid, tag, script_path):
    session = device.attach(pid)
    with open(script_path, "r") as f:
        script_source = f.read()
    script = session.create_script(script_source)
    script.on('message', on_message(tag))
    script.on('destroyed', lambda t=tag: print(f"[{t}] Script destroyed", flush=True))
    script.load()
    return session, script

def main():
    device = frida.get_usb_device(timeout=5)
    pid = device.spawn(["com.vng.pubgmobile"])
    print(f"Spawned main PID: {pid}", flush=True)

    session_main, script_main = attach_script(device, pid, "MAIN", "frida_bypass_diag.js")
    device.resume(pid)
    print("Main script loaded. Resuming...", flush=True)

    # Wait for plugin process to spawn and attach to it too
    plugin_session = None
    plugin_pid = None
    attempts = 0
    while attempts < 30:
        time.sleep(1)
        try:
            processes = device.enumerate_processes()
            for p in processes:
                if p.name == "com.vng.pubgmobile:plugin":
                    if plugin_pid != p.pid:
                        plugin_pid = p.pid
                        print(f"Attaching to plugin PID: {plugin_pid}", flush=True)
                        plugin_session, plugin_script = attach_script(device, plugin_pid, "PLUGIN", "frida_bypass_diag.js")
                        print("Plugin script loaded.", flush=True)
                    break
            else:
                attempts += 1
                continue
            break
        except Exception as e:
            print(f"Plugin attach error: {e}", flush=True)
            attempts += 1

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
