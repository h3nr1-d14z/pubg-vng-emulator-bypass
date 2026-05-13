#!/usr/bin/env python3
import frida
import sys

device = frida.get_usb_device(timeout=5)
pid = device.spawn(["com.vng.pubgmobile"])
print(f"Spawned PID: {pid}")
session = device.attach(pid)
with open("list_modules.js", "r") as f:
    src = f.read()
script = session.create_script(src)
script.on('message', lambda msg, data: print(msg.get('payload', msg)) if msg['type'] == 'send' else print(msg))
script.load()
device.resume(pid)
import time
time.sleep(3)
session.detach()
