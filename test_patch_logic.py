#!/usr/bin/env python3
"""Test Key-Value patch logic on decrypted payload (byte-scan approach)."""
import sys
import hashlib

def calc_device_hash():
    s = "samsung|SM-S928B|e3q|qcom|14|UP1A.231005.007|S928BXXU1AWM9|pineapple|release-keys|user"
    return hashlib.sha256(s.encode('ascii')).hexdigest()

def patch_telemetry(data):
    out = bytearray()
    i = 0
    new_xid = calc_device_hash()
    print(f"[INFO] Computed XID: {new_xid}")
    patched = 0

    key_map = [
        ("EmulatorName", "SM-S928B"),
        ("GLRender", "Adreno (TM) 750"),
        ("DeviceModel", "SM-S928B"),
        ("DeviceName", "SM-S928B"),
        ("DeviceMake", "samsung"),
        ("SystemHardware", "qcom+samsung"),
        ("XID", new_xid),
    ]

    while i < len(data):
        matched = False
        for kstr, new_val in key_map:
            klen = len(kstr)
            if i + 2 + klen <= len(data) and data[i] == 0x03 and data[i+1] == klen:
                match = True
                for ci in range(klen):
                    if data[i + 2 + ci] != ord(kstr[ci]):
                        match = False
                        break
                if match:
                    # Write Key TLV
                    out.extend([0x03, klen])
                    out.extend(kstr.encode('ascii'))
                    i += 2 + klen

                    # Patch Value TLV
                    if i + 1 < len(data):
                        vt = data[i]
                        vl = data[i+1]
                        if vl <= 200 and i + 2 + vl <= len(data):
                            old_val = data[i+2:i+2+vl]
                            if new_val:
                                print(f"[PATCH] {kstr}: '{old_val.decode('ascii', errors='replace')}' -> '{new_val}'")
                                out.extend([0x03, len(new_val)])
                                out.extend(new_val.encode('ascii'))
                                i += 2 + vl
                                matched = True
                                patched += 1
                                break
        if not matched:
            out.append(data[i])
            i += 1

    print(f"[INFO] Total patched fields: {patched}")
    return bytes(out)

def main():
    path = sys.argv[1] if len(sys.argv) > 1 else "/tmp/decrypted_4013.bin"
    with open(path, 'rb') as f:
        data = f.read()
    print(f"File: {path} ({len(data)} bytes)")
    patched = patch_telemetry(data)
    print(f"Output size: {len(patched)} bytes (original: {len(data)} bytes)")
    if len(patched) != len(data):
        print("[WARN] Size mismatch!")
    else:
        print("[OK] Size preserved.")

if __name__ == "__main__":
    main()
