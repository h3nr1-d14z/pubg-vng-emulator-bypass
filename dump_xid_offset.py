#!/usr/bin/env python3
"""
Dump offset cua XID va cac truong TLV-0x03 trong decrypted 0x4013 payload.
Thu nhieu dinh dang TLV va brute-force scan chuoi hex dai.
"""
import sys
import struct

def is_hex_string(b):
    if len(b) < 32:
        return False
    for ch in b:
        if not (48 <= ch <= 57 or 97 <= ch <= 102 or 65 <= ch <= 70):
            return False
    return True

def parse_tlv_variant(data):
    """Thu nhieu dinh dang TLV va tra ve list cac entry (offset, type, length, value)"""
    entries = []
    i = 0
    while i < len(data) - 3:
        # Format 1: [type:1][len:1]
        t = data[i]
        l = data[i+1]
        if l <= 128 and i + 2 + l <= len(data):
            v = data[i+2:i+2+l]
            entries.append((i, t, l, v, '1B_LEN'))
            i += 2 + l
            continue

        # Format 2: [type:1][len:2 LE]
        if i + 3 <= len(data):
            l2 = struct.unpack('<H', data[i+1:i+3])[0]
            if l2 <= 2048 and i + 3 + l2 <= len(data):
                v = data[i+3:i+3+l2]
                entries.append((i, t, l2, v, '2LE_LEN'))
                i += 3 + l2
                continue

        # Format 3: [type:1][len:2 BE]
        if i + 3 <= len(data):
            l3 = struct.unpack('>H', data[i+1:i+3])[0]
            if l3 <= 2048 and i + 3 + l3 <= len(data):
                v = data[i+3:i+3+l3]
                entries.append((i, t, l3, v, '2BE_LEN'))
                i += 3 + l3
                continue

        i += 1
    return entries

def brute_force_hex_strings(data, min_len=32, max_len=128):
    """Quet toan bo file tim cac chuoi hex lien tuc"""
    results = []
    i = 0
    while i <= len(data) - min_len:
        # Kiem tra xem tu vi tri i co chuoi hex dai nhat la bao nhieu
        j = i
        while j < len(data) and j - i < max_len:
            ch = data[j]
            if not (48 <= ch <= 57 or 97 <= ch <= 102 or 65 <= ch <= 70):
                break
            j += 1
        length = j - i
        if length >= min_len:
            results.append((i, length, data[i:j].decode('ascii')))
            i = j
        else:
            i += 1
    return results

def main():
    path = sys.argv[1] if len(sys.argv) > 1 else "/tmp/decrypted_4013.bin"
    try:
        with open(path, 'rb') as f:
            data = f.read()
    except FileNotFoundError:
        print(f"ERROR: Khong tim thay {path}")
        print("Usage: python3 dump_xid_offset.py <decrypted_file>")
        sys.exit(1)

    print(f"File: {path}")
    print(f"Size: {len(data)} bytes")
    print()

    # Hexdump 256 bytes dau
    print("=== Hexdump 256 bytes dau ===")
    for offset in range(0, min(256, len(data)), 16):
        chunk = data[offset:offset+16]
        hex_str = ' '.join(f'{b:02x}' for b in chunk)
        ascii_str = ''.join(chr(b) if 32<=b<127 else '.' for b in chunk)
        print(f"  {offset:04x}: {hex_str:<48} {ascii_str}")
    print()

    # Thử parse TLV đa dạng
    entries = parse_tlv_variant(data)
    print(f"=== Da thu parse {len(entries)} TLV entries ===")

    # Loc ra cac string doc duoc
    strings = []
    for off, t, l, v, fmt in entries:
        if t == 0x03:
            try:
                s = v.decode('ascii')
                strings.append((off, l, s, fmt))
            except:
                pass

    if strings:
        print(f"--- Tim thay {len(strings)} TLV-0x03 strings ---")
        for off, l, s, fmt in strings:
            print(f"  offset=0x{off:04x} fmt={fmt} len={l:3d} value='{s}'")
    else:
        print("Khong tim thay TLV-0x03 string nao voi cac dinh dang thu.")
    print()

    # Brute force hex strings
    print("=== Brute-force scan chuoi hex trong toan bo file ===")
    hex_results = brute_force_hex_strings(data, min_len=32, max_len=128)
    if hex_results:
        for off, length, val in hex_results:
            print(f"  offset=0x{off:04x} ({off})  len={length:3d}  hex='{val}'")
    else:
        print("  Khong tim thay chuoi hex lien tuc nao dai >= 32.")
    print()

    # Tim XID cu the (64 ky tu hex)
    xid_candidates = [r for r in hex_results if r[1] == 64]
    if xid_candidates:
        print("=== XID CANDIDATES (64 hex chars) ===")
        for off, length, val in xid_candidates:
            print(f"  offset=0x{off:04x} ({off})  value={val}")
    else:
        print("=== KHONG TIM THAY XID 64 ky tu ===")
        # Thu tim 32 ky tu
        xid32 = [r for r in hex_results if r[1] == 32]
        if xid32:
            print("Nhung tim thay chuoi hex 32 ky tu (co the la MD5 hoac nua SHA256):")
            for off, length, val in xid32:
                print(f"  offset=0x{off:04x} ({off})  value={val}")

if __name__ == "__main__":
    main()
