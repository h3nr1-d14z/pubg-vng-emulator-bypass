#!/usr/bin/env python3
"""
Giải mã payload 0x4013 và phân tích emulator detection fields
Key: token từ auth response (AES-128-CBC, IV=zeros)
"""
import struct
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

def read_pcap(filename):
    with open(filename, 'rb') as f:
        data = f.read()
    magic = struct.unpack('<I', data[:4])[0]
    endian = '<' if magic == 0xa1b2c3d4 else '>'
    link_type = struct.unpack(endian + 'I', data[20:24])[0]
    offset = 24
    packets = []
    while offset < len(data):
        if offset + 16 > len(data): break
        ts_sec, ts_usec, incl_len, orig_len = struct.unpack(endian + 'IIII', data[offset:offset+16])
        offset += 16
        if offset + incl_len > len(data): break
        packets.append(data[offset:offset+incl_len])
        offset += incl_len
    return packets, link_type

def extract_tcp_payload(pkt_data, link_type):
    if link_type == 113:
        if len(pkt_data) < 16: return None
        proto = struct.unpack('>H', pkt_data[14:16])[0]
        if proto != 0x0800: return None
        ip_start = 16
    else:
        return None
    if len(pkt_data) < ip_start + 20: return None
    ip_header = pkt_data[ip_start:]
    ihl = (ip_header[0] & 0x0f) * 4
    protocol = ip_header[9]
    if protocol != 6: return None
    tcp_start = ip_start + ihl
    if len(pkt_data) < tcp_start + 20: return None
    tcp_header = pkt_data[tcp_start:]
    src_port = struct.unpack('>H', tcp_header[0:2])[0]
    dst_port = struct.unpack('>H', tcp_header[2:4])[0]
    data_offset = ((tcp_header[12] >> 4) & 0x0f) * 4
    payload_start = tcp_start + data_offset
    return src_port, dst_port, pkt_data[payload_start:]

def parse_anogs_header(data, offset=0):
    if len(data) < offset + 16: return None
    magic = data[offset:offset+2]
    if magic != b'\x33\x66': return None
    opcode = struct.unpack('>H', data[offset+6:offset+8])[0]
    seq = struct.unpack('<I', data[offset+8:offset+12])[0]
    body_len = struct.unpack('<I', data[offset+12:offset+16])[0]
    return {'opcode': opcode, 'seq': seq, 'body_len': body_len}

def decrypt_aes_cbc(data, key, iv):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(data) + decryptor.finalize()

def hexdump(data, offset=0, width=16):
    for i in range(0, len(data), width):
        chunk = data[i:i+width]
        hex_str = ' '.join(f'{b:02x}' for b in chunk)
        ascii_str = ''.join(chr(b) if 32<=b<127 else '.' for b in chunk)
        print(f"{offset+i:04x}: {hex_str:<{width*3}} {ascii_str}")

def extract_strings(data, min_len=4):
    strings = []
    current = ""
    for b in data:
        if 32 <= b < 127:
            current += chr(b)
        else:
            if len(current) >= min_len:
                strings.append(current)
            current = ""
    if len(current) >= min_len:
        strings.append(current)
    return strings

def main():
    packets, link_type = read_pcap("/tmp/anti_cheat_17500.pcap")

    # Extract token
    token = None
    for pkt in packets:
        result = extract_tcp_payload(pkt, link_type)
        if result is None: continue
        sport, dport, payload = result
        if len(payload) < 16: continue
        hdr = parse_anogs_header(payload)
        if not hdr: continue
        if hdr['opcode'] == 0x1002 and sport < dport:
            trailer = payload[16+hdr['body_len']:]
            token = trailer[6:22].rstrip(b'\x00')
            break

    if not token:
        print("ERROR: Token not found")
        return

    key = token.ljust(16, b'\x00')[:16]
    iv = b'\x00' * 16
    print(f"Key: {key}")
    print(f"IV:  {iv.hex()}")

    # Decrypt all C->S 0x4013 packets and reassemble
    decrypted_parts = []
    for pkt in packets:
        result = extract_tcp_payload(pkt, link_type)
        if result is None: continue
        sport, dport, payload = result
        if len(payload) < 16: continue
        hdr = parse_anogs_header(payload)
        if not hdr or hdr['opcode'] != 0x4013: continue
        if sport < dport: continue  # Only C->S

        trailer = payload[16+hdr['body_len']:]
        # Skip first 5 bytes header (d0 00 00 00 00)
        if len(trailer) > 5:
            encrypted = trailer[5:]
            # Pad to 16-byte boundary
            padding = 16 - (len(encrypted) % 16)
            if padding != 16:
                encrypted += b'\x00' * padding
            plain = decrypt_aes_cbc(encrypted, key, iv)
            decrypted_parts.append(plain)

    full_plain = b''.join(decrypted_parts)
    print(f"\nTotal decrypted: {len(full_plain)} bytes")

    # Save to file
    with open("/tmp/decrypted_4013.bin", "wb") as f:
        f.write(full_plain)
    print("Saved to /tmp/decrypted_4013.bin")

    # Show first 512 bytes
    print("\n--- First 512 bytes of decrypted data ---")
    hexdump(full_plain[:512])

    # Extract all strings
    print("\n=== ALL STRINGS IN DECRYPTED DATA ===")
    strings = extract_strings(full_plain)
    for i, s in enumerate(strings):
        print(f"  [{i:3d}] {s}")

    # Look for specific emulator-related fields
    print("\n=== EMULATOR DETECTION FIELDS ===")
    keywords = ['emulator', 'ldplayer', 'bluestacks', 'nox', 'memu', 'vbox',
                'virtualbox', 'qemu', 'goldfish', 'ranchu', 'generic', 'x86',
                'intel', 'amd', 'hardware', 'product', 'device', 'model',
                'manufacturer', 'board', 'bootloader', 'fingerprint', 'serial',
                'brand', 'host', 'id', 'display', 'tags', 'type', 'user',
                'sdk', 'release', 'codename', 'incremental', 'base_os',
                'security_patch', 'preview_sdk', 'codename', 'gpu', 'renderer',
                'gl_version', 'gles', 'adreno', 'mali', 'powervr']

    full_lower = full_plain.lower()
    for kw in keywords:
        idx = full_lower.find(kw.encode())
        if idx >= 0:
            ctx = full_plain[max(0,idx-32):idx+len(kw)+32]
            print(f"\n  FOUND '{kw}' at offset {idx}:")
            try:
                print(f"    Context: {ctx.decode('latin1')}")
            except:
                print(f"    Context hex: {ctx.hex()}")

if __name__ == "__main__":
    main()
