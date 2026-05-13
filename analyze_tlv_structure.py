#!/usr/bin/env python3
"""
Phân tích cấu trúc TLV của decrypted 0x4013 payload
"""
import struct

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
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(data) + decryptor.finalize()

def parse_tlv(data, offset):
    """Parse TLV entry at offset. Returns (type, length, value, next_offset) or None"""
    if offset >= len(data):
        return None

    # Try different TLV formats
    # Format 1: [type:1][length:1][value:var]
    if offset + 2 <= len(data):
        t = data[offset]
        l = data[offset+1]
        if l < 128 and offset + 2 + l <= len(data):
            v = data[offset+2:offset+2+l]
            return t, l, v, offset + 2 + l

    # Format 2: [type:1][length:2 LE][value:var]
    if offset + 3 <= len(data):
        t = data[offset]
        l = struct.unpack('<H', data[offset+1:offset+3])[0]
        if l < 1024 and offset + 3 + l <= len(data):
            v = data[offset+3:offset+3+l]
            return t, l, v, offset + 3 + l

    # Format 3: [type:1][length:2 BE][value:var]
    if offset + 3 <= len(data):
        t = data[offset]
        l = struct.unpack('>H', data[offset+1:offset+3])[0]
        if l < 1024 and offset + 3 + l <= len(data):
            v = data[offset+3:offset+3+l]
            return t, l, v, offset + 3 + l

    # Format 4: [type:2 LE][length:2 LE][value:var]
    if offset + 4 <= len(data):
        t = struct.unpack('<H', data[offset:offset+2])[0]
        l = struct.unpack('<H', data[offset+2:offset+4])[0]
        if l < 2048 and offset + 4 + l <= len(data):
            v = data[offset+4:offset+4+l]
            return t, l, v, offset + 4 + l

    return None

def main():
    packets, link_type = read_pcap("/tmp/anti_cheat_17500.pcap")

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

    # Decrypt first large C->S 0x4013 packet
    for pkt in packets:
        result = extract_tcp_payload(pkt, link_type)
        if result is None: continue
        sport, dport, payload = result
        if len(payload) < 16: continue
        hdr = parse_anogs_header(payload)
        if not hdr or hdr['opcode'] != 0x4013: continue
        if sport < dport: continue
        if len(payload) < 2000: continue

        trailer = payload[16+hdr['body_len']:]
        if len(trailer) <= 5: continue

        encrypted = trailer[5:]
        padding = 16 - (len(encrypted) % 16)
        if padding != 16:
            encrypted += b'\x00' * padding
        plain = decrypt_aes_cbc(encrypted, key, iv)

        print(f"Decrypted {len(plain)} bytes")
        print(f"First 64 bytes hex: {plain[:64].hex()}")
        print()

        # Try to parse as TLV starting after first 16 bytes (possible IV/header)
        # The data starts with some random bytes, then seems to have structure
        # Let's look for 0x03 pattern (appears before many strings)
        print("=== Scanning for TLV structure ===")

        # Based on hexdump, pattern seems to be: 0x03 [len:1] [string]
        # Let's scan for this
        offset = 0
        entries = []
        while offset < len(plain) - 2:
            # Look for 0x03 prefix pattern
            if plain[offset] == 0x03 and plain[offset+1] < 128:
                l = plain[offset+1]
                if offset + 2 + l <= len(plain):
                    v = plain[offset+2:offset+2+l]
                    # Check if value is mostly printable
                    printable = sum(1 for b in v if 32 <= b < 127)
                    if printable >= l * 0.8:
                        entries.append((offset, 0x03, l, v.decode('latin1')))
                        offset += 2 + l
                        continue
            offset += 1

        print(f"Found {len(entries)} potential TLV-0x03 entries:")
        for off, t, l, v in entries[:50]:
            print(f"  offset={off:04x} type=0x{t:02x} len={l:3d} value='{v}'")

        # Look for numeric values (type = 0x01, 0x02, 0x04, etc.)
        print("\n=== Scanning for numeric fields ===")
        for offset in range(len(plain) - 5):
            if plain[offset] in (0x01, 0x02, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b):
                l = plain[offset+1]
                if l <= 8 and offset + 2 + l <= len(plain):
                    v = plain[offset+2:offset+2+l]
                    # Try decode as integer
                    if l == 1:
                        val = v[0]
                    elif l == 2:
                        val = struct.unpack('<H', v)[0]
                    elif l == 4:
                        val = struct.unpack('<I', v)[0]
                    else:
                        val = v.hex()

                    # Check context
                    ctx_start = max(0, offset - 32)
                    ctx = plain[ctx_start:offset]
                    # Look for preceding 0x03 string
                    prev_str = ""
                    for i in range(offset - 1, max(0, offset - 64), -1):
                        if plain[i] == 0x03 and plain[i+1] < 128:
                            sl = plain[i+1]
                            if i + 2 + sl <= offset and all(32 <= b < 127 for b in plain[i+2:i+2+sl]):
                                prev_str = plain[i+2:i+2+sl].decode('latin1')
                                break

                    if prev_str:
                        print(f"  {prev_str} = {val} (type=0x{plain[offset]:02x}, len={l})")

        break  # Only analyze first large packet

if __name__ == "__main__":
    main()
