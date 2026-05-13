#!/usr/bin/env python3
"""
Phân tích key exchange và auth packets (opcode 0x1001, 0x1002, 0x2001, 0x2002)
Mục tiêu: Tìm thuật toán mã hóa và cách emulator bị detect
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
    timestamps = []
    while offset < len(data):
        if offset + 16 > len(data): break
        ts_sec, ts_usec, incl_len, orig_len = struct.unpack(endian + 'IIII', data[offset:offset+16])
        offset += 16
        if offset + incl_len > len(data): break
        packets.append(data[offset:offset+incl_len])
        timestamps.append((ts_sec, ts_usec))
        offset += incl_len
    return packets, timestamps, link_type

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
    f1 = struct.unpack('>H', data[offset+2:offset+4])[0]
    f2 = struct.unpack('>H', data[offset+4:offset+6])[0]
    opcode = struct.unpack('>H', data[offset+6:offset+8])[0]
    seq = struct.unpack('<I', data[offset+8:offset+12])[0]
    body_len = struct.unpack('<I', data[offset+12:offset+16])[0]
    return {'magic': magic, 'f1': f1, 'f2': f2, 'opcode': opcode, 'seq': seq, 'body_len': body_len}

def hexdump(data, offset=0, width=16):
    for i in range(0, len(data), width):
        chunk = data[i:i+width]
        hex_str = ' '.join(f'{b:02x}' for b in chunk)
        ascii_str = ''.join(chr(b) if 32<=b<127 else '.' for b in chunk)
        print(f"{offset+i:04x}: {hex_str:<{width*3}} {ascii_str}")

def entropy(data):
    from math import log2
    if not data: return 0
    freq = {}
    for b in data: freq[b] = freq.get(b, 0) + 1
    ent = 0.0
    for count in freq.values():
        p = count / len(data)
        ent -= p * log2(p)
    return ent

def analyze_auth_packets(packets, timestamps, link_type):
    """Phân tích auth packets 0x1001 và 0x1002"""
    print("=" * 80)
    print("PHÂN TÍCH AUTH PACKETS (0x1001, 0x1002)")
    print("=" * 80)

    for i, (pkt, (ts_sec, ts_usec)) in enumerate(zip(packets, timestamps)):
        result = extract_tcp_payload(pkt, link_type)
        if result is None: continue
        sport, dport, payload = result
        if len(payload) < 16: continue

        hdr = parse_anogs_header(payload)
        if not hdr or hdr['opcode'] not in (0x1001, 0x1002):
            continue

        direction = "C->S" if sport > dport else "S->C"
        print(f"\n--- Packet {i} | {direction} | opcode=0x{hdr['opcode']:04x} | seq={hdr['seq']} | body_len={hdr['body_len']} ---")

        # Show full header
        print("Header bytes:")
        hexdump(payload[:16])

        # body_len here might be actual body length for auth
        body = payload[16:16+hdr['body_len']]
        trailer = payload[16+hdr['body_len']:]

        print(f"\nBody ({len(body)} bytes, entropy={entropy(body):.2f}):")
        hexdump(body[:128])

        print(f"\nTrailer ({len(trailer)} bytes):")
        hexdump(trailer[:128])

        # Look for strings
        for off in range(len(body)):
            if body[off:off+1] == b'\x00':
                continue
            # Try to read null-terminated string
            end = body.find(b'\x00', off)
            if end == -1:
                end = len(body)
            s = body[off:end]
            if len(s) >= 4 and all(32 <= b < 127 for b in s):
                print(f"  String at body offset {off}: '{s.decode()}'")

def analyze_key_exchange(packets, timestamps, link_type):
    """Phân tích key exchange packets 0x2001 và 0x2002"""
    print("\n" + "=" * 80)
    print("PHÂN TÍCH KEY EXCHANGE PACKETS (0x2001, 0x2002)")
    print("=" * 80)

    for i, (pkt, (ts_sec, ts_usec)) in enumerate(zip(packets, timestamps)):
        result = extract_tcp_payload(pkt, link_type)
        if result is None: continue
        sport, dport, payload = result
        if len(payload) < 16: continue

        hdr = parse_anogs_header(payload)
        if not hdr or hdr['opcode'] not in (0x2001, 0x2002):
            continue

        direction = "C->S" if sport > dport else "S->C"
        print(f"\n--- Packet {i} | {direction} | opcode=0x{hdr['opcode']:04x} | seq={hdr['seq']} | body_len={hdr['body_len']} ---")

        print("Header bytes:")
        hexdump(payload[:16])

        # For key exchange, body_len might be actual length
        body = payload[16:16+hdr['body_len']]
        trailer = payload[16+hdr['body_len']:]

        print(f"\nBody ({len(body)} bytes, entropy={entropy(body):.2f}):")
        hexdump(body[:256])

        if len(trailer) > 0:
            print(f"\nTrailer ({len(trailer)} bytes):")
            hexdump(trailer[:128])

        # Look for known crypto constants
        print("\nChecking for crypto constants:")

        # AES S-box first few bytes: 0x63 0x7c 0x77 0x7b
        if b'\x63\x7c\x77\x7b' in body:
            print("  FOUND: AES S-box signature!")

        # ChaCha20 sigma: "expand 32-byte k"
        if b'expand 32-byte k' in body:
            print("  FOUND: ChaCha20 sigma constant!")

        # Curve25519 / ECDH OIDs
        if b'\x2b\x65\x6e' in body:  # OID for Curve25519 (1.3.101.110)
            print("  FOUND: Curve25519 OID!")
        if b'\x2b\x65\x70' in body:  # OID for X25519 (1.3.101.112)
            print("  FOUND: X25519 OID!")

        # Look for prime numbers (RSA/DH)
        print("\n  Looking for large prime-like structures (first 4 bytes as length):")
        if len(body) >= 4:
            le_len = struct.unpack('<I', body[:4])[0]
            be_len = struct.unpack('>I', body[:4])[0]
            if 0 < le_len < len(body) - 4:
                print(f"    LE length at start: {le_len} -> next bytes: {body[4:4+min(32, le_len)].hex()}")
            if 0 < be_len < len(body) - 4:
                print(f"    BE length at start: {be_len} -> next bytes: {body[4:4+min(32, be_len)].hex()}")

        # Check for fixed XOR patterns
        print("\n  Testing for simple XOR encryption on body:")
        for key in [0x33, 0x66, 0x00, 0xff, 0x55, 0xaa, 0x0a]:
            xored = bytes([b ^ key for b in body[:64]])
            printable = sum(1 for b in xored if 32 <= b < 127 or b in (0, 10, 13))
            if printable > 30:
                print(f"    XOR key 0x{key:02x}: {printable}/64 printable")

def analyze_4013_first_packet(packets, timestamps, link_type):
    """Phân tích packet 0x4013 đầu tiên (C->S, lớn nhất)"""
    print("\n" + "=" * 80)
    print("PHÂN TÍCH PACKET 0x4013 ĐẦU TIÊN (LỚN NHẤT)")
    print("=" * 80)

    candidates = []
    for i, (pkt, (ts_sec, ts_usec)) in enumerate(zip(packets, timestamps)):
        result = extract_tcp_payload(pkt, link_type)
        if result is None: continue
        sport, dport, payload = result
        if len(payload) < 16: continue

        hdr = parse_anogs_header(payload)
        if not hdr or hdr['opcode'] != 0x4013:
            continue

        direction = "C->S" if sport > dport else "S->C"
        if direction == "C->S":
            candidates.append((i, len(payload), payload, hdr))

    if not candidates:
        print("Không tìm thấy packet 0x4013 C->S")
        return

    # Lấy packet lớn nhất
    candidates.sort(key=lambda x: x[1], reverse=True)
    idx, size, payload, hdr = candidates[0]

    print(f"\nPacket {idx}: {size} bytes")
    print("Header:")
    hexdump(payload[:16])

    # body_len là chunk index, trailer chứa dữ liệu thực
    body = payload[16:16+hdr['body_len']]
    trailer = payload[16+hdr['body_len']:]

    print(f"\nBody ({len(body)} bytes, index={hdr['body_len']}):")
    hexdump(body[:64])

    print(f"\nTrailer ({len(trailer)} bytes, entropy={entropy(trailer):.2f}):")
    hexdump(trailer[:256])

    # Phân tích trailer structure
    print("\nPhân tích cấu trúc trailer:")

    # Kiểm tra length prefix ở đầu trailer
    if len(trailer) >= 4:
        le_len = struct.unpack('<I', trailer[:4])[0]
        be_len = struct.unpack('>I', trailer[:4])[0]
        print(f"  4 bytes đầu trailer: LE={le_len}, BE={be_len}")

    # Kiểm tra alignment 16-byte (AES block)
    print(f"\n  Trailer length mod 16 = {len(trailer) % 16}")
    print(f"  Trailer length mod 12 = {len(trailer) % 12}")  # ChaCha20 block
    print(f"  Trailer length mod 64 = {len(trailer) % 64}")  # Some ciphers

    # Dump toàn bộ trailer đầu tiên để phân tích thủ công
    print(f"\nFull trailer hex (first 512 bytes):")
    print(trailer[:512].hex())

def main():
    packets, timestamps, link_type = read_pcap("/tmp/anti_cheat_17500.pcap")
    print(f"Loaded {len(packets)} packets\n")

    analyze_auth_packets(packets, timestamps, link_type)
    analyze_key_exchange(packets, timestamps, link_type)
    analyze_4013_first_packet(packets, timestamps, link_type)

if __name__ == "__main__":
    main()
