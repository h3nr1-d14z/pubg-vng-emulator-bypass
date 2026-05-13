#!/usr/bin/env python3
"""
Deep analysis of ANOGS protocol on port 17500
Focus: Packet 17 (2537 bytes C->S) and Packet 19 (embedded sub-packets)
Goal: Identify emulator detection fields and encryption patterns
"""

import struct
import os

# ANOGS header constants
ANOGS_MAGIC = b'\x33\x66'

def read_pcap(filename):
    """Read pcap file without external dependencies"""
    with open(filename, 'rb') as f:
        data = f.read()

    # Global header: 24 bytes
    magic = struct.unpack('<I', data[:4])[0]
    if magic == 0xa1b2c3d4:
        endian = '<'
    elif magic == 0xd4c3b2a1:
        endian = '>'
    else:
        raise ValueError("Not a pcap file or unsupported byte order")

    link_type = struct.unpack(endian + 'I', data[20:24])[0]
    offset = 24
    packets = []

    while offset < len(data):
        # Packet header: 16 bytes
        if offset + 16 > len(data):
            break
        ts_sec, ts_usec, incl_len, orig_len = struct.unpack(endian + 'IIII', data[offset:offset+16])
        offset += 16
        if offset + incl_len > len(data):
            break
        pkt_data = data[offset:offset+incl_len]
        offset += incl_len
        packets.append(pkt_data)

    return packets, link_type

def parse_anogs_header(data, offset=0):
    """Parse ANOGS protocol header at given offset"""
    if len(data) < offset + 16:
        return None
    magic = data[offset:offset+2]
    if magic != ANOGS_MAGIC:
        return None
    f1 = struct.unpack('>H', data[offset+2:offset+4])[0]
    f2 = struct.unpack('>H', data[offset+4:offset+6])[0]
    opcode = struct.unpack('>H', data[offset+6:offset+8])[0]
    seq = struct.unpack('<I', data[offset+8:offset+12])[0]
    body_len = struct.unpack('<I', data[offset+12:offset+16])[0]
    return {
        'magic': magic.hex(),
        'f1': f"0x{f1:04x}",
        'f2': f"0x{f2:04x}",
        'opcode': f"0x{opcode:04x}",
        'seq': seq,
        'body_len': body_len,
        'total_len': 16 + body_len,
        'offset': offset
    }

def hexdump(data, offset=0, width=16):
    """Print hexdump with byte offsets"""
    for i in range(0, len(data), width):
        chunk = data[i:i+width]
        hex_str = ' '.join(f'{b:02x}' for b in chunk)
        ascii_str = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        print(f"{offset+i:04x}: {hex_str:<{width*3}} {ascii_str}")

def entropy(data):
    """Calculate Shannon entropy to detect encrypted vs structured data"""
    from math import log2
    if not data:
        return 0
    freq = {}
    for b in data:
        freq[b] = freq.get(b, 0) + 1
    ent = 0.0
    for count in freq.values():
        p = count / len(data)
        ent -= p * log2(p)
    return ent

def extract_tcp_payload(pkt_data, link_type):
    """Extract TCP payload from packet data based on link type"""
    if link_type == 1:  # Ethernet
        if len(pkt_data) < 14:
            return None, None, None, None
        eth_type = struct.unpack('>H', pkt_data[12:14])[0]
        if eth_type != 0x0800:  # Not IP
            return None, None, None, None
        ip_start = 14
    elif link_type == 101:  # Raw IP
        ip_start = 0
    elif link_type == 113:  # Linux cooked capture (SLL)
        if len(pkt_data) < 16:
            return None, None, None, None
        proto = struct.unpack('>H', pkt_data[14:16])[0]
        if proto != 0x0800:
            return None, None, None, None
        ip_start = 16
    else:
        return None, None, None, None

    if len(pkt_data) < ip_start + 20:
        return None, None, None, None

    ip_header = pkt_data[ip_start:]
    version_ihl = ip_header[0]
    ihl = (version_ihl & 0x0f) * 4
    protocol = ip_header[9]
    src_ip = '.'.join(str(b) for b in ip_header[12:16])
    dst_ip = '.'.join(str(b) for b in ip_header[16:20])

    if protocol != 6:  # Not TCP
        return None, None, None, None

    tcp_start = ip_start + ihl
    if len(pkt_data) < tcp_start + 20:
        return None, None, None, None

    tcp_header = pkt_data[tcp_start:]
    src_port = struct.unpack('>H', tcp_header[0:2])[0]
    dst_port = struct.unpack('>H', tcp_header[2:4])[0]
    data_offset = ((tcp_header[12] >> 4) & 0x0f) * 4
    payload_start = tcp_start + data_offset

    payload = pkt_data[payload_start:]
    return src_ip, dst_ip, src_port, dst_port, payload

def analyze_packet_17(pkt_data):
    """Analyze the 2537-byte client payload (opcode 0x4013)"""
    print("=" * 80)
    print("PACKET 17 ANALYSIS: 2537-byte client payload (opcode 0x4013)")
    print("=" * 80)

    header = parse_anogs_header(pkt_data)
    if not header:
        print("ERROR: Not a valid ANOGS packet")
        return

    print(f"\nHeader: {header}")
    body = pkt_data[16:16+header['body_len']]
    print(f"Body length: {len(body)} bytes")
    print(f"Entropy: {entropy(body):.2f}/8.00 (8.0=random/encrypted, <7.0=structured)")

    # Print first 256 bytes of body
    print("\n--- Body first 256 bytes ---")
    hexdump(body[:256])

    # Check for known strings
    print("\n--- Looking for ASCII strings in body ---")
    strings = []
    current = ""
    for i, b in enumerate(body):
        if 32 <= b < 127:
            current += chr(b)
        else:
            if len(current) >= 4:
                strings.append((i-len(current), current))
            current = ""
    if len(current) >= 4:
        strings.append((len(body)-len(current), current))

    for offset, s in strings[:30]:  # Limit output
        print(f"  Offset {offset:04x}: '{s}'")

    # Look for potential TLV structure
    print("\n--- Analyzing potential TLV structure ---")
    print("Scanning for length-prefixed fields at 4-byte boundaries...")
    for i in range(0, min(128, len(body)), 4):
        if i+4 <= len(body):
            val = struct.unpack('<I', body[i:i+4])[0]
            if 0 < val < 1000 and i + 4 + val <= len(body):
                # Potential length field
                preview = body[i+4:i+4+min(val, 32)]
                hex_preview = ' '.join(f'{b:02x}' for b in preview)
                ascii_preview = ''.join(chr(b) if 32 <= b < 127 else '.' for b in preview)
                print(f"  Offset {i:04x}: len={val:4d} -> {hex_preview} | {ascii_preview}")

    # Check for zlib/gzip magic
    print("\n--- Checking for compression signatures ---")
    if body[:2] == b'\x78\x9c':
        print("  Found zlib deflate signature at offset 0!")
    if body[:2] == b'\x1f\x8b':
        print("  Found gzip signature at offset 0!")

    # Look for common Android/emulator property strings
    print("\n--- Scanning for emulator-related keywords ---")
    keywords = [b'ldplayer', b'emulator', b'vbox', b'virtualbox',
                b'generic', b'goldfish', b'ranchu', b'qemu',
                b'x86', b'intel', b'amd', b'unknown',
                b'ro.hardware', b'ro.product', b'build.fingerprint']
    for kw in keywords:
        idx = body.find(kw)
        if idx >= 0:
            ctx = body[max(0,idx-16):idx+len(kw)+16]
            print(f"  Found '{kw.decode()}' at offset {idx:04x}")
            print(f"    Context: {ctx.hex()}")

    # Check for null-terminated string clusters
    print("\n--- Null-terminated string clusters ---")
    null_positions = [i for i, b in enumerate(body) if b == 0]
    clusters = []
    cluster_start = 0
    for i in range(1, len(null_positions)):
        if null_positions[i] - null_positions[i-1] > 64:  # Gap > 64 bytes
            if i - cluster_start > 3:
                clusters.append((null_positions[cluster_start], null_positions[i-1]))
            cluster_start = i
    for start, end in clusters[:5]:
        print(f"  Cluster at {start:04x}-{end:04x}")
        hexdump(body[start:end+1])

    # Statistical analysis: byte frequency
    print("\n--- Byte frequency analysis (top 10) ---")
    freq = {}
    for b in body:
        freq[b] = freq.get(b, 0) + 1
    sorted_freq = sorted(freq.items(), key=lambda x: x[1], reverse=True)[:10]
    for b, count in sorted_freq:
        print(f"  0x{b:02x} ({chr(b) if 32<=b<127 else '?'}): {count} times ({100*count/len(body):.1f}%)")

    return body

def analyze_packet_19(pkt_data):
    """Analyze Packet 19 with embedded sub-packets"""
    print("\n" + "=" * 80)
    print("PACKET 19 ANALYSIS: Server response with embedded sub-packets")
    print("=" * 80)

    header = parse_anogs_header(pkt_data)
    if not header:
        print("ERROR: Not a valid ANOGS packet")
        return

    print(f"\nOuter Header: {header}")
    body = pkt_data[16:16+header['body_len']]
    print(f"Body length: {len(body)} bytes")

    # Find all embedded ANOGS packets
    print("\n--- Scanning for embedded sub-packets ---")
    embedded = []
    i = 0
    while i < len(body) - 16:
        if body[i:i+2] == ANOGS_MAGIC:
            sub = parse_anogs_header(body, i)
            if sub and i + sub['total_len'] <= len(body):
                embedded.append(sub)
                i += sub['total_len']
                continue
        i += 1

    print(f"Found {len(embedded)} embedded packets:")
    for j, sub in enumerate(embedded):
        print(f"\n  Sub-packet {j+1}: {sub}")
        sub_body = body[sub['offset']+16:sub['offset']+16+sub['body_len']]
        print(f"    Entropy: {entropy(sub_body):.2f}")
        print(f"    First 32 bytes:")
        hexdump(sub_body[:32], sub['offset']+16)

        # Check for strings
        strings = []
        current = ""
        for k, b in enumerate(sub_body):
            if 32 <= b < 127:
                current += chr(b)
            else:
                if len(current) >= 4:
                    strings.append(current)
                current = ""
        if strings:
            print(f"    Strings: {strings[:5]}")

    # Analyze gaps between embedded packets
    if len(embedded) >= 2:
        print("\n--- Gaps between embedded packets ---")
        for j in range(len(embedded)-1):
            gap_start = embedded[j]['offset'] + embedded[j]['total_len']
            gap_end = embedded[j+1]['offset']
            gap_len = gap_end - gap_start
            if gap_len > 0:
                gap_data = body[gap_start:gap_end]
                print(f"  Gap {j+1}: {gap_len} bytes at offset {gap_start:04x}")
                hexdump(gap_data[:min(gap_len, 32)])

    # Analyze data before first embedded packet
    if embedded:
        first_off = embedded[0]['offset']
        if first_off > 0:
            print(f"\n--- Prefix data before first sub-packet ({first_off} bytes) ---")
            prefix = body[:first_off]
            hexdump(prefix)
            print(f"Entropy: {entropy(prefix):.2f}")

    return body, embedded

def analyze_opcode_flow(packets, link_type):
    """Analyze the full opcode flow to understand session state"""
    print("\n" + "=" * 80)
    print("FULL OPCODE FLOW ANALYSIS")
    print("=" * 80)

    for i, pkt in enumerate(packets):
        result = extract_tcp_payload(pkt, link_type)
        if result[0] is None:
            continue
        src_ip, dst_ip, sport, dport, payload = result
        if len(payload) < 16:
            continue
        header = parse_anogs_header(payload)
        if not header:
            continue

        direction = "C->S" if sport > dport else "S->C"
        body = payload[16:16+header['body_len']]
        print(f"Pkt {i}: {direction} opcode={header['opcode']} seq={header['seq']} "
              f"body_len={header['body_len']} entropy={entropy(body):.2f}")

def main():
    pcap_file = "/tmp/anti_cheat_17500.pcap"
    print(f"Loading {pcap_file}...")
    packets, link_type = read_pcap(pcap_file)
    print(f"Loaded {len(packets)} packets (link_type={link_type})\n")

    # Find packets 17 and 19
    pkt17 = None
    pkt19 = None
    packets_17500 = []

    for i, pkt in enumerate(packets):
        result = extract_tcp_payload(pkt, link_type)
        if result[0] is None:
            continue
        src_ip, dst_ip, sport, dport, payload = result
        if len(payload) >= 16:
            header = parse_anogs_header(payload)
            if header:
                packets_17500.append(pkt)
                # Packet 17: C->S, large payload, opcode 0x4013
                if len(payload) > 2000 and sport > dport and not pkt17:
                    pkt17 = payload
                    print(f"Identified Packet 17 (index {i}): {len(payload)} bytes")
                # Packet 19: S->C, ~1423 bytes
                elif 1400 < len(payload) < 1500 and sport < dport and not pkt19:
                    pkt19 = payload
                    print(f"Identified Packet 19 (index {i}): {len(payload)} bytes")

    if pkt17:
        body17 = analyze_packet_17(pkt17)
    else:
        print("WARNING: Packet 17 not found!")

    if pkt19:
        body19, embedded19 = analyze_packet_19(pkt19)
    else:
        print("WARNING: Packet 19 not found!")

    analyze_opcode_flow(packets, link_type)

    # Additional: look for XOR or simple encryption patterns
    print("\n" + "=" * 80)
    print("ENCRYPTION PATTERN ANALYSIS")
    print("=" * 80)

    if pkt17:
        body = pkt17[16:]
        print("\n--- Testing for XOR with common keys ---")
        for key in [0x33, 0x66, 0x00, 0x0a, 0xff, 0x55, 0xaa]:
            xored = bytes([b ^ key for b in body[:64]])
            printable = sum(1 for b in xored if 32 <= b < 127 or b in (0, 10, 13))
            if printable > 40:
                print(f"  Key 0x{key:02x}: {printable}/64 printable after XOR")
                print(f"    Sample: {xored[:32].hex()}")

        print("\n--- Looking for repeating XOR keystream (4-byte period) ---")
        for period in [4, 8, 16]:
            counts = {}
            for i in range(0, len(body)-period, period):
                seq = bytes(body[i:i+period])
                counts[seq] = counts.get(seq, 0) + 1
            max_repeat = max(counts.values()) if counts else 0
            print(f"  Period {period}: max repeat = {max_repeat}")

        # Check for AES block structure
        print("\n--- Checking for AES block alignment ---")
        for offset in [0, 4, 8]:
            aligned = (len(body) - offset) % 16 == 0
            print(f"  Offset {offset}: {'AES-aligned' if aligned else 'not aligned'} ({(len(body)-offset)%16} remainder)")

if __name__ == "__main__":
    main()
