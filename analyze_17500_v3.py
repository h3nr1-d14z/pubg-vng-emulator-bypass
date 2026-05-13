#!/usr/bin/env python3
"""
Deep analysis v3: Analyze trailer structure and crypto patterns
"""
import struct

ANOGS_MAGIC = b'\x33\x66'

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
    src_ip = '.'.join(str(b) for b in ip_header[12:16])
    dst_ip = '.'.join(str(b) for b in ip_header[16:20])
    if protocol != 6: return None
    tcp_start = ip_start + ihl
    if len(pkt_data) < tcp_start + 20: return None
    tcp_header = pkt_data[tcp_start:]
    src_port = struct.unpack('>H', tcp_header[0:2])[0]
    dst_port = struct.unpack('>H', tcp_header[2:4])[0]
    data_offset = ((tcp_header[12] >> 4) & 0x0f) * 4
    payload_start = tcp_start + data_offset
    return src_ip, dst_ip, src_port, dst_port, pkt_data[payload_start:]

def parse_anogs_header(data, offset=0):
    if len(data) < offset + 16: return None
    magic = data[offset:offset+2]
    if magic != ANOGS_MAGIC: return None
    f1 = struct.unpack('>H', data[offset+2:offset+4])[0]
    f2 = struct.unpack('>H', data[offset+4:offset+6])[0]
    opcode = struct.unpack('>H', data[offset+6:offset+8])[0]
    seq = struct.unpack('<I', data[offset+8:offset+12])[0]
    body_len = struct.unpack('<I', data[offset+12:offset+16])[0]
    return {
        'magic': magic.hex(), 'f1': f"0x{f1:04x}", 'f2': f"0x{f2:04x}",
        'opcode': f"0x{opcode:04x}", 'seq': seq, 'body_len': body_len,
        'total_len': 16 + body_len, 'offset': offset
    }

def hexdump(data, offset=0, width=16):
    for i in range(0, len(data), width):
        chunk = data[i:i+width]
        hex_str = ' '.join(f'{b:02x}' for b in chunk)
        ascii_str = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
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

def analyze_trailer_structure(trailer, pkt_info):
    """Analyze trailer for structure patterns"""
    print(f"\n--- Trailer Analysis ({len(trailer)} bytes) ---")
    print(f"Entropy: {entropy(trailer):.2f}")
    
    # Look for 4-byte length fields at start
    if len(trailer) >= 4:
        val = struct.unpack('<I', trailer[:4])[0]
        print(f"First 4 bytes (LE): {val} (0x{val:08x})")
        val_be = struct.unpack('>I', trailer[:4])[0]
        print(f"First 4 bytes (BE): {val_be} (0x{val_be:08x})")
    
    # Check if trailer starts with known patterns
    if len(trailer) >= 2:
        print(f"First 2 bytes: {trailer[:2].hex()}")
    
    # Look for length-value pairs
    print("\nScanning for potential LV structure...")
    found = 0
    for i in range(0, min(256, len(trailer)-4), 1):
        lv = struct.unpack('<I', trailer[i:i+4])[0]
        if 0 < lv < len(trailer) - i - 4 and lv < 10000:
            # Check if data after length looks printable or structured
            following = trailer[i+4:i+4+min(lv, 32)]
            printable = sum(1 for b in following if 32 <= b < 127 or b == 0)
            if printable > min(lv, 32) * 0.3 or lv < 100:
                print(f"  Offset {i:04x}: len={lv} -> {following[:16].hex()}...")
                found += 1
                if found > 10: break
    
    # Show first 128 bytes
    print("\nFirst 128 bytes of trailer:")
    hexdump(trailer[:128])
    
    # Look for string clusters
    strings = []
    current = ""
    for i, b in enumerate(trailer):
        if 32 <= b < 127:
            current += chr(b)
        else:
            if len(current) >= 4:
                strings.append((i-len(current), current))
            current = ""
    if len(current) >= 4:
        strings.append((len(trailer)-len(current), current))
    
    if strings:
        print(f"\nFound {len(strings)} ASCII strings (>=4 chars):")
        for off, s in strings[:20]:
            print(f"  {off:04x}: '{s}'")

def analyze_key_exchange(pkt_idx, payload):
    """Deep analysis of key exchange packets"""
    print(f"\n{'='*80}")
    print(f"KEY EXCHANGE PACKET {pkt_idx} ({len(payload)} bytes)")
    print(f"{'='*80}")
    
    hdr = parse_anogs_header(payload)
    if not hdr:
        print("No ANOGS header")
        return
    
    print(f"Header: {hdr}")
    body = payload[16:16+hdr['body_len']]
    trailer = payload[16+hdr['body_len']:]
    
    print(f"\nBody ({len(body)} bytes): {body.hex()}")
    
    print(f"\nTrailer ({len(trailer)} bytes):")
    hexdump(trailer)
    
    # Look for public key patterns, curve identifiers, etc.
    print("\n--- Crypto Pattern Analysis ---")
    
    # Check for 0x00 0x00 prefix in trailer (common in ASN.1 or length-prefixed data)
    if trailer[:2] == b'\x00\x00':
        print("Trailer starts with 0x00 0x00 - possible length-prefixed structure")
        # Next 2 bytes might be length
        next_len = struct.unpack('>H', trailer[2:4])[0] if len(trailer) >= 4 else 0
        print(f"  Next 2 bytes (BE): {next_len} (0x{next_len:04x})")
        next_len_le = struct.unpack('<H', trailer[2:4])[0] if len(trailer) >= 4 else 0
        print(f"  Next 2 bytes (LE): {next_len_le} (0x{next_len_le:04x})")
    
    # Look for fixed-size blocks (32, 48, 64 bytes)
    for block_size in [32, 48, 64]:
        if len(trailer) >= block_size:
            # Check if multiple blocks have similar entropy
            blocks = [trailer[i:i+block_size] for i in range(0, len(trailer)-block_size+1, block_size)]
            if len(blocks) >= 2:
                ents = [entropy(b) for b in blocks]
                avg_ent = sum(ents) / len(ents)
                print(f"  {block_size}-byte blocks: avg entropy = {avg_ent:.2f} ({len(blocks)} blocks)")
    
    # Check for known crypto constants
    constants = {
        'secp256r1': b'\x2a\x86\x48\xce\x3d\x03\x01\x07',
        'secp384r1': b'\x2b\x81\x04\x00\x23',
        'secp521r1': b'\x2b\x81\x04\x00\x23',
    }
    for name, const in constants.items():
        if const in trailer:
            print(f"  Found {name} OID in trailer!")
    
    return trailer

def main():
    packets, link_type = read_pcap("/tmp/anti_cheat_17500.pcap")
    print(f"Loaded {len(packets)} packets")
    
    payloads = {}
    for i, pkt in enumerate(packets):
        result = extract_tcp_payload(pkt, link_type)
        if result is None: continue
        src_ip, dst_ip, sport, dport, payload = result
        if sport == 17500 or dport == 17500:
            payloads[i] = (sport, dport, payload)
    
    # Analyze key exchange packets (7 and 8)
    if 7 in payloads:
        trailer7 = analyze_key_exchange(7, payloads[7][2])
    if 8 in payloads:
        trailer8 = analyze_key_exchange(8, payloads[8][2])
    
    # Analyze auth packets (3, 5)
    print(f"\n{'='*80}")
    print("AUTH PACKET 3 (opcode 0x1001)")
    print(f"{'='*80}")
    if 3 in payloads:
        p = payloads[3][2]
        hdr = parse_anogs_header(p)
        print(f"Header: {hdr}")
        trailer = p[16+hdr['body_len']:]
        analyze_trailer_structure(trailer, "auth3")
    
    print(f"\n{'='*80}")
    print("AUTH PACKET 5 (opcode 0x1002)")
    print(f"{'='*80}")
    if 5 in payloads:
        p = payloads[5][2]
        hdr = parse_anogs_header(p)
        print(f"Header: {hdr}")
        trailer = p[16+hdr['body_len']:]
        analyze_trailer_structure(trailer, "auth5")
    
    # Analyze the large packet 16
    print(f"\n{'='*80}")
    print("LARGE PACKET 16 (opcode 0x4013, 2537 bytes)")
    print(f"{'='*80}")
    if 16 in payloads:
        p = payloads[16][2]
        hdr = parse_anogs_header(p)
        print(f"Header: {hdr}")
        trailer = p[16+hdr['body_len']:]
        analyze_trailer_structure(trailer, "pkt16")
        
        # Save trailer to file for further analysis
        with open('/tmp/pkt16_trailer.bin', 'wb') as f:
            f.write(trailer)
        print(f"\nSaved trailer to /tmp/pkt16_trailer.bin ({len(trailer)} bytes)")
    
    # Analyze packet 18 (server response with multiple frames)
    print(f"\n{'='*80}")
    print("PACKET 18 (server response, 1423 bytes)")
    print(f"{'='*80}")
    if 18 in payloads:
        p = payloads[18][2]
        hdr = parse_anogs_header(p)
        print(f"Header: {hdr}")
        trailer = p[16+hdr['body_len']:]
        analyze_trailer_structure(trailer, "pkt18")

if __name__ == "__main__":
    main()
