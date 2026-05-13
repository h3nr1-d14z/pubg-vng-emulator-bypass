#!/usr/bin/env python3
"""
Deep analysis v5: Reassemble chunked data stream
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
    return {'opcode': opcode, 'seq': seq, 'body_len': body_len, 'total_len': 16 + body_len}

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

def main():
    packets, link_type = read_pcap("/tmp/anti_cheat_17500.pcap")
    print(f"Loaded {len(packets)} packets")
    
    cs_chunks = {}  # C->S chunks keyed by body_len
    sc_chunks = {}  # S->C chunks keyed by body_len
    
    for i, pkt in enumerate(packets):
        result = extract_tcp_payload(pkt, link_type)
        if result is None: continue
        sport, dport, payload = result
        if len(payload) < 16: continue
        
        hdr = parse_anogs_header(payload)
        if not hdr or hdr['opcode'] != 0x4013:
            continue
        
        body_len = hdr['body_len']
        trailer = payload[16+body_len:]
        
        if sport > dport:  # C->S
            if body_len not in cs_chunks:
                cs_chunks[body_len] = []
            cs_chunks[body_len].append((i, trailer))
        else:  # S->C
            if body_len not in sc_chunks:
                sc_chunks[body_len] = []
            sc_chunks[body_len].append((i, trailer))
    
    # Sort by body_len
    print(f"\n{'='*80}")
    print("C->S CHUNKS (sorted by body_len)")
    print(f"{'='*80}")
    for bl in sorted(cs_chunks.keys()):
        chunks = cs_chunks[bl]
        total = sum(len(c[1]) for c in chunks)
        print(f"body_len={bl}: {len(chunks)} chunks, total {total} bytes")
        if bl <= 5:
            for idx, trailer in chunks[:3]:
                print(f"  Pkt {idx}: {len(trailer)} bytes trailer, entropy={entropy(trailer):.2f}")
                if len(trailer) <= 64:
                    print(f"    {trailer.hex()}")
    
    print(f"\n{'='*80}")
    print("S->C CHUNKS (sorted by body_len)")
    print(f"{'='*80}")
    for bl in sorted(sc_chunks.keys()):
        chunks = sc_chunks[bl]
        total = sum(len(c[1]) for c in chunks)
        print(f"body_len={bl}: {len(chunks)} chunks, total {total} bytes")
        if bl <= 10:
            for idx, trailer in chunks[:3]:
                print(f"  Pkt {idx}: {len(trailer)} bytes trailer, entropy={entropy(trailer):.2f}")
                if len(trailer) <= 64:
                    print(f"    {trailer.hex()}")
    
    # Try reassembling C->S stream
    print(f"\n{'='*80}")
    print("REASSEMBLING C->S DATA STREAM")
    print(f"{'='*80}")
    cs_stream = b''
    for bl in sorted(cs_chunks.keys()):
        # Just take first chunk for each body_len
        cs_stream += cs_chunks[bl][0][1]
    
    print(f"Total reassembled: {len(cs_stream)} bytes")
    print(f"Entropy: {entropy(cs_stream):.2f}")
    
    # Save for analysis
    with open('/tmp/cs_stream.bin', 'wb') as f:
        f.write(cs_stream)
    print("Saved to /tmp/cs_stream.bin")
    
    # Try reassembling S->C stream
    print(f"\n{'='*80}")
    print("REASSEMBLING S->C DATA STREAM")
    print(f"{'='*80}")
    sc_stream = b''
    for bl in sorted(sc_chunks.keys()):
        sc_stream += sc_chunks[bl][0][1]
    
    print(f"Total reassembled: {len(sc_stream)} bytes")
    print(f"Entropy: {entropy(sc_stream):.2f}")
    
    with open('/tmp/sc_stream.bin', 'wb') as f:
        f.write(sc_stream)
    print("Saved to /tmp/sc_stream.bin")
    
    # Look for strings in streams
    print(f"\n{'='*80}")
    print("STRING SEARCH IN C->S STREAM")
    print(f"{'='*80}")
    strings = []
    current = ""
    for i, b in enumerate(cs_stream):
        if 32 <= b < 127:
            current += chr(b)
        else:
            if len(current) >= 4:
                strings.append((i-len(current), current))
            current = ""
    if len(current) >= 4:
        strings.append((len(cs_stream)-len(current), current))
    
    print(f"Found {len(strings)} strings")
    for off, s in strings[:30]:
        print(f"  {off:06x}: '{s}'")
    
    # Look for emulator keywords
    keywords = [b'ldplayer', b'emulator', b'vbox', b'virtualbox', b'generic', 
                b'goldfish', b'ranchu', b'qemu', b'x86', b'intel', b'amd', 
                b'unknown', b'ro.hardware', b'ro.product', b'build.fingerprint',
                b'bluestacks', b'nox', b'memu', b'andro', b'android']
    print(f"\n{'='*80}")
    print("EMULATOR KEYWORD SEARCH IN C->S STREAM")
    print(f"{'='*80}")
    found_any = False
    for kw in keywords:
        idx = cs_stream.lower().find(kw)
        if idx >= 0:
            found_any = True
            ctx = cs_stream[max(0,idx-16):idx+len(kw)+16]
            print(f"FOUND '{kw.decode()}' at offset {idx:06x}")
            print(f"  Context: {ctx.hex()}")
    if not found_any:
        print("No emulator keywords found in cleartext")
    
    # Check first bytes of stream for structure
    print(f"\n{'='*80}")
    print("STREAM STRUCTURE ANALYSIS")
    print(f"{'='*80}")
    print(f"First 256 bytes of C->S stream:")
    for i in range(0, min(256, len(cs_stream)), 16):
        chunk = cs_stream[i:i+16]
        hex_str = ' '.join(f'{b:02x}' for b in chunk)
        ascii_str = ''.join(chr(b) if 32<=b<127 else '.' for b in chunk)
        print(f"  {i:04x}: {hex_str}  {ascii_str}")

if __name__ == "__main__":
    main()
