#!/usr/bin/env python3
"""
Deep analysis v2: Focus on TCP payload structure beyond ANOGS body_len
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
    if link_type == 1:
        if len(pkt_data) < 14: return None
        eth_type = struct.unpack('>H', pkt_data[12:14])[0]
        if eth_type != 0x0800: return None
        ip_start = 14
    elif link_type == 101:
        ip_start = 0
    elif link_type == 113:
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

def find_all_anogs_frames(payload):
    """Find all ANOGS frames embedded in TCP payload"""
    frames = []
    i = 0
    while i <= len(payload) - 16:
        if payload[i:i+2] == ANOGS_MAGIC:
            hdr = parse_anogs_header(payload, i)
            if hdr and i + hdr['total_len'] <= len(payload):
                frames.append(hdr)
                i += hdr['total_len']
                continue
        i += 1
    return frames

def main():
    packets, link_type = read_pcap("/tmp/anti_cheat_17500.pcap")
    print(f"Loaded {len(packets)} packets, link_type={link_type}")
    
    # Collect all TCP payloads with port 17500
    tcp_payloads = []
    for i, pkt in enumerate(packets):
        result = extract_tcp_payload(pkt, link_type)
        if result is None: continue
        src_ip, dst_ip, sport, dport, payload = result
        if sport == 17500 or dport == 17500:
            tcp_payloads.append((i, src_ip, dst_ip, sport, dport, payload))
    
    print(f"Found {len(tcp_payloads)} TCP packets on port 17500")
    
    # Analyze each packet
    for idx, src_ip, dst_ip, sport, dport, payload in tcp_payloads[:25]:
        direction = "C->S" if sport > dport else "S->C"
        frames = find_all_anogs_frames(payload)
        
        print(f"\n{'='*80}")
        print(f"Pkt {idx}: {direction} {src_ip}:{sport} -> {dst_ip}:{dport}")
        print(f"TCP payload: {len(payload)} bytes")
        print(f"ANOGS frames found: {len(frames)}")
        
        if frames:
            for j, f in enumerate(frames):
                print(f"  Frame {j}: opcode={f['opcode']} seq={f['seq']} body_len={f['body_len']} total={f['total_len']} offset={f['offset']}")
                body = payload[f['offset']+16:f['offset']+16+f['body_len']]
                print(f"    Body entropy: {entropy(body):.2f}")
                if f['body_len'] <= 32:
                    print(f"    Body hex: {body.hex()}")
                else:
                    print(f"    Body first 32 bytes: {body[:32].hex()}")
        else:
            print("  No ANOGS frames found! Raw hexdump:")
            hexdump(payload[:64])
            
        # If multiple frames, show gaps
        if len(frames) > 1:
            print("  Gaps between frames:")
            for j in range(len(frames)-1):
                gap_start = frames[j]['offset'] + frames[j]['total_len']
                gap_end = frames[j+1]['offset']
                if gap_end > gap_start:
                    gap = payload[gap_start:gap_end]
                    print(f"    Gap {j+1}: {len(gap)} bytes")
                    hexdump(gap[:min(len(gap), 32)])
        
        # Show trailer after last frame
        if frames:
            last_end = frames[-1]['offset'] + frames[-1]['total_len']
            if last_end < len(payload):
                trailer = payload[last_end:]
                print(f"  Trailer after last frame: {len(trailer)} bytes")
                hexdump(trailer[:min(len(trailer), 64)])

if __name__ == "__main__":
    main()
