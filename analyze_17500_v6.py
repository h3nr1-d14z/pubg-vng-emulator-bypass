#!/usr/bin/env python3
"""
Deep analysis v6: Separate streams by seq field and reassemble by time
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

def hexdump(data, offset=0, width=16):
    for i in range(0, min(len(data), 512), width):
        chunk = data[i:i+width]
        hex_str = ' '.join(f'{b:02x}' for b in chunk)
        ascii_str = ''.join(chr(b) if 32<=b<127 else '.' for b in chunk)
        print(f"{offset+i:04x}: {hex_str:<{width*3}} {ascii_str}")

def main():
    packets, timestamps, link_type = read_pcap("/tmp/anti_cheat_17500.pcap")
    print(f"Loaded {len(packets)} packets")
    
    # Separate by (direction, seq) = stream
    streams = {}
    
    for i, (pkt, (ts_sec, ts_usec)) in enumerate(zip(packets, timestamps)):
        result = extract_tcp_payload(pkt, link_type)
        if result is None: continue
        sport, dport, payload = result
        if len(payload) < 16: continue
        
        hdr = parse_anogs_header(payload)
        if not hdr or hdr['opcode'] != 0x4013:
            continue
        
        direction = "C->S" if sport > dport else "S->C"
        stream_key = (direction, hdr['seq'])
        
        if stream_key not in streams:
            streams[stream_key] = []
        
        body_len = hdr['body_len']
        trailer = payload[16+body_len:]
        
        streams[stream_key].append({
            'pkt_idx': i,
            'ts': ts_sec + ts_usec/1e6,
            'body_len': body_len,
            'trailer': trailer,
            'hdr': hdr
        })
    
    print(f"\nFound {len(streams)} streams:")
    for key in sorted(streams.keys()):
        print(f"  {key}: {len(streams[key])} packets")
    
    # Analyze each stream
    for key in sorted(streams.keys()):
        stream = streams[key]
        print(f"\n{'='*80}")
        print(f"STREAM: {key[0]} seq=0x{key[1]:08x} ({key[1]})")
        print(f"{'='*80}")
        
        # Sort by time
        stream.sort(key=lambda x: x['ts'])
        
        # Reassemble in time order
        reassembled = b''
        for entry in stream:
            reassembled += entry['trailer']
        
        print(f"Packets: {len(stream)}")
        print(f"Reassembled size: {len(reassembled)} bytes")
        print(f"Entropy: {entropy(reassembled):.2f}")
        
        # Show first chunks
        print(f"\nFirst 20 packets (by time):")
        for entry in stream[:20]:
            print(f"  Pkt {entry['pkt_idx']} body_len={entry['body_len']:3d} trailer={len(entry['trailer']):4d}B "
                  f"ts={entry['ts']:.6f} entropy={entropy(entry['trailer']):.2f}")
        
        # Save reassembled
        fname = f"/tmp/stream_{key[0].replace('->','_')}_seq{key[1]}.bin"
        with open(fname, 'wb') as f:
            f.write(reassembled)
        print(f"Saved reassembled stream to {fname}")
        
        # Analyze reassembled data structure
        if len(reassembled) > 0:
            print(f"\nFirst 256 bytes of reassembled stream:")
            hexdump(reassembled[:256])
            
            # Look for length fields at start
            if len(reassembled) >= 4:
                le_len = struct.unpack('<I', reassembled[:4])[0]
                be_len = struct.unpack('>I', reassembled[:4])[0]
                print(f"\nFirst 4 bytes as LE length: {le_len}")
                print(f"First 4 bytes as BE length: {be_len}")
            
            # Look for strings
            strings = []
            current = ""
            for i, b in enumerate(reassembled):
                if 32 <= b < 127:
                    current += chr(b)
                else:
                    if len(current) >= 4:
                        strings.append((i-len(current), current))
                    current = ""
            if current:
                strings.append((len(reassembled)-len(current), current))
            
            if strings:
                print(f"\nFound {len(strings)} ASCII strings (showing first 30):")
                for off, s in strings[:30]:
                    print(f"  {off:06x}: '{s}'")
            
            # Check for zlib/gzip
            if reassembled[:2] == b'\x78\x9c':
                print("\nFound zlib deflate signature!")
            if reassembled[:2] == b'\x1f\x8b':
                print("\nFound gzip signature!")
            
            # Emulator keywords
            keywords = [b'ldplayer', b'emulator', b'vbox', b'virtualbox', b'generic', 
                        b'goldfish', b'ranchu', b'qemu', b'x86', b'intel', b'amd', 
                        b'unknown', b'ro.hardware', b'ro.product', b'build.fingerprint',
                        b'bluestacks', b'nox', b'memu', b'android']
            print(f"\nEmulator keyword search:")
            found = False
            for kw in keywords:
                idx = reassembled.lower().find(kw)
                if idx >= 0:
                    found = True
                    print(f"  FOUND '{kw.decode()}' at offset {idx:06x}")
            if not found:
                print("  No emulator keywords found in cleartext")

if __name__ == "__main__":
    main()
