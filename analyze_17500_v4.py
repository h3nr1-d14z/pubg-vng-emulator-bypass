#!/usr/bin/env python3
"""
Deep analysis v4: Parse trailer TLV/length-prefixed structure
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
    f1 = struct.unpack('>H', data[offset+2:offset+4])[0]
    f2 = struct.unpack('>H', data[offset+4:offset+6])[0]
    opcode = struct.unpack('>H', data[offset+6:offset+8])[0]
    seq = struct.unpack('<I', data[offset+8:offset+12])[0]
    body_len = struct.unpack('<I', data[offset+12:offset+16])[0]
    return {
        'opcode': f"0x{opcode:04x}", 'seq': seq, 'body_len': body_len,
        'total_len': 16 + body_len, 'offset': offset
    }

def hexdump(data, offset=0, width=16):
    for i in range(0, len(data), width):
        chunk = data[i:i+width]
        hex_str = ' '.join(f'{b:02x}' for b in chunk)
        ascii_str = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        print(f"{offset+i:04x}: {hex_str:<{width*3}} {ascii_str}")

def parse_tlv_trailer(trailer, name):
    """Attempt to parse trailer as TLV structure"""
    print(f"\n--- TLV Parsing for {name} ({len(trailer)} bytes) ---")
    
    offset = 0
    field_num = 0
    while offset < len(trailer) - 4 and field_num < 50:
        field_num += 1
        
        # Try reading 4-byte LE length at current offset
        length = struct.unpack('<I', trailer[offset:offset+4])[0]
        
        # Sanity check: length should be reasonable
        if 0 < length <= len(trailer) - offset - 4 and length < 100000:
            # Look for type indicator (often 2 bytes after length)
            if offset + 4 + 2 <= len(trailer):
                type_bytes = trailer[offset+4:offset+6]
                type_val = struct.unpack('>H', type_bytes)[0]
                type_val_le = struct.unpack('<H', type_bytes)[0]
                
                data_start = offset + 4  # Assuming no type, just length+data
                # Or maybe: data_start = offset + 6 with 2-byte type
                
                data_bytes = trailer[data_start:data_start+min(length, 64)]
                ascii_preview = ''.join(chr(b) if 32<=b<127 else '.' for b in data_bytes[:32])
                
                print(f"  Field {field_num} @ offset {offset:04x}: len={length} (0x{length:04x})")
                print(f"    Raw start: {trailer[offset:offset+16].hex()}")
                if length <= 64:
                    print(f"    Data: {data_bytes.hex()}")
                    if any(32 <= b < 127 for b in data_bytes):
                        print(f"    ASCII: '{ascii_preview}'")
                else:
                    print(f"    Data first 64 bytes: {data_bytes.hex()}")
                
                offset += 4 + length
                continue
        
        # Try 2-byte BE length
        if offset + 2 <= len(trailer):
            length2 = struct.unpack('>H', trailer[offset:offset+2])[0]
            if 0 < length2 <= len(trailer) - offset - 2 and length2 < 100000:
                data_bytes = trailer[offset+2:offset+2+min(length2, 64)]
                print(f"  Field {field_num} @ offset {offset:04x}: 2-byte-BE-len={length2}")
                print(f"    Data: {data_bytes[:32].hex()}")
                offset += 2 + length2
                continue
        
        # Unknown, skip a byte
        offset += 1

def parse_pkt16_structure(trailer):
    """Parse the large packet 16 trailer structure"""
    print(f"\n--- Packet 16 Trailer Deep Parse ({len(trailer)} bytes) ---")
    
    # First 4 bytes look like length=208
    first_len = struct.unpack('<I', trailer[:4])[0]
    print(f"First 4 bytes (LE length): {first_len}")
    
    if first_len <= len(trailer) - 4:
        block1 = trailer[4:4+first_len]
        print(f"\nBlock 1 ({first_len} bytes, offset 4):")
        hexdump(block1[:64])
        
        # Look inside block1 for structure
        print(f"\n  Block 1 entropy: {entropy(block1):.2f}")
        
        # Check for TLV inside block1
        offset = 0
        while offset < len(block1) - 4:
            lv = struct.unpack('<I', block1[offset:offset+4])[0]
            if 0 < lv < len(block1) - offset - 4 and lv < 10000:
                data = block1[offset+4:offset+4+min(lv, 48)]
                ascii_p = ''.join(chr(b) if 32<=b<127 else '.' for b in data[:32])
                print(f"    Sub-field @ {offset:04x}: len={lv}")
                print(f"      Hex: {data[:16].hex()}")
                if any(32 <= b < 127 for b in data[:lv]):
                    print(f"      ASCII: '{ascii_p}'")
                offset += 4 + lv
            else:
                # Try 1-byte length
                lv1 = block1[offset]
                if 0 < lv1 < len(block1) - offset - 1 and lv1 < 200:
                    data = block1[offset+1:offset+1+lv1]
                    ascii_p = ''.join(chr(b) if 32<=b<127 else '.' for b in data)
                    print(f"    Byte-field @ {offset:04x}: len={lv1}")
                    if any(32 <= b < 127 for b in data):
                        print(f"      ASCII: '{ascii_p}'")
                    offset += 1 + lv1
                else:
                    offset += 1
        
        # Check remaining data after block1
        remaining = trailer[4+first_len:]
        if remaining:
            print(f"\nRemaining after block 1 ({len(remaining)} bytes):")
            hexdump(remaining[:64])
            
            # Check if remaining starts with another length
            if len(remaining) >= 4:
                next_len = struct.unpack('<I', remaining[:4])[0]
                print(f"  Next length field: {next_len}")

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
    
    payloads = {}
    for i, pkt in enumerate(packets):
        result = extract_tcp_payload(pkt, link_type)
        if result is None: continue
        sport, dport, payload = result
        if sport == 17500 or dport == 17500:
            payloads[i] = payload
    
    # Parse auth trailers
    if 3 in payloads:
        hdr = parse_anogs_header(payloads[3])
        trailer = payloads[3][16+hdr['body_len']:]
        parse_tlv_trailer(trailer, "Auth3 (0x1001)")
    
    if 5 in payloads:
        hdr = parse_anogs_header(payloads[5])
        trailer = payloads[5][16+hdr['body_len']:]
        parse_tlv_trailer(trailer, "Auth5 (0x1002)")
    
    # Parse packet 16
    if 16 in payloads:
        hdr = parse_anogs_header(payloads[16])
        trailer = payloads[16][16+hdr['body_len']:]
        parse_pkt16_structure(trailer)
    
    # Parse packet 18
    if 18 in payloads:
        hdr = parse_anogs_header(payloads[18])
        trailer = payloads[18][16+hdr['body_len']:]
        print(f"\n--- Packet 18 Trailer ({len(trailer)} bytes) ---")
        hexdump(trailer[:64])
        
        # Look for length fields
        for i in range(0, 64, 1):
            if i+4 <= len(trailer):
                lv = struct.unpack('<I', trailer[i:i+4])[0]
                if 0 < lv < 5000:
                    print(f"  Potential len @ {i:04x}: {lv}")

if __name__ == "__main__":
    main()
