#!/usr/bin/env python3
"""
Thử giải mã payload 0x4013 với các key thu được từ auth và key exchange
"""
import struct
import hashlib
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

def decrypt_aes(data, key, iv=None, mode='ecb'):
    try:
        if mode == 'ecb':
            cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
        elif mode == 'cbc':
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        else:
            return None
        decryptor = cipher.decryptor()
        return decryptor.update(data) + decryptor.finalize()
    except Exception as e:
        return None

def printable_ratio(data):
    if not data: return 0
    return sum(1 for b in data if 32 <= b < 127 or b in (0, 10, 13)) / len(data)

def find_strings(data, min_len=4):
    strings = []
    current = b""
    for b in data:
        if 32 <= b < 127:
            current += bytes([b])
        else:
            if len(current) >= min_len:
                strings.append(current.decode('latin1'))
            current = b""
    if len(current) >= min_len:
        strings.append(current.decode('latin1'))
    return strings

def main():
    packets, link_type = read_pcap("/tmp/anti_cheat_17500.pcap")

    # Extract keys from auth and key exchange
    auth_key = None
    keyex_c = None
    keyex_s = None
    token = None
    pkt_4013 = None

    for pkt in packets:
        result = extract_tcp_payload(pkt, link_type)
        if result is None: continue
        sport, dport, payload = result
        if len(payload) < 16: continue

        hdr = parse_anogs_header(payload)
        if not hdr: continue

        body = payload[16:16+hdr['body_len']]
        trailer = payload[16+hdr['body_len']:]

        if hdr['opcode'] == 0x1002 and sport < dport:  # S->C
            # Token at offset 6 in trailer
            token = trailer[6:22].rstrip(b'\x00')
            # 16 bytes at end
            auth_key = trailer[-16:]
            print(f"[AUTH] Token: {token}")
            print(f"[AUTH] Potential key (last 16 bytes): {auth_key.hex()}")

        elif hdr['opcode'] == 0x2001 and sport > dport:  # C->S
            keyex_c = trailer
            print(f"[KEYEX C->S] Trailer {len(trailer)} bytes: {trailer[:32].hex()}...")

        elif hdr['opcode'] == 0x2002 and sport < dport:  # S->C
            keyex_s = trailer
            print(f"[KEYEX S->C] Trailer {len(trailer)} bytes: {trailer[:32].hex()}...")

        elif hdr['opcode'] == 0x4013 and sport > dport and len(payload) > 2000:
            if pkt_4013 is None:
                pkt_4013 = payload

    if not pkt_4013:
        print("ERROR: No 0x4013 packet found")
        return

    hdr = parse_anogs_header(pkt_4013)
    body = pkt_4013[16:16+hdr['body_len']]
    trailer = pkt_4013[16+hdr['body_len']:]

    print(f"\n[0x4013] Trailer size: {len(trailer)}")
    print(f"[0x4013] First 16 bytes: {trailer[:16].hex()}")

    # Hypothesis: first 5 bytes are header, rest is encrypted
    # Actually, first 4 bytes = LE length (208), then 1 byte = 0x00
    # Encrypted data might start at offset 5
    encrypted_data = trailer[5:]
    # Pad to 16-byte boundary
    padding = 16 - (len(encrypted_data) % 16)
    if padding != 16:
        encrypted_data += b'\x00' * padding

    print(f"\n[CRYPTO TESTS] Testing {len(encrypted_data)} bytes (padded to 16-byte boundary)")

    keys_to_test = []

    # Key from auth response
    if auth_key:
        keys_to_test.append(("auth_key (last 16 bytes)", auth_key))
        # SHA256 of auth_key for AES-256
        keys_to_test.append(("SHA256(auth_key)", hashlib.sha256(auth_key).digest()))
        keys_to_test.append(("MD5(auth_key)", hashlib.md5(auth_key).digest()))

    # Key from token
    if token:
        keys_to_test.append(("token_raw", token.ljust(16, b'\x00')[:16]))
        keys_to_test.append(("SHA256(token)", hashlib.sha256(token).digest()))
        keys_to_test.append(("MD5(token)", hashlib.md5(token).digest()))

    # Keys from key exchange
    if keyex_c:
        keys_to_test.append(("keyex_c_first16", keyex_c[:16]))
        keys_to_test.append(("keyex_c_last16", keyex_c[-16:]))
        keys_to_test.append(("SHA256(keyex_c)", hashlib.sha256(keyex_c).digest()))
    if keyex_s:
        keys_to_test.append(("keyex_s_first16", keyex_s[:16]))
        keys_to_test.append(("keyex_s_last16", keyex_s[-16:]))
        keys_to_test.append(("SHA256(keyex_s)", hashlib.sha256(keyex_s).digest()))

    # Combined keys
    if auth_key and token:
        combined = hashlib.sha256(token + auth_key).digest()
        keys_to_test.append(("SHA256(token+auth_key)", combined))
        combined2 = hashlib.sha256(auth_key + token).digest()
        keys_to_test.append(("SHA256(auth_key+token)", combined2))

    iv_candidates = []
    iv_candidates.append(("zeros", b'\x00' * 16))
    if keyex_c:
        iv_candidates.append(("keyex_c_first16", keyex_c[:16]))
        iv_candidates.append(("keyex_c_last16", keyex_c[-16:]))
    if keyex_s:
        iv_candidates.append(("keyex_s_first16", keyex_s[:16]))
        iv_candidates.append(("keyex_s_last16", keyex_s[-16:]))

    # Test AES-128-ECB
    print("\n--- AES-128-ECB ---")
    for name, key in keys_to_test:
        if len(key) < 16: continue
        key_16 = key[:16]
        plain = decrypt_aes(encrypted_data, key_16, mode='ecb')
        if plain:
            ratio = printable_ratio(plain)
            strings = find_strings(plain[:256])
            if ratio > 0.3 or strings:
                print(f"  {name}: {ratio:.2%} printable")
                for s in strings[:10]:
                    print(f"    String: '{s}'")

    # Test AES-128-CBC
    print("\n--- AES-128-CBC ---")
    for kname, key in keys_to_test:
        if len(key) < 16: continue
        key_16 = key[:16]
        for iname, iv in iv_candidates:
            plain = decrypt_aes(encrypted_data, key_16, iv, mode='cbc')
            if plain:
                ratio = printable_ratio(plain)
                strings = find_strings(plain[:256])
                if ratio > 0.3 or strings:
                    print(f"  key={kname} iv={iname}: {ratio:.2%} printable")
                    for s in strings[:10]:
                        print(f"    String: '{s}'")

    # Test AES-256 variants
    print("\n--- AES-256-ECB ---")
    for name, key in keys_to_test:
        if len(key) < 32: continue
        key_32 = key[:32]
        plain = decrypt_aes(encrypted_data, key_32, mode='ecb')
        if plain:
            ratio = printable_ratio(plain)
            strings = find_strings(plain[:256])
            if ratio > 0.3 or strings:
                print(f"  {name}: {ratio:.2%} printable")
                for s in strings[:10]:
                    print(f"    String: '{s}'")

    print("\n--- AES-256-CBC ---")
    for kname, key in keys_to_test:
        if len(key) < 32: continue
        key_32 = key[:32]
        for iname, iv in iv_candidates:
            plain = decrypt_aes(encrypted_data, key_32, iv, mode='cbc')
            if plain:
                ratio = printable_ratio(plain)
                strings = find_strings(plain[:256])
                if ratio > 0.3 or strings:
                    print(f"  key={kname} iv={iname}: {ratio:.2%} printable")
                    for s in strings[:10]:
                        print(f"    String: '{s}'")

    # Also try with data starting at different offsets
    print("\n--- Testing different start offsets (AES-128-CBC with auth_key) ---")
    for start in range(0, 16):
        data = trailer[start:]
        padding = 16 - (len(data) % 16)
        if padding != 16:
            data += b'\x00' * padding
        for iname, iv in iv_candidates:
            plain = decrypt_aes(data, auth_key[:16], iv, mode='cbc')
            if plain:
                ratio = printable_ratio(plain)
                strings = find_strings(plain[:256])
                if ratio > 0.3 or strings:
                    print(f"  offset={start} iv={iname}: {ratio:.2%} printable")
                    for s in strings[:10]:
                        print(f"    String: '{s}'")

if __name__ == "__main__":
    main()
