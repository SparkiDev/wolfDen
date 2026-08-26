# An independent transcription of hostapd's aes_kdf (src/pae/ieee802_1x_key.c,
# "IEEE Std 802.1X-2010, 6.2.1 KDF"). Nothing here is derived from wolfMKA.
from cryptography.hazmat.primitives import cmac
from cryptography.hazmat.primitives.ciphers import algorithms

def aes_cmac(key, msg):
    c = cmac.CMAC(algorithms.AES(key)); c.update(bytes(msg)); return c.finalize()

def aes_kdf(kdk, label, context, ret_bits):
    kdk_bits = len(kdk) * 8
    assert kdk_bits in (128, 256), f"kdk_bits={kdk_bits} rejected by aes_kdf"
    h = 128
    lab = label.encode()
    lab_len, ctx_len = len(lab), len(context)
    ret_len = ((ret_bits & 0xffff) + 7) // 8
    buf_len = lab_len + ctx_len + 4
    n = (ret_bits + h - 1) // h
    assert n <= 255
    buf = bytearray(buf_len)
    buf[1:1 + lab_len] = lab
    buf[lab_len + 2: lab_len + 2 + ctx_len] = context
    buf[buf_len - 2:] = ret_bits.to_bytes(2, "big")
    out = b""
    for i in range(n):
        buf[0] = i + 1
        out += aes_cmac(kdk, buf)
    return out[:ret_len]

def joint(mac1, mac2):
    return mac1 + mac2 if mac1 < mac2 else mac2 + mac1

def cak(msk, mac1, mac2, cak_bytes):
    return aes_kdf(msk, "IEEE8021 EAP CAK", joint(mac1, mac2), 8 * cak_bytes)

def ckn(msk, sid, mac1, mac2):
    return aes_kdf(msk, "IEEE8021 EAP CKN", sid + joint(mac1, mac2), 128)

msk  = bytes(range(32))
mac1 = bytes.fromhex("020000000001")
mac2 = bytes.fromhex("020000000002")
sid  = bytes.fromhex("11223344")

# Validate the oracle against the three vectors already pinned in test_crypto.c.
known = [
    ("CAK-128 (msk 16)", cak(msk[:16], mac1, mac2, 16),
     "f7c54b9b518839f4453a7415c65d4be3"),
    ("CAK-256 (msk 32)", cak(msk, mac1, mac2, 32),
     "00a576209229b866b3d59d1e54ad8b9b5ace0c503dc214c391fc2c9b46d3657c"),
    ("CKN     (msk 16)", ckn(msk[:16], sid, mac1, mac2),
     "9c97b8ea80a9a9110cca65f4560bff96"),
]
ok = True
for name, got, exp in known:
    m = got.hex() == exp
    ok &= m
    print(f"  {name}: {got.hex()}  {'MATCH' if m else 'MISMATCH exp ' + exp}")
print("oracle validated" if ok else "ORACLE DISAGREES - do not trust it")
print()
print("  CKN     (msk 32): " + ckn(msk, sid, mac1, mac2).hex() + "   <- unpinned")
