#!/usr/bin/env python3
"""OpenCrypto against Python's cryptography package (OpenSSL underneath) on
random inputs: X25519, Ed25519 (good and altered signatures), ChaCha20,
Poly1305, AES (CTR, CBC, ECB; 128, 192, 256), RSA's public operation
(2048, 3072, 4096 bits), ECDSA (P-256, P-384, P-521; good and altered),
SHA-256, SHA-512, and sntrup761 round trips.
  python3 tests/differential.py OC_CLI [ROUNDS]
Copyright (c) 2026 Dalsin Limited. MIT."""
import hashlib, os, random, subprocess, sys
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa, x25519, utils
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.poly1305 import Poly1305
from cryptography.hazmat.primitives import serialization

cli = subprocess.Popen([sys.argv[1]], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
rounds = int(sys.argv[2]) if len(sys.argv) > 2 else 200
H = lambda b: b.hex() if b else "-"
fails, counts = 0, {}

def ask(*words):
    cli.stdin.write(" ".join(words) + "\n")
    cli.stdin.flush()
    return cli.stdout.readline().strip()

def check(name, ok, detail=""):
    global fails
    counts[name] = counts.get(name, 0) + 1
    if not ok:
        fails += 1
        print("FAIL", name, detail)

raw = serialization.Encoding.Raw, serialization.PublicFormat.Raw
for i in range(rounds):
    # X25519
    k, u = os.urandom(32), x25519.X25519PrivateKey.generate().public_key().public_bytes(*raw)
    want = x25519.X25519PrivateKey.from_private_bytes(k).exchange(x25519.X25519PublicKey.from_public_bytes(u))
    check("X25519", ask("x25519", H(k), H(u)) == want.hex())
    # Ed25519
    sk = ed25519.Ed25519PrivateKey.generate()
    msg = os.urandom(random.randrange(0, 300))
    sig = sk.sign(msg)
    pk = sk.public_key().public_bytes(*raw)
    check("Ed25519 good", ask("ed25519", H(sig), H(pk), H(msg)) == "1")
    bad = bytearray(sig); bad[random.randrange(64)] ^= 1 << random.randrange(8)
    check("Ed25519 altered", ask("ed25519", H(bytes(bad)), H(pk), H(msg)) == "0")
    # ChaCha20 (Python's 16-byte nonce is the 64-bit counter, little-endian, then the 64-bit nonce)
    key, nonce, ctr = os.urandom(32), os.urandom(8), random.randrange(0, 2**40)
    data = os.urandom(random.randrange(0, 500))
    enc = Cipher(algorithms.ChaCha20(key, ctr.to_bytes(8, "little") + nonce), None).encryptor().update(data)
    check("ChaCha20", ask("chacha", H(key), H(nonce), "%x" % ctr, H(data)) == (enc.hex() or "-"))
    # Poly1305
    pkey = os.urandom(32)
    check("Poly1305", ask("poly", H(pkey), H(data)) == Poly1305.generate_tag(pkey, data).hex())
    # AES
    for kl in (16, 24, 32):
        key, iv = os.urandom(kl), os.urandom(16)
        blocks = os.urandom(16 * random.randrange(1, 12))
        odd = os.urandom(random.randrange(1, 200))
        want = Cipher(algorithms.AES(key), modes.CTR(iv)).encryptor().update(odd)
        check("AES-CTR", ask("aes", "0", H(key), H(iv), H(odd)) == want.hex())
        want = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor().update(blocks)
        check("AES-CBC encrypt", ask("aes", "1", H(key), H(iv), H(blocks)) == want.hex())
        want = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor().update(blocks)
        check("AES-CBC decrypt", ask("aes", "2", H(key), H(iv), H(blocks)) == want.hex())
    # SHA-2
    data = os.urandom(random.randrange(0, 1000))
    check("SHA-256", ask("sha256", H(data)) == hashlib.sha256(data).hexdigest())
    check("SHA-512", ask("sha512", H(data)) == hashlib.sha512(data).hexdigest())

# slower ones, fewer rounds
for i in range(max(4, rounds // 20)):
    for bits in (2048, 3072, 4096):
        k = rsa.generate_private_key(public_exponent=65537, key_size=bits)
        n = k.public_key().public_numbers().n
        s = random.randrange(2, n)
        nb = n.to_bytes(bits // 8, "big")
        check("RSA public", ask("rsa", H(nb), "010001", H(s.to_bytes(bits // 8, "big"))) == pow(s, 65537, n).to_bytes(bits // 8, "big").hex())
    for curve, bits, h in ((ec.SECP256R1(), 256, hashes.SHA256()), (ec.SECP384R1(), 384, hashes.SHA384()), (ec.SECP521R1(), 521, hashes.SHA512())):
        k = ec.generate_private_key(curve)
        msg = os.urandom(50)
        r, s = utils.decode_dss_signature(k.sign(msg, ec.ECDSA(h)))
        pn = k.public_key().public_numbers()
        L = (bits + 7) // 8
        dig = hashlib.new(h.name, msg).digest()
        args = ["ecdsa", str(bits)] + [x.to_bytes(L, "big").hex() for x in (pn.x, pn.y, r, s)]
        check("ECDSA good", ask(*args, dig.hex()) == "1")
        bad = bytearray(dig); bad[3] ^= 0x10
        check("ECDSA altered", ask(*args, bytes(bad).hex()) == "0")
    check("sntrup761 round trip", ask("kem", H(os.urandom(32)), H(os.urandom(32))) == "1")

print("differential against Python cryptography %s: %s; %d failures" % (
    __import__("cryptography").__version__, ", ".join("%s %d" % kv for kv in counts.items()), fails))
sys.exit(1 if fails else 0)
