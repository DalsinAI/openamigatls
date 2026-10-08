# OpenTLS

OpenTLS is the native TLS and cryptography stack for the Open Amiga platform.

The repository contains two public Amiga-facing layers:

- **OpenCrypto** — hashes, MAC/KDF, RNG, AEAD and public-key primitives.
- **OpenTLS** — TLS 1.2/1.3, certificate validation, sessions and trust policy.

Applications use these APIs directly. AmiSSL/OpenSSL become reference and
compatibility technology during qualification rather than production
dependencies of OpenBrowser.

Current slice (8 October 2026): `opencrypto.library` 2.0, with what SSH
needs, for OpenPuTTY first:

| What | Notes |
| --- | --- |
| SHA-256, SHA-384, SHA-512, HMAC, HKDF | version 1; version 2 adds the block functions (`OC_SHA256Blocks`, `OC_SHA512Blocks`) |
| X25519 | RFC 7748, constant time |
| sntrup761 | NTRU Prime as SSH's `sntrup761x25519-sha512` uses it, constant time; keys from a 32-byte seed |
| Ed25519 verification | RFC 8032 |
| ECDSA verification | P-256, P-384, P-521 |
| RSA public operation | up to 8192 bits, for PKCS #1 signatures |
| AES-128/192/256 | CTR (SSH's SDCTR), CBC, ECB; constant time |
| ChaCha20, Poly1305 | the 64-bit nonce form SSH's `chacha20-poly1305@openssh.com` uses |

On AmigaChrome the host does the heavy work: each operation is an AC090
magic function (`library/oc_magic.h`), which AC090 runs as host code from
the same C (amigachrome's `jit_crypto.c`); everywhere else the library
runs it as 68k code. `OC_Accelerated()` says which operations are host code. In an
AmigaChrome lab (scratch copy of Instance-11, AC090 68040, 8 October 2026)
OpenPuTTY's NTRU Prime / Curve25519 key exchange went from 11 s with
PuTTY's own code on the old JIT to about 60 ms with OpenCrypto as host
code; DESIGN.md section 8 has the 68k figures and the tests.

## Building and testing

    cmake -S . -B build && cmake --build build && ctest --test-dir build
        the portable core on the PC: the published vectors
        (tests/test_ssh_primitives.c) and, with Python's cryptography
        package, random inputs against OpenSSL (tests/differential.py)
    tests/interop_putty.sh
        sntrup761 against PuTTY 0.85's own, both ways (PuTTY is fetched
        as its release tarball and checked against its SHA-256)
    ./build-amiga.sh
        opencrypto.library and the Amiga tests (OpenCryptoLibTest,
        OpenCryptoVectors: the same vectors on the 68k; OpenCryptoBench:
        each call checked and timed), with the os32 GCC 16 stove

## Architecture

```text
OpenBrowser / curl OpenTLS backend / native applications
                         |
                    opentls.library
                         |
                  opencrypto.library
              /          |           \
           68040       AC090       host/OpenGPU
```

OpenGPU is optional and only used where batching makes it faster. TLS semantics
never live in OpenGPU.

## Correctness rule

Crypto is stricter than graphics: no accelerated implementation is enabled
until it passes standard vectors and differential tests against a trusted
reference implementation.

The existing `opentls.key/1` service in DalsinAI/openamigaservice remains the
bridge-era reference for slow public-key work while this native stack grows.
