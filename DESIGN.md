# OpenTLS and OpenCrypto design

Version 0.1 — 8 October 2026

## 1. Decision

OpenTLS replaces AmiSSL/OpenSSL as the production TLS dependency of the Open
Amiga applications. OpenCrypto is part of the same programme and repository,
but remains a separate public library so non-TLS software can use cryptography
without pulling in the TLS protocol engine.

## 2. Layers

```text
application
   |
opentls.library
   |
opencrypto.library
   |
68040 reference / AC090 host leaves / OpenService / OpenGPU batches
```

The caller asks for cryptographic work. It never selects an accelerator.

## 3. OpenCrypto 1.0 scope

- SHA-1, SHA-256, SHA-384, SHA-512
- HMAC
- HKDF
- secure RNG
- constant-time compare and cleanse
- AES-GCM
- ChaCha20-Poly1305
- X25519
- P-256/P-384 ECDH and ECDSA
- Ed25519
- RSA signature verification

The first implementation slice lands SHA-256/HMAC/HKDF and utility primitives.

## 4. OpenTLS scope

- TLS 1.2 and 1.3 client
- SNI and ALPN
- certificate chain and hostname validation
- session cache and tickets
- trust store integration
- clean socket abstraction suitable for bsdsocket.library
- curl backend for OpenBrowser

## 5. Acceleration policy

Latency-sensitive one-off ECC/RSA work normally runs on the fastest trusted CPU
provider. OpenGPU is reserved for demonstrably profitable batches such as bulk
hash/AEAD work or many independent operations.

Secret-bearing operations may only use providers inside the same trusted
machine or a deliberately paired OpenService endpoint.

## 6. Migration

The existing OpenSSL 3 provider and `opentls.key/1` service are retained as
qualification tools. OpenBrowser first gains an OpenTLS backend alongside
AmiSSL. The old path is removed only after real-site regression and protocol
test coverage pass.

## 7. Version 2: what SSH needs (8 October 2026)

OpenPuTTY is the first user. `opencrypto.library` 2.0 adds X25519,
sntrup761, Ed25519, ECDSA (P-256, P-384, P-521) and RSA verification, the
SHA-256 and SHA-512 block functions, AES (CTR, CBC, ECB), ChaCha20 and
Poly1305 (`include/libraries/opencrypto.h`: one request structure per call,
in A0, as version 1's calls).

- **Who does the work.** Each heavy operation is a magic function
  (`library/oc_magic.h`): a 12-byte tag in front of a stack-convention
  function, with the ids `$00010200` to `$0001020c` in amigachrome-guest's
  `ac_magic.h`. On AmigaChrome AC090 runs it as host code
  (amigachrome's `jit_crypto.c`), compiled from this repository's
  `src/` (copied there by its `opencrypto/sync.sh`); everywhere else the
  library runs the same C as 68k code. `OC_Accelerated()` (the probe,
  `$00010200`) says which operations are host code on this machine.
  This puts the 68040 reference and the AC090 leaves of section 2 in
  place; OpenGPU batches and OpenService stay for later.
- **Same bytes either way.** Each magic function writes one range (its
  first argument) and nothing else, and the host compiles the very same C,
  so AC090's `AC090_MAGIC=verify` can run both and compare. Randomness is
  not drawn inside the library: key generation and encapsulation take a
  32-byte seed from the caller (expanded with ChaCha20), so a call is a
  pure function of its inputs.
- **Constant time** where a secret is involved: X25519 (a Montgomery
  ladder with conditional swaps), sntrup761 (the reference algorithms'
  division steps, a sorting network, masks), AES (every S-box lookup reads
  the whole table; the host uses AES-NI or the ARMv8 AES instructions),
  ChaCha20 and Poly1305. Verification (Ed25519, ECDSA, RSA) handles public
  values only and is written for clarity.
- **Stack.** sntrup761 builds its polynomials on the caller's stack (about
  24 KB), so several tasks can call at once; the library refuses
  (`OCERR_STACK`) when the calling task has less than 32 KB free.

## 8. Tests and measurements (8 October 2026)

- On the PC (`ctest`): the published vectors (`tests/test_ssh_primitives.c`:
  RFC 7748 including 1,000 iterations, RFC 8032 tests 1 to 3 and altered
  copies, RFC 8439 ChaCha20 and Poly1305, FIPS 197 for each key size, FIPS
  180 through the block functions, RFC 6979 A.2.5 for P-256, an RSA-2048
  public operation, sntrup761 round trips, implicit rejection and
  OpenCrypto's own known answer), and random inputs against Python's
  cryptography package (`tests/differential.py`: 200 rounds of each
  symmetric operation and 30 of RSA 2048/3072/4096 and ECDSA on each
  curve, good and altered): no failures.
- sntrup761 against PuTTY 0.85's own (`tests/interop_putty.sh`), each
  side's key pair with the other side's encapsulation: 100 rounds each way,
  no failures. In the lab, OpenPuTTY with OpenCrypto completes the
  sntrup761x25519-sha512 key exchange with PuTTY's test server.
- On the Amiga (a scratch copy of AmigaChrome's Instance-11, AC090 68040):
  `OpenCryptoVectors` passes all 42 checks as 68k code, with the same
  sntrup761 known answer as the PC; `OpenCryptoBench` checks each library
  call. 68k code on the AC090 JIT: X25519 21 ms, Ed25519 verification
  69 ms, sntrup761 key pair 1.04 s, encapsulation 0.16 s, decapsulation
  0.35 s, AES-256-CTR 250 ms for 16 KB (the constant-time S-box is slow as
  68k code). As host code each of these is well under a millisecond of the
  Amiga's time.
- **The stove's GCC 16 miscompiles one loop shape.** At -O2,
  m68k-amigaos-gcc 16.2.0b turns `for (i = n; i > 0; --i) v[i] = v[i-1];`
  into an inline forward copy, which smears the array. sntrup761's
  polynomial shifts were such loops and gave wrong keys on the 68k (the
  same object gave the same wrong bytes in qemu-m68k and in AC090's
  interpreter, so the emulator was not at fault). The shifts are now
  `memmove` calls, and the Amiga build passes
  `-fno-tree-loop-distribute-patterns` throughout.
