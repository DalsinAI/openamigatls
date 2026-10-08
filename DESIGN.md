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
