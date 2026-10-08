# OpenTLS

OpenTLS is the native TLS and cryptography stack for the Open Amiga platform.

The repository contains two public Amiga-facing layers:

- **OpenCrypto** — hashes, MAC/KDF, RNG, AEAD and public-key primitives.
- **OpenTLS** — TLS 1.2/1.3, certificate validation, sessions and trust policy.

Applications use these APIs directly. AmiSSL/OpenSSL become reference and
compatibility technology during qualification rather than production
dependencies of OpenBrowser.

Current slice: the portable OpenCrypto reference core for SHA-256,
HMAC-SHA256, HKDF-SHA256, constant-time comparison and secure cleansing.

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
