---
title: Sister packages
description: pqtransport is a product of Yardenah PQ, on top of pqforge and swissarmyknife.
---

[Yardenah PQ](https://yardenah.com) is the lab. pqtransport is one
product of that lab. Cryptography stays in pqforge. This package does
not take a direct `pqcrypto` dependency.

| Package | Site | Role |
| --- | --- | --- |
| [pqcrypto](https://turkananation.github.io/pqcrypto/) | primitives | FIPS 203/204/205 and the KAT corpus. Zero runtime deps. |
| [pqforge](https://turkananation.github.io/pqforge/) | recipes | ML-KEM, ML-DSA, SLH-DSA, Ed25519, Ed448, RSA, X25519, P-256, P-384, P-521, AES-GCM, ChaCha, HKDF, HPKE, X.509. |
| [swissarmyknife](https://turkananation.github.io/swissarmyknife/) | utilities | Result, StateMachine, Cache, CircuitBreaker, Throttler. |
| **pqtransport** | this site | TLS, UDP, DNSSEC, DoH, DoT, mDNS, QUIC, HTTP/1.1–3. |

- Need a signature or a KEM? **pqforge**.
- Need `Result`, a state machine, or a cache? **swissarmyknife**.
- Need a handshake, a DNSSEC check, or an HTTP client over that crypto? **pqtransport**.