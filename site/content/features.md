---
title: Features
description: Feature matrix for pqtransport 0.1.0 — done, partial, fail-closed, not started.
---

Status: **Done** (tested), **Partial**, **Fail-closed**, **Not started**.

## Hybrid key exchange

| Feature | Status |
| --- | --- |
| X25519MLKEM768 share encode/decode/combine | Done |
| SecP256r1MLKEM768 share encode/decode/combine | Done |
| SecP384r1MLKEM1024 share encode/decode/combine | Done |
| Length filter before crypto | Done |
| All-zero classical shared secret rejected | Done |
| Live X25519MLKEM768 KEX | Done |
| Live P-256 / P-384 ECDH | Fail-closed |

## TLS 1.3

| Feature | Status |
| --- | --- |
| Client / server state machines | Done |
| Compact ClientHello / ServerHello | Done |
| AES-256-GCM records, epoch sequences | Done |
| TLS exporter | Done |
| HKDF-SHA-256 schedule | Done |
| HelloRetryRequest on the wire | Partial |
| SNI, ALPN, key_share extensions | Not started |
| X.509 / certificate chains | Not started |
| ChaCha20-Poly1305 records | Not started |
| OpenSSL interop | Not started |

## UDP / DNS / mDNS / QUIC / HTTP

| Feature | Status |
| --- | --- |
| Datagram AEAD + replay-before-open | Done |
| Encrypted UDP session (X25519MLKEM768) | Done |
| DNS RR round-trip including PTR/NS | Done |
| CircuitBreaker + TTL cache | Done |
| mDNS probe/announce/browse + signed TXT | Done |
| HTTP/1.1 GET over `PqTlsSocket` | Done |
| QUIC 1-RTT protect + CRYPTO/STREAM | Partial |
| HTTP/2 | Not started |
| HTTP/3 QPACK | Not started |
| IoDatagramChannel multicast join | Not started |

## Claims we do not feature

- FIPS 140 / CMVP validation.
- Hard constant-time execution.
- Hard memory erasure (zeroize is best-effort).
- "Production-ready post-quantum TLS" in the OpenSSL sense.
