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
| Live SecP256r1MLKEM768 KEX | Done |
| Live SecP384r1MLKEM1024 KEX (`maximum`) | Done |
| Profile / group refuse (`requireGroup`) | Done |

## TLS 1.3

| Feature | Status |
| --- | --- |
| Client / server state machines | Done |
| Compact ClientHello / ServerHello | Done (RFC 8446-shaped; compact 0.1 retired) |
| AES-256-GCM records, epoch sequences | Done (IANA `0x1302`) |
| TLS exporter | Done |
| HKDF-SHA-384 schedule | Done (IANA `0x1302`, default) |
| HKDF-SHA-256 schedule | Done (ChaCha `0x1303` and UDP) |
| HelloRetryRequest on the wire | Done (cookie + selected_group, OPEN-05) |
| SNI, ALPN, key_share extensions | Done |
| X.509 / certificate chains | Not started (raw-pk negotiated, OPEN-04) |
| ChaCha20-Poly1305 records | Done (IANA `0x1303`; dart2js via pqforge 0.4.5) |
| OpenSSL interop | Not started |

## UDP / DNS / mDNS / QUIC / HTTP

| Feature | Status |
| --- | --- |
| Datagram AEAD + replay-before-open | Done |
| Encrypted UDP session (X25519MLKEM768) | Done |
| Encrypted UDP session (P-256 / P-384) | Done |
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
