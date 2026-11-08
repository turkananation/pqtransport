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
| X.509 / certificate chains | Done. Opt-in, chain of 1 to 8, caller anchors. Default offer stays raw public key. Not WebPKI. Not a browser |
| ChaCha20-Poly1305 records | Done (IANA `0x1303`; dart2js via pqforge 0.4.5) |
| ECH (RFC 9849) | Done. One BoringSSL 0.20261020.0 flight. DHKEM(X25519, HKDF-SHA256) + AES-128-GCM via `PqHpke` (pqforge 0.4.10). Inner name `localhost`. Not OpenSSL. Not GREASE. Not DNS |
| OpenSSL 3.5.9 RFC 10024 | Done. Three hybrid groups, raw-pk and X.509, both directions. Also X25519, secp256r1, secp384r1, and MLKEM1024. BoringSSL 0.20261020.0 is a TLS peer on those same groups except the two NIST hybrids. curl does two HTTP/1.1 GETs. Not a browser |

## UDP / DNS / mDNS / QUIC / HTTP

| Feature | Status |
| --- | --- |
| Datagram AEAD + replay-before-open | Done |
| Encrypted UDP session (X25519MLKEM768) | Done |
| Encrypted UDP session (P-256 / P-384) | Done |
| DNS RR round-trip including PTR/NS/DNSKEY/DS/RRSIG | Done |
| DNSSEC ECDSAP256SHA256 | Done. Algorithm 13 only, via `PqEcdsaP256.verify`. Canonical RDATA order. Zone bit required. 32-bit serial validity. SHA-256 DS. AD is not consulted. Not NSEC/NSEC3 |
| CircuitBreaker + TTL cache | Done |
| mDNS probe/announce/browse + signed TXT | Done |
| HTTP/1.1 GET over `PqTlsSocket` | Done |
| QUIC 1-RTT protect + CRYPTO/STREAM | Done |
| QUIC loss recovery (RFC 9002 NewReno) | Done |
| HTTP/2 | Done (ALPN `h2`, RFC 9113 + RFC 7541) |
| HTTP/3 QPACK | Done (ALPN `h3`, RFC 9114 + RFC 9204) |
| IoDatagramChannel multicast join | Done |

## Claims we do not feature

- FIPS 140 / CMVP validation.
- Hard constant-time execution.
- Hard memory erasure (zeroize is best-effort).
- "Production-ready post-quantum TLS" in the OpenSSL sense.
