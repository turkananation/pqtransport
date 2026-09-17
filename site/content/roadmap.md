---
title: Roadmap
description: 0.2 through 0.5 for pqtransport. Order is not optional.
---

0.1.0 is the self-interop vertical slice. Order after that is not
optional: inverting a slice produces fake HTTP clients on unimplemented
QUIC, DoT without TLS, or OpenSSL claims on a compact private encoding.

Canonical:
[`doc/ROADMAP.md`](https://github.com/turkananation/pqtransport/blob/main/doc/ROADMAP.md).

## Non-goals that stay non-goals

CMVP / FIPS 140. Hard constant-time / hard erasure. Browser raw UDP /
mDNS / QUIC sockets. QUIC 0-RTT. Classical-only fallback after a PQ
hello. Direct `pqcrypto` dependency. `dart:ffi` / `SecureSocket` on the
PQ path.

## 0.2 — RFC 8446-shaped wire

Real ClientHello / ServerHello (`legacy_version`, `cipher_suites`,
`supported_versions`, `supported_groups`, `key_share`, SNI, ALPN).
EncryptedExtensions as a real message. Certificate as X.509 or an
explicit raw-public-key extension. HelloRetryRequest on the wire with
cookie. Refuse `PqForgeProfile.maximum` with ML-KEM-768 groups.

Still SHA-256. Still do not put IANA `0x1302` on the wire. Unblocks
OpenSSL **parsing** without waiting on pqforge ECDH.

## 0.3 — live NIST groups + honest cipher suite

Blocked on pqforge exports: `p256SharedSecret` / `p384SharedSecret`,
`hkdfExpandSha256`, SHA-384 Extract/Expand, optional sync ChaCha,
optional `checkEncapsulationKey`. Exit gate: live handshake tests for
**all three** RFC 10024 groups; cipher suite bytes match the transcript
hash.

## 0.4 — OpenSSL 3.5+ / BoringSSL fixture

Recorded X25519MLKEM768 transcript against OpenSSL 3.5+ s_server /
s_client. Until that is green, wording stays "unit-tested
concatenation," not "interoperable with OpenSSL."

## 0.5 — DNSSEC / LAN mDNS / QUIC mapping

Only after the TLS wire is honest. Do not grow HTTP/3 QPACK on a QUIC
sketch that cannot carry TLS.
