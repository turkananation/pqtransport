---
title: Roadmap
description: 0.2 through 0.5 for pqtransport. Order is not optional.
---

0.1.0 is the self-interop vertical slice **plus live NIST groups**
(pqforge 0.4.4). Order after that is not optional: inverting a slice
produces fake HTTP clients on unimplemented QUIC, DoT without TLS, or
OpenSSL claims on a compact private encoding.

Canonical:
[`doc/ROADMAP.md`](https://github.com/turkananation/pqtransport/blob/main/doc/ROADMAP.md).

## Non-goals that stay non-goals

CMVP / FIPS 140. Hard constant-time / hard erasure. Browser raw UDP /
mDNS / QUIC sockets. QUIC 0-RTT. Classical-only fallback after a PQ
hello. Direct `pqcrypto` dependency. `dart:ffi` / `SecureSocket` on the
PQ path.

## 0.2 — RFC 8446-shaped wire

ClientHello / ServerHello are RFC 8446-shaped (OPEN-01 **done**). Cipher
on the wire is private-use `0xFF00`, not IANA `0x1302`. Remaining in 0.2:
EncryptedExtensions as a real message + Certificate as X.509 or explicit
raw-pk (OPEN-04); HelloRetryRequest on the wire with cookie (OPEN-05);
drop unused UDP `role` args (OPEN-11, parallel).

Still SHA-256. Still do not put IANA `0x1302` on the wire. OpenSSL
**parsing** of hellos is unblocked; handshake completion still needs
cert + an IANA suite.

## 0.3 remaining — honest cipher suite

Live NIST groups, HKDF-SHA-256 Expand, and `checkEncapsulationKey` are
**done** (pqforge 0.4.4). Remaining: SHA-384 schedule then IANA
`0x1302` (OPEN-02); wire sync ChaCha as `0x1303` (OPEN-13). Do not put
`0x1302` on a SHA-256 schedule.

## 0.4 — OpenSSL 3.5+ / BoringSSL fixture

Recorded X25519MLKEM768 transcript against OpenSSL 3.5+ s_server /
s_client. Requires OPEN-01 hellos. Until that is green, wording stays
"unit-tested concatenation," not "interoperable with OpenSSL."

## 0.5 — DNSSEC / LAN mDNS / QUIC mapping

Only after the TLS wire is honest. Do not grow HTTP/3 QPACK on a QUIC
sketch that cannot carry TLS.
