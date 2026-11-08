---
title: Roadmap
description: What has landed on pqtransport main, and what is next. Order is not optional.
---

0.2.0 is the 0.1.0 slice plus what landed after it: X.509, the four
non-hybrid groups, BoringSSL, ECH, UDP loss recovery, and DNSSEC.
0.1.0 remains the self-interop vertical slice plus live NIST groups.

Canonical:
[`doc/ROADMAP.md`](https://github.com/turkananation/pqtransport/blob/main/doc/ROADMAP.md).

## Non-goals that stay non-goals

CMVP / FIPS 140. Hard constant-time / hard erasure. Browser raw UDP /
mDNS / QUIC sockets. QUIC 0-RTT (LIM-05). Classical-only fallback after
a PQ hello. Direct `pqcrypto` dependency. `dart:ffi` / `SecureSocket`
on the PQ path. ML-DSA DNSSEC. An authoritative DNS server.

## Landed

| Slice | What main does now |
| --- | --- |
| 0.2 | RFC 8446 hellos, raw public key, wire HRR, IANA `0x1302` / `0x1303` |
| 0.3 | Live KEX on all three RFC 10024 groups. SHA-384 schedule for `0x1302` |
| 0.4 | OpenSSL 3.5.9, raw-pk and X.509, both directions. BoringSSL 0.20261020.0 on X25519MLKEM768 and X25519, secp256r1, secp384r1, MLKEM1024. Not the two NIST hybrids on BoringSSL. curl is two HTTP/1.1 GETs |
| 0.5 | DoH, DoT, HTTP/2, HTTP/3+QPACK, QUIC loss recovery |
| 0.6 | Opt-in X.509 chain of 1 to 8. ECH, one BoringSSL flight, pqforge 0.4.10 HPKE. DNSSEC is algorithms 5, 7, 8, 10, 13, 14, 15, and 16. RSA moduli 1024 through 4096. Ed448 verifies. Iterative resolver, NSEC and NSEC3 |

## Next

OPEN-21: an optional SLH-DSA signature on mDNS TXT, one parameter set
pqforge already exports. The default announce path stays ML-DSA-65.
Do not start 0-RTT.
