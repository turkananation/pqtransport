---
title: Bugs
description: Open, blocked, limited, and fixed defects in pqtransport 0.1.0.
---

Canonical tracker:
[`doc/BUGS.md`](https://github.com/turkananation/pqtransport/blob/main/doc/BUGS.md).

| Status | Meaning |
| --- | --- |
| Open | Reproduced or structurally true in 0.1.0 |
| Blocked | Fix lives in pqforge, not here |
| Fixed | Corrected in this tree |
| Won't fix in 0.1 | Honest limit, tracked on the roadmap |

## Open

| ID | Sev | Summary |
| --- | --- | --- |
| OPEN-01 | P1 | Compact private TLS encoding, not RFC 8446 hellos |
| OPEN-02 | P1 | AES-256-GCM with SHA-256 schedule — not IANA 0x1302 |
| OPEN-03 | P1 | `PqForgeProfile.maximum` with ML-KEM-768 groups is constructible |
| OPEN-04 | P1 | Certificate is a raw ML-DSA-65 key, not X.509 |
| OPEN-05 | P2 | HelloRetryRequest is a counter, not a wire HRR |
| OPEN-06 | P2 | QUIC has no header protection / ACK / RFC 9001 |
| OPEN-07 | P2 | HTTP/2 missing; HTTP/3 is frames without QPACK |
| OPEN-08 | P2 | DNS rdata compression into the outer message is not resolved |
| OPEN-09 | P2 | `IoDatagramChannel` does not join mDNS multicast |
| OPEN-10 | P2 | DoH/DoT are thin adapters |
| OPEN-11 | P3 | Unused UDP `role` named args |
| OPEN-12 | P3 | ~9.5% of `lib/` unhit |

## Blocked on pqforge

| ID | Summary |
| --- | --- |
| BLK-01 | No P-256 / P-384 ECDH |
| BLK-02 | No RFC 5869 Expand / SHA-384 HKDF |
| BLK-03 | No sync ChaCha20-Poly1305 primitive |
| BLK-04 | `PqForgeCombiner` is always classical then PQ |
| BLK-05 | No pre-encapsulate `checkEncapsulationKey` |

## Honest limits (won't fix in 0.1)

LIM-01 OpenSSL handshake. LIM-02 CMVP / FIPS 140. LIM-03 hard
constant-time / hard erasure. LIM-04 browser raw UDP / mDNS. LIM-05
QUIC 0-RTT.

## Fixed in 0.1.0

Replay-before-AEAD, epoch record sequences, `MemoryByteSocket` buffering,
multicast flood, NS codec, combiner-order tests, SDK pin `>=3.12.0`,
handshake `late` application secrets. Twelve FIX-* rows in the canonical
file.
