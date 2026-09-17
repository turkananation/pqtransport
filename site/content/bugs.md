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
| OPEN-02 | P1 | AES-256-GCM with SHA-256 schedule — not IANA 0x1302 |
| OPEN-05 | P2 | HelloRetryRequest is a counter, not a wire HRR |
| OPEN-06 | P2 | QUIC has no header protection / ACK / RFC 9001 |
| OPEN-07 | P2 | HTTP/2 missing; HTTP/3 is frames without QPACK |
| OPEN-08 | P2 | DNS rdata compression into the outer message is not resolved |
| OPEN-09 | P2 | `IoDatagramChannel` does not join mDNS multicast |
| OPEN-10 | P2 | DoH/DoT are thin adapters |
| OPEN-12 | P3 | leftover DNS/UDP/TLS error paths |
| OPEN-13 | P2 | ChaCha records / IANA 0x1303 not wired (export exists) |

## Blocked on pqforge

None. pqforge **0.4.4** shipped BLK-01 … BLK-05. Remaining crypto work is
**this package**: OPEN-02 (SHA-384 schedule) and OPEN-13 (ChaCha records).

## Honest limits (won't fix in 0.1)

LIM-01 OpenSSL handshake (needs OPEN-01 hellos; NIST live KEX is no
longer the blocker). LIM-02 CMVP / FIPS 140. LIM-03 hard constant-time /
hard erasure. LIM-04 browser raw UDP / mDNS. LIM-05 QUIC 0-RTT.

## Fixed in 0.1.0

Replay-before-AEAD, epoch record sequences, `MemoryByteSocket` buffering,
multicast flood, NS codec, combiner-order tests, SDK pin `>=3.12.0`,
handshake `late` application secrets. OPEN-03 (`requireGroup`), BLK-01
(live NIST ECDH), BLK-02 (SHA-256 HKDF helpers), BLK-04
(`concatenateSharedSecrets`), BLK-05 (`checkEncapsulationKey`), OPEN-01
(RFC 8446 hellos), OPEN-04 (RFC 7250 RawPublicKey), OPEN-11 (unused UDP
`role` args removed). Twelve FIX-* rows plus those in the canonical file.
