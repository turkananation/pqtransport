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
| OPEN-06 | P2 | QUIC has no header protection / ACK / RFC 9001 |
| OPEN-07 | P2 | HTTP/2 missing; HTTP/3 is frames without QPACK |
| OPEN-10 | P2 | DoH/DoT are thin adapters |

## Blocked on pqforge

None. pqforge **0.4.4** shipped BLK-01 … BLK-05. OPEN-02 (SHA-384 schedule /
`0x1302`) and OPEN-13 (ChaCha records / `0x1303`) are **Fixed** in this tree.

## Honest limits (won't fix in 0.1)

LIM-01 OpenSSL handshake (hellos, raw-pk, HRR, and IANA `0x1302`/`0x1303`
are on the wire; still needs a recorded transcript). LIM-02 CMVP / FIPS
140. LIM-03 hard constant-time / hard erasure. LIM-04 browser raw UDP /
mDNS. LIM-05 QUIC 0-RTT.

## Fixed in 0.1.0

Replay-before-AEAD, epoch record sequences, `MemoryByteSocket` buffering,
multicast flood, NS codec, combiner-order tests, SDK pin `>=3.12.0`,
handshake `late` application secrets. OPEN-03 (`requireGroup`), BLK-01
(live NIST ECDH), BLK-02 (SHA-256 HKDF helpers), BLK-04
(`concatenateSharedSecrets`), BLK-05 (`checkEncapsulationKey`), OPEN-01
(RFC 8446 hellos), OPEN-04 (RFC 7250 RawPublicKey), OPEN-05 (wire HRR +
cookie), OPEN-11 (unused UDP `role` args removed), OPEN-02 (IANA `0x1302`
+ SHA-384 schedule), OPEN-13 (IANA `0x1303` + ChaCha records), OPEN-12
(leftover DNS/UDP/TLS error paths). Twelve FIX-* rows plus those in the
canonical file.
