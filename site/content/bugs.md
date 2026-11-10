---
title: Bugs
description: Open, blocked, limited, and fixed defects in pqtransport 0.2.0.
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

None. OPEN-19 (DNSSEC algorithms 5, 7, 8, 10, 13, 14, 15, and 16) is fixed.
Ed448 verifies. OPEN-21 (optional SLH-DSA-SHA2-128f on mDNS TXT) and
LIM-05 (QUIC 0-RTT) are implemented in this tree. The GitHub issues
stay open until the owner closes them.

## Blocked on pqforge

None. pqforge **0.4.13** is the floor (1024-bit RSA verify and SHA-1
PKCS#1 for DNSSEC algorithms 5 and 7, plus the 0.4.11 SHA-1 digest,
HPKE, X.509, and the earlier BLK-01 … BLK-05 exports). OPEN-02 and
OPEN-13 are **Fixed** in this tree.

## Honest limits (won't fix in 0.1)

LIM-01 was the raw-public-key OpenSSL row. OpenSSL 3.5.9 now completes
that row, and the X.509 row, in both directions. LIM-02 is CMVP / FIPS 140.
LIM-03 hard constant-time / hard erasure. LIM-04 browser raw UDP /
mDNS. 0-RTT is not a permanent limit: early data is sent, it shares
the Application Data packet number space with 1-RTT, and it is
replayable.


## Fixed in 0.1.0

Replay-before-AEAD, epoch record sequences, `MemoryByteSocket` buffering,
multicast flood, NS codec, combiner-order tests, SDK pin `>=3.12.0`,
handshake `late` application secrets. OPEN-03 (`requireGroup`), BLK-01
(live NIST ECDH), BLK-02 (SHA-256 HKDF helpers), BLK-04
(`concatenateSharedSecrets`), BLK-05 (`checkEncapsulationKey`), OPEN-01
(RFC 8446 hellos), OPEN-04 (RFC 7250 RawPublicKey), OPEN-05 (wire HRR +
cookie), OPEN-11 (unused UDP `role` args removed), OPEN-02 (IANA `0x1302`
+ SHA-384 schedule), OPEN-13 (IANA `0x1303` + ChaCha records), OPEN-12
(leftover DNS/UDP/TLS error paths), OPEN-06 (QUIC HP + RFC 9001),
OPEN-07 (HTTP/2 + HTTP/3 QPACK on STREAM), OPEN-08 (DNS rdata pointers),
OPEN-09 (`joinMulticast`). Twelve FIX-* rows plus those in the
canonical file.
