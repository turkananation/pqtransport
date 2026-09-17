---
title: Hybrid Groups
description: RFC 10024 hybrid key_share concatenation. ML-KEM-first for X25519MLKEM768. ECDHE-first for NIST-curve groups.
---

The #1 interop bug in this stack is concatenating hybrid shares in the
wrong order. pqtransport encodes and decodes three RFC 10024 groups.
Live key exchange in 0.1.0 is **X25519MLKEM768 only**.

## Why the name lies

RFC 9954-style names read classical-then-PQ. **X25519MLKEM768 does not
follow that order on the wire.** ML-KEM encapsulation key / ciphertext
comes first; X25519 follows. NIST-curve groups (`SecP256r1MLKEM768`,
`SecP384r1MLKEM1024`) **do** put the uncompressed ECDHE share first,
including the `0x04` prefix.

`package:pqforge`'s `PqForgeCombiner` is always `classical || PQ`. Using
it for X25519MLKEM768 would reverse the RFC. TLS concat stays in
pqtransport.

## Wire sizes

| Group | IANA | Client | Server | Shared secret | Order |
| --- | --- | --- | --- | --- | --- |
| X25519MLKEM768 | 0x11EC | 1216 | 1120 | 64 | kem-first |
| SecP256r1MLKEM768 | 0x11EB | 1249 | 1153 | 64 | ecdhe-first |
| SecP384r1MLKEM1024 | 0x11ED | 1665 | 1665 | 80 | ecdhe-first |

ML-KEM-768: ek 1184, ct 1088, ss 32.
ML-KEM-1024: ek/ct 1568, ss 32.
X25519: 32. P-256 uncompressed: 65. P-384 uncompressed: 97.

## Live vs fail-closed

| Path | Status |
| --- | --- |
| Encode / decode / combine all three groups | Done, byte-exact tests |
| Live X25519 + ML-KEM-768 + ML-DSA-65 + AES-256-GCM | Done |
| Live P-256 ECDH | Fail-closed until pqforge exports it |
| Live P-384 ECDH | Fail-closed until pqforge exports it |

Fail closed means the handshake refuses. It does **not** silently skip
the classical share. See
[`doc/PQFORGE_EXPORTS.md`](https://github.com/turkananation/pqtransport/blob/main/doc/PQFORGE_EXPORTS.md).

## Profile footgun

`PqForgeProfile.maximum` selects ML-KEM-1024 + ML-DSA-87. The live TLS
path is sized for ML-KEM-768 + ML-DSA-65. Constructing
`PqTransportCrypto(profile: PqForgeProfile.maximum)` with the default
X25519MLKEM768 group is inconsistent (OPEN-03). Refuse the mismatch;
do not pad or truncate.

SecP384r1MLKEM1024 is the group that **belongs** with ML-KEM-1024, once
P-384 ECDH exists.

## Tests that pin this

- Combiner order differs for X25519 vs P-256.
- Client 1216 / server 1120 / ss 64, ML-KEM first.
- P-256 1249 / 1153, ECDHE first, leading `0x04`.
- P-384 1665 / 1665 / 80.
- Wrong-length encapsulation key is `illegal_parameter`.
