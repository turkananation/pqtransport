---
name: Protocol / wire defect
about: RFC 10024 concat, TLS record, DNS rdata, QUIC frame, or HTTP codec issue.
title: "fix(wire): "
labels: "bug,rfc-10024"
assignees: ""
---

## Protocol

- [ ] TLS 1.3 hybrid (RFC 10024 / RFC 8446)
- [ ] Encrypted UDP
- [ ] DNS / DoH / DoT
- [ ] mDNS
- [ ] QUIC
- [ ] HTTP/1.1 or HTTP/3 frames

## Group / lengths

| Field | Value |
|---|---|
| Group | X25519MLKEM768 / SecP256r1MLKEM768 / SecP384r1MLKEM1024 / n/a |
| Expected length | (cite `lib/src/core/lengths.dart`) |
| Observed length | |

## Concatenation order

RFC 10024: X25519MLKEM768 is **ML-KEM then X25519**. NIST-curve groups are **ECDHE then ML-KEM**. Do not use `PqForgeCombiner` as the TLS combiner.

## Evidence

Hex dump, `Result` error code, or failing test path.

## Proposed fix

Keep size literals in `lengths.dart`. Parses stay `Result`-typed. Fail closed.
