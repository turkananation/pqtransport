---
title: Claim Boundary
description: Allowed vs forbidden wording for pqtransport. This layer may not invent a stronger claim than pqcrypto or pqforge.
---

pqtransport sits **above** pqforge, which sits **above** pqcrypto. This
layer may not invent a stronger claim than the primitive layer has. A
later role (Client Integration) may not upgrade a claim made here.

<Warning>
  Not a FIPS 140 module. No CMVP listing. Side-channel resistance and
  zeroization in Dart are best-effort. Do not write "FIPS validated",
  "CMVP validated", "constant-time Dart", or "securely erased".
</Warning>

## Package floor

| Package | Floor | Role |
| --- | --- | --- |
| pqcrypto | 0.4.1 (via pqforge) | FIPS 203/204/205 primitives, KATs |
| pqforge | **0.4.4** | Hybrid KEX, AEAD, HKDF, signatures |
| swissarmyknife | **0.1.0** | StateMachine, Result, Cache, CircuitBreaker, Throttler |
| pqtransport | 0.1.0 in this tree | Protocol layer |

SDK: **`>=3.12.0 <4.0.0`**. Do not lower the floor.

## Allowed wording

- "FIPS 203-aligned ML-KEM via package:pqforge / package:pqcrypto with
  checked-in KAT evidence in pqcrypto."
- "FIPS 204-aligned ML-DSA, byte-exact on pqcrypto's checked-in KAT corpus."
- "TLS 1.3 hybrid groups X25519MLKEM768, SecP256r1MLKEM768, and
  SecP384r1MLKEM1024 as specified by RFC 10024, with unit-tested share
  concatenation." Live KEX in 0.1.0 is **all three RFC 10024 groups**.
- "Pure-Dart transport. No dart:ffi. Cryptography exclusively from pqforge."
- "Best-effort zeroization in Dart."
- "Best-effort side-channel posture in Dart."
- "RFC 10024-aligned hybrid share encoding with unit-tested concatenation."

## Forbidden → use instead

| Do not claim | Use instead |
| --- | --- |
| Module validation under FIPS 140 | "not a FIPS 140 module" |
| A CMVP listing | "no CMVP listing; not claimed" |
| Hard constant-time execution | "best-effort side-channel posture in Dart" |
| Hard memory erasure | "best-effort zeroization" |
| Interoperable with OpenSSL | "unit-tested concatenation" until a fixture is green |

Canonical file:
[`doc/CLAIM_BOUNDARY.md`](https://github.com/turkananation/pqtransport/blob/main/doc/CLAIM_BOUNDARY.md).
