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
| pqforge | **0.4.13** | Hybrid KEX, AEAD (incl. dart2js ChaCha), HKDF, signatures, X.509, `PqHpke`, `PqBytes.sha1` for NSEC3 and DS type 1, `PqRsa.verifyPkcs1` for DNSSEC algorithms 5, 7, 8, and 10 including a 1024-bit modulus |
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
- "DNSSEC verifies algorithms 5, 7, 8, 10, 13, 14, 15, and 16 via pqforge. RSA moduli are 1024, 2048, 3072, and 4096 bits. Ed448 is pure, empty context. The iterative resolver returns secure, insecure, or bogus from a caller-supplied root anchor. NSEC and NSEC3 prove denial. SHA-1 is the NSEC3 hash, DS digest type 1, and the hash inside algorithms 5 and 7. The AD bit is not validation."
- "ECH is one BoringSSL 0.20261020.0 flight (RFC 9849, pqforge 0.4.10 HPKE). Not OpenSSL. Not a browser."

## Forbidden → use instead

| Do not claim | Use instead |
| --- | --- |
| Module validation under FIPS 140 | "not a FIPS 140 module" |
| A CMVP listing | "no CMVP listing; not claimed" |
| Hard constant-time execution | "best-effort side-channel posture in Dart" |
| Hard memory erasure | "best-effort zeroization" |
| Interoperable with OpenSSL | The sentence in [CLAIM_BOUNDARY.md](https://github.com/turkananation/pqtransport/blob/main/doc/CLAIM_BOUNDARY.md): OpenSSL 3.5.9, three hybrid groups plus X25519, secp256r1, secp384r1, and MLKEM1024. BoringSSL 0.20261020.0 is X25519MLKEM768 and those four fallback groups, not the two NIST hybrids. curl is two GETs. Not a browser. |

Canonical file:
[`doc/CLAIM_BOUNDARY.md`](https://github.com/turkananation/pqtransport/blob/main/doc/CLAIM_BOUNDARY.md).
