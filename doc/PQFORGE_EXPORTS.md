# pqforge exports pqtransport needs

Last updated: 2026-09-17

pqtransport must not vendor a second Kyber, a second X25519, or a second
AES-GCM. When a primitive is missing, the correct move is a pqforge
export, then a thin call here.

Floor today: **pqforge 0.4.4** (SDK `^3.12.0`, depends on pqcrypto ^0.4.1,
pointycastle ^4.0.0, cryptography ^2.9.0). Web-safe barrel
`package:pqforge/pqforge.dart`. No `dart:ffi` in that barrel.

BLK-01 … BLK-05 all **landed in 0.4.4**. This file records what we consume
and what is still not wired. IDs: [BUGS.md](BUGS.md).

## What 0.4.4 already gives us (do not re-export)

| Job | API we call |
|---|---|
| Profile | `PqForgeProfile.balanced` (768/65), `.maximum` (1024/87), `.compact` (512/44) |
| ML-KEM | `PqKemPrimitives.generateKeyPair` / `encapsulate` / `decapsulate` |
| ML-DSA | `PqSignaturePrimitives.generateKeyPair` / `sign` / `verify` |
| X25519 keygen | `PqForgeHybridKeyAgreement.generateClassicalKeyPairBytes` |
| X25519 ECDH | `PqForgeHybridKeyAgreement.x25519SharedSecret` (raw 32-byte ss) |
| **P-256 ECDH (BLK-01)** | `generateP256KeyPairBytes` / `p256SharedSecret` — uncompressed SEC1, x-coordinate |
| **P-384 ECDH (BLK-01)** | `generateP384KeyPairBytes` / `p384SharedSecret` |
| HMAC / SHA-256 / CSPRNG | `PqBytes.hmacSha256`, `PqBytes.sha256`, `PqBytes.randomBytes` |
| Combined HKDF-SHA-256 | `PqSymmetricPrimitives.hkdfSha256` |
| **RFC 5869 SHA-256 (BLK-02)** | `hkdfExtractSha256` / `hkdfExpandSha256` |
| RFC 5869 SHA-384 | `hkdfExtractSha384` / `hkdfExpandSha384` / `hmacSha384` — **wired** (OPEN-02) |
| AES-256-GCM (sync) | `PqSymmetricPrimitives.aesGcmEncrypt` / `aesGcmDecrypt` |
| **Sync ChaCha (BLK-03 → OPEN-13)** | `chacha20Poly1305Encrypt` / `Decrypt` — **wired** into `aeadSeal` |
| ChaCha session object | `PqForgeSecureSession` — still not a TLS record primitive |
| Combiner HKDF | `PqForgeCombiner.combine()` — **always** `classical \|\| PQ`, then HKDF. Must **not** be the TLS combiner |
| **Concat-only join (BLK-04)** | `concatenateSharedSecrets` + `PqHybridConcatOrder` |
| **KEM check (BLK-05)** | `PqKemPrimitives.checkEncapsulationKey` |

`PqEcdsaP256` is a **signature** (RFC 6979 + low-S). It is not ECDH.

## Consumed in this tree

1. Bump `pqforge` to `^0.4.4`.
2. Call new helpers **only** from `PqTransportCrypto`.
3. Live handshake tests for all three RFC 10024 groups.
4. Local HMAC Expand loop deleted.
5. Fail-closed NIST branch deleted; `requireGroup` refuses profile/group mismatch.

## Still not wired (this package, not a pqforge wait)

| ID | Export | Why it waits |
|---|---|---|
| Expand-Label | — | Stays in pqtransport (TLS framing: `tls13 ` + label + context). |

OPEN-02 and OPEN-13 are **Fixed**.

## What pqtransport will never ask pqforge for

| Ask | Why not |
|---|---|
| RFC 8446 ClientHello codec | Protocol layer |
| DNS / QUIC / HTTP codecs | Protocol layer |
| `StateMachine` / `CircuitBreaker` | swissarmyknife |
| A FIPS 140 module boundary | Neither package is a CMVP listing |
| `dart:ffi` Kyber | Forbidden |

## Integration rule after an export lands

1. Bump `pqforge` in `pubspec.yaml` (do not pin a git path).
2. Call the new helper from `PqTransportCrypto` only.
3. Delete the local adapter in the same PR.
4. Add a live handshake test for any newly unlocked group.
5. Update this file, [BUGS.md](BUGS.md), and [TRACKER.md](TRACKER.md)
   together.
