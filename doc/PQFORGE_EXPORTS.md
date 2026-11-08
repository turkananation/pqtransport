# pqforge exports pqtransport needs

Last updated: 2026-11-08

pqtransport must not vendor a second Kyber, a second X25519, or a second
AES-GCM. When a primitive is missing, the correct move is a pqforge
export, then a thin call here.

Floor today: **pqforge 0.4.13**. The 0.4.6 and 0.4.11 notes below stay
as history.
**0.4.9** is the X.509 parser this package calls. **0.4.10** exports
`PqHpke`. ECH calls that type. It does not keep a second HPKE.
**0.4.11** exports `PqBytes.sha1`. NSEC3 and DS digest type 1 call it.
**0.4.13** makes `PqRsa.verifyPkcs1` accept a 1024, 2048, 3072, or
4096 bit modulus, and adds `PqRsaHash.sha1`. DNSSEC algorithms 5 and 7
call that hash. Algorithms 8 and 10 call SHA-256 and SHA-512.
`generateKeyPair` still refuses 1024. SHA-1 is not used for new
signatures outside those two DNSSEC algorithm numbers.

BLK-01 … BLK-05 landed in 0.4.4. **0.4.5** makes the sync ChaCha helper
dart2js-safe. **0.4.6** exports AES-ECB (`aesEncryptBlock`) and
AES-128-GCM for QUIC Initial / header protection (OPEN-06).
This file records what we consume and what is still not wired. IDs:
[BUGS.md](BUGS.md).

## What 0.4.6 already gives us (do not re-export)

| Job | API we call |
| --- | --- |
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
| **AES-128-GCM + AES-ECB (OPEN-06)** | `aes128GcmEncrypt` / `Decrypt`, `aesEncryptBlock` (16- or 32-byte key) — QUIC Initial AEAD and header protection |
| **Sync ChaCha (BLK-03 → OPEN-13)** | `chacha20Poly1305Encrypt` / `Decrypt` — **wired** into `aeadSeal`. dart2js-safe (Dart engine, 0.4.5). `supportsChaCha20Poly1305` is always `true`. Report: [CHACHA_DART2JS.md](CHACHA_DART2JS.md). |
| **ChaCha20 keystream (OPEN-16)** | `chacha20` — RFC 8439 keystream, caller counter. QUIC header protection (RFC 9001 §5.4.4), pqforge 0.4.8. Not the Poly1305 AEAD. |
| **RSA PKCS#1 verify (0.4.13)** | `PqRsa.verifyPkcs1` with `PqRsaHash.sha1`, `.sha256`, or `.sha512`. DNSSEC algorithms 5, 7, 8, and 10. Moduli 1024, 2048, 3072, 4096. Not PSS. |
| **Ed448 (0.4.13)** | `PqEd448.verify`. DNSSEC algorithm 16. Pure Ed448, empty context. 57-byte key, 114-byte signature. Not Ed448ph. Not X.509. |
| ChaCha session object | `PqForgeSecureSession` — still not a TLS record primitive |
| Combiner HKDF | `PqForgeCombiner.combine()` — **always** `classical \|\| PQ`, then HKDF. Must **not** be the TLS combiner |
| **Concat-only join (BLK-04)** | `concatenateSharedSecrets` + `PqHybridConcatOrder` |
| **KEM check (BLK-05)** | `PqKemPrimitives.checkEncapsulationKey` |

`PqEcdsaP256` is a **signature** (RFC 6979 + low-S). It is not ECDH.

## Consumed in this tree

1. Floor is pqforge 0.4.13, pinned by git commit `30a7279` until that version is on pub.dev. The pin is not publishable. `PqBytes.sha1` is NSEC3 and DS digest type 1. `PqRsaHash.sha1` is DNSSEC algorithms 5 and 7 only.
2. Call new helpers **only** from `PqTransportCrypto`.
3. Live handshake tests for all three RFC 10024 groups.
4. Local HMAC Expand loop deleted.
5. Fail-closed NIST branch deleted; `requireGroup` refuses profile/group mismatch.

## Still not wired (this package, not a pqforge wait)

| ID | Export | Why it waits |
|---|---|---|
| Expand-Label | — | Stays in pqtransport (TLS framing: `tls13` + label + context). |

OPEN-02 and OPEN-13 are **Fixed**.

## What pqtransport will never ask pqforge for

| Ask | Why not |
| --- | --- |
| RFC 8446 ClientHello codec | Protocol layer |
| DNS / QUIC / HTTP codecs | Protocol layer |
| `StateMachine` / `CircuitBreaker` | swissarmyknife |
| A FIPS 140 module boundary | Neither package is a CMVP listing |
| `dart:ffi` Kyber | Forbidden |

## Integration rule after an export lands

1. Bump `pqforge` in `pubspec.yaml`. A git pin is only for the unpublished 0.4.13 commit, and it comes out before this package is published.
2. Call the new helper from `PqTransportCrypto` only.
3. Delete the local adapter in the same PR.
4. Add a live handshake test for any newly unlocked group.
5. Update this file, [BUGS.md](BUGS.md), and [TRACKER.md](TRACKER.md)
   together.

## OPEN-14 waits on pqforge 0.4.8

X.509 is a pqforge certificate layer, not a pqtransport codec and not a
PointyCastle import here. pqforge 0.4.7 does not parse certificates.
0.4.8 adds `lib/src/certificates/x509.dart` and exports it from
`package:pqforge/pqforge.dart`. Projects that never speak TLS can call
`PqX509`. pqtransport only applies TLS policy.

| Need | Where it comes from |
| --- | --- |
| Parse, mint, path check, original TBS bytes | `PqX509` in pqforge 0.4.8 |
| ML-DSA-65/87/44, empty context, pure | existing primitive, called by `PqX509` |
| P-256 ECDSA | existing `PqEcdsaP256`, after DER `r\|\|s` decode |
| P-384 ECDSA | new `PqEcdsaP384` in that same release |
| RSA PKCS#1 and RSA-PSS | new `PqRsa`, PointyCastle already inside pqforge |
| Ed25519 | new sync `PqEd25519`. Not the async hybrid verifier |
| TLS Certificate message, alerts, anchors-as-policy | pqtransport, after the bump to `pqforge: ^0.4.8` |

Do not import `package:pointycastle` or `package:cryptography` from
pqtransport to get there. No git pin.

Design: [ADR-0014](adr/ADR-0014-x509-certificate.md).
Plan: [OPEN-14-x509-certificate.md](plans/OPEN-14-x509-certificate.md).

