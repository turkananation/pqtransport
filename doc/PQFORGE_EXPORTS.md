# pqforge exports pqtransport needs

Last updated: 2026-09-17

pqtransport must not vendor a second Kyber, a second X25519, or a second
AES-GCM. When a primitive is missing, the correct move is a pqforge
export, then a thin call here.

Floor today: **pqforge 0.4.3** (SDK `^3.12.0`, depends on pqcrypto ^0.4.1,
pointycastle ^4.0.0, cryptography ^2.9.0). Web-safe barrel
`package:pqforge/pqforge.dart`. No `dart:ffi` in that barrel.

Tracked as BLK-01 … BLK-05 in [BUGS.md](BUGS.md).

## What 0.4.3 already gives us (do not re-export)

| Job | API we call |
|---|---|
| Profile | `PqForgeProfile.balanced` (768/65), `.maximum` (1024/87), `.compact` (512/44) |
| ML-KEM | `PqKemPrimitives.generateKeyPair` / `encapsulate` / `decapsulate` |
| ML-DSA | `PqSignaturePrimitives.generateKeyPair` / `sign` / `verify` |
| X25519 keygen | `PqForgeHybridKeyAgreement.generateClassicalKeyPairBytes` |
| X25519 ECDH | `PqForgeHybridKeyAgreement.x25519SharedSecret` (raw 32-byte ss) |
| HMAC / SHA-256 / CSPRNG | `PqBytes.hmacSha256`, `PqBytes.sha256`, `PqBytes.randomBytes` |
| Combined HKDF-SHA-256 | `PqSymmetricPrimitives.hkdfSha256` (Extract+Expand in one call) |
| AES-256-GCM (sync) | `PqSymmetricPrimitives.aesGcmEncrypt` / `aesGcmDecrypt` |
| ChaCha (session object) | `PqForgeSecureSession` with `PqForgeCipherSuite.chaCha20Poly1305` — **async**, nonce prepended on the packet, not a TLS record primitive |
| Combiner | `PqForgeCombiner` — **always** `classical \|\| PQ`, then HKDF. Must **not** be the TLS combiner |

`PqEcdsaP256` is a **signature** (RFC 6979 + low-S). It is not ECDH.
`PqClassicalKeyAgreementAlgorithm` is X25519-only.
`PqClassicalProvider` exposes X25519, Ed25519, and ECDSA-P256 sign/verify —
still no P-256/P-384 ECDH.

## BLK-01 — P-256 / P-384 ECDH (P0 for live NIST groups)

Needed so SecP256r1MLKEM768 and SecP384r1MLKEM1024 can complete a
handshake instead of fail-closed.

Proposed (names are a suggestion; byte contracts are not):

```dart
// Uncompressed SEC1: 0x04 || X || Y. Secret is the scalar.
// Shared secret is the x-coordinate only (RFC 8446 / SP 800-56A).

Future<({Uint8List publicKey, Uint8List secretKey})> p256GenerateKeyPair({
  Uint8List? seed,
});
Future<Uint8List> p256SharedSecret({
  required Uint8List secretKey,       // 32-byte scalar
  required Uint8List remotePublicKey, // 65 bytes, prefix 0x04
}); // → 32-byte x-coordinate

Future<({Uint8List publicKey, Uint8List secretKey})> p384GenerateKeyPair({
  Uint8List? seed,
});
Future<Uint8List> p384SharedSecret({
  required Uint8List secretKey,       // 48-byte scalar
  required Uint8List remotePublicKey, // 97 bytes, prefix 0x04
}); // → 48-byte x-coordinate
```

Must reject:

- Point at infinity
- All-zero shared secret
- Wrong length / missing `0x04` prefix
- Off-curve points

Natural home: `PqClassicalProvider` next to `x25519SharedSecret`, plus
static helpers on `PqForgeHybridKeyAgreement` mirroring
`x25519SharedSecret`. Do not overload `PqEcdsaP256`.

Until this lands, pqtransport codecs are byte-exact and the live path
returns `PqTransportError.unsupported`.

## BLK-02 — HKDF-Expand and SHA-384 (P1)

pqforge exports combined `hkdfSha256(ikm, salt, info, outputBytes)` and
`PqBytes.hmacSha256`. It does **not** export:

- RFC 5869 `HKDF-Expand` as its own function
- RFC 8446 `HKDF-Expand-Label`
- Any SHA-384 Extract / Expand / HMAC

0.1.0 composes Expand from HMAC-SHA-256 in
`PqTransportCrypto.hkdfExpand`, tested against RFC 5869 Appendix A.1.
That is protocol framing over an exported HMAC, not a second hash
library. It is still a gap: every TLS stack will rewrite it, and IANA
`TLS_AES_256_GCM_SHA384` (0x1302) cannot be claimed on SHA-256.

Proposed:

```dart
Uint8List hkdfExtractSha256({required Uint8List salt, required Uint8List ikm});
Uint8List hkdfExpandSha256({
  required Uint8List prk,
  required Uint8List info,
  required int outputBytes,
});

Uint8List hmacSha384({required Uint8List key, required Uint8List data});
Uint8List hkdfExtractSha384({required Uint8List salt, required Uint8List ikm});
Uint8List hkdfExpandSha384({
  required Uint8List prk,
  required Uint8List info,
  required int outputBytes,
});
```

Expand-Label can stay in pqtransport (it is TLS framing: `tls13 ` +
label + context). Extract/Expand belong in pqforge so UDP, TLS, and
QUIC share one KDF.

## BLK-03 — sync ChaCha20-Poly1305 (P2)

`PqForgeSecureSession.encrypt` is async, generates its own nonce, and
prepends it. TLS/QUIC records need:

```dart
Uint8List chacha20Poly1305Encrypt({
  required Uint8List key,    // 32
  required Uint8List nonce,  // 12, caller-supplied, uniqueness is ours
  required Uint8List plaintext,
  Uint8List? aad,
}); // ciphertext || tag (16)

Uint8List chacha20Poly1305Decrypt({
  required Uint8List key,
  required Uint8List nonce,
  required Uint8List ciphertext, // ct || tag
  Uint8List? aad,
});
```

Match the AES-GCM helper shape so `PqTransportCrypto.aeadSeal` can switch
on suite without a session object. Needed for IANA 0x1303.

## BLK-04 — group-aware combiner (P2, optional)

`PqForgeCombiner` documents and implements:

```text
concatenatedSecret = classicalSharedSecret || postQuantumSharedSecret
sessionKey         = HKDF(ikm: concatenatedSecret, salt, info, L)
```

RFC 10024 X25519MLKEM768 is the opposite join (`ss_mlkem || ss_x25519`)
and does **not** HKDF inside the combiner — TLS HKDF-Extract consumes the
64-byte concatenation as the (EC)DHE input.

Options for pqforge:

1. Leave TLS concat in pqtransport (current, preferred until a group
   enum exists).
2. Add `PqHybridConcatOrder { classicalThenPq, pqThenClassical }` and a
   **concat-only** helper that does not HKDF.

Do not "just call PqForgeCombiner" from TLS. That reverses X25519MLKEM768
and double-KDFs.

## BLK-05 — FIPS 203 §7.2 encapsulation-key check (P3)

pqcrypto `encapsulate` throws on a bad modulus. RFC 10024 wants
`illegal_parameter` **before** encapsulate, as a `Result`, not a catch.

Proposed:

```dart
bool checkEncapsulationKey(PqKemAlgorithm kem, Uint8List encapsulationKey);
// or Result<(), PqForgeException>
```

Nice-to-have, not load-bearing: 0.1.0 already length-filters; a thrown
encapsulate still tears the handshake down.

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
3. Delete the local adapter in the same PR (Expand, or the fail-closed
   NIST branch).
4. Add a live handshake test for the newly unlocked group.
5. Update this file, [BUGS.md](BUGS.md), and [TRACKER.md](TRACKER.md)
   together.
