# Claim Boundary

Last updated: 2026-09-17

pqtransport sits **above** pqforge, which sits **above** pqcrypto. This
layer may not invent a stronger claim than the primitive layer has. A
later role (Client Integration) may not upgrade a claim made here.

Sister evidence:

- [`pqcrypto`](https://github.com/turkananation/pqcrypto) — FIPS 203/204/205 primitives and KAT ledger
- [`pqforge`](https://github.com/turkananation/pqforge) — hybrid KEX, AEAD, HKDF, signatures
- Skill: `.grok/skills/pqtransport-distinguished-engineer/references/00-evidence-boundary.md`

## Package floor (verify live before a pub.dev cut)

| Package | Floor | Role |
|---|---|---|
| pqcrypto | 0.4.1 (via pqforge, not a direct dep) | FIPS 203/204/205 primitives, KATs |
| pqforge | **0.4.4** | Hybrid KEX, AEAD, HKDF, signatures |
| swissarmyknife | **0.1.0** | StateMachine, Result, Cache, CircuitBreaker, Throttler |
| pqtransport | 0.1.0 in this tree, unpublished until gates pass | Protocol layer |

SDK: **`>=3.12.0 <4.0.0`**. The original blueprint said `>=3.8.0`; both
foundational packages publish `sdk: ^3.12.0`. Do not lower the floor.

## Allowed wording

- "FIPS 203-aligned ML-KEM via package:pqforge / package:pqcrypto with
  checked-in KAT evidence in pqcrypto."
- "FIPS 204-aligned ML-DSA, byte-exact on pqcrypto's checked-in KAT corpus."
- "FIPS 205-aligned SLH-DSA for all 12 parameter sets in pqcrypto 0.4.x"
  (available through pqforge; **not** the default interactive handshake
  signature in pqtransport).
- "TLS 1.3 hybrid groups X25519MLKEM768, SecP256r1MLKEM768, and
  SecP384r1MLKEM1024 as specified by RFC 10024, with unit-tested share
  concatenation." Live KEX in 0.1.0 is **all three RFC 10024 groups**.
  SecP384r1MLKEM1024 requires `PqForgeProfile.maximum`.
- "Pure-Dart transport. No dart:ffi. Cryptography exclusively from pqforge."
- "Best-effort zeroization in Dart."
- "Best-effort side-channel posture in Dart (VM / dart2js / dart2wasm
  cannot guarantee constant-time execution)."
- "RFC 10024-aligned hybrid share encoding with unit-tested concatenation."

## Forbidden wording

Do not write the invariant-script banned phrases (see
`scripts/check_invariants.sh` in the Distinguished Engineer skill).
Positive claims of module validation, a CMVP listing, hard
constant-time execution, or hard memory erasure are forbidden.

Use instead:

| Do not claim | Use instead |
|---|---|
| Module validation under FIPS 140 | "not a FIPS 140 module" |
| A CMVP listing | "no CMVP listing; not claimed" |
| Hard constant-time execution | "best-effort side-channel posture in Dart" |
| Hard memory erasure | "best-effort zeroization" |

Also forbidden in meaning, even if the substring differs:

- "certified", "FIPS 140 module" as a positive claim.
- "Production-ready post-quantum TLS" in the OpenSSL sense.
- RFC-byte-exact TLS 1.3 interoperability with OpenSSL / BoringSSL
  **before** the fixture in [OPENSSL_INTEROP.md](OPENSSL_INTEROP.md) is green.
- "IANA `TLS_AES_256_GCM_SHA384` (0x1302)" for the 0.1.0 record cipher.
  The schedule is HKDF-SHA-256. Putting 0x1302 on the wire would be a lie.
- Web UDP / mDNS / raw QUIC when the target is a browser.

## RFC claim map

| Need | Cite | 0.1.0 honesty |
|---|---|---|
| TLS 1.3 record + handshake + key schedule | RFC 8446 | Schedule structure yes; hellos RFC 8446-shaped; hash SHA-256; cipher `0xFF00` not IANA 0x1302 |
| Hybrid KEX framework in TLS 1.3 | RFC 9954 | Concat is group-dependent; X25519 name order is **not** followed |
| X25519MLKEM768 / SecP256r1MLKEM768 / SecP384r1MLKEM1024 | RFC 10024 | Codecs for all three; live KEX for 0x11EC only |
| PQ/T terminology | RFC 9794 | Hybrid, not PQ-only |
| ML-KEM / ML-DSA / SLH-DSA | FIPS 203 / 204 / 205 | Via pqforge → pqcrypto |
| QUIC | RFC 9000, 9001, 9002 | Packet + frame sketch, not a connection |
| HTTP/3 | RFC 9114 | Frame types only |
| DNS / EDNS0 / SVCB / DoH / DoT / mDNS | RFC 1035, 6891, 9460, 8484, 7858, 6762/6763 | Wire + helpers; production ALPN not done |
| X25519 | RFC 7748 | Via pqforge |

RFC 10024 note (normative): the group name `X25519MLKEM768` does **not**
follow RFC 9954 §3.2 naming order. Shares and shared secrets are
**ML-KEM then X25519**. Do not "correct" this to match the name.

## Primitive profile (do not invert)

Default enterprise profile is **hybrid**:

| Primitive | Set | Size |
|---|---|---|
| Classical KEX | X25519 (or P-256 / P-384 when that group is selected) | 32-byte ss (P-256 x-coordinate); 48-byte ss (P-384 x-coordinate) |
| Lattice KEM | ML-KEM-768 (balanced) | pk=1184, ct=1088, sk=2400, ss=32 |
| Lattice KEM (maximum / P-384 group) | ML-KEM-1024 | pk=1568, ct=1568, sk=3168, ss=32 |
| Identity signature | ML-DSA-65 | pk=1952, sk=4032, sig=3309 |
| Session key (app UDP) | HKDF-SHA-256 output | 32 bytes |

SLH-DSA is **not** the default interactive handshake signature. Use it
for low-frequency artifact, archival, or mDNS defense-in-depth signing
after handling large signatures and slow `s` sets.

Public keys must be authenticated. ML-KEM alone is not authenticated
transport — TLS certificates / ML-DSA-bound mDNS records / an
out-of-band key id are the authentication story.

## Drift rule

If pub.dev versions, IANA codepoints, or RFC text disagree with a number
in `lib/src/core/lengths.dart` or this folder, **stop**, fetch the live
document, update lengths + docs together, then continue. Silent drift is
a defect.
