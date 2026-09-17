# pqtransport Documentation Index

Last updated: 2026-09-17

This is the canonical documentation root for `package:pqtransport` **0.1.0**.
Use `doc/` links for project documentation. The README is the install
entry; this folder is the evidence, architecture, and planning surface.

Surfaces: [GitHub Pages](https://turkananation.github.io/pqtransport/) ·
[Wiki](https://github.com/turkananation/pqtransport/wiki) ·
[Repository](https://github.com/turkananation/pqtransport) ·
[pub.dev](https://pub.dev/packages/pqtransport)

Sister packages:

- [`pqcrypto`](https://github.com/turkananation/pqcrypto) — FIPS 203/204/205 primitives
- [`pqforge`](https://github.com/turkananation/pqforge) — hybrid KEX, AEAD, HKDF, signatures
- [`swissarmyknife`](https://github.com/turkananation/swissarmyknife) — StateMachine, Result, Cache, CircuitBreaker, Throttler

pqtransport sits **above** pqforge, which sits **above** pqcrypto. Do not
upgrade a claim this layer is not allowed to make. See
[CLAIM_BOUNDARY.md](CLAIM_BOUNDARY.md).

## Current package boundary

| Area | Current state |
|---|---|
| Package version | `0.1.0` (unpublished on pub.dev; GitHub tag `vX.Y.Z` publishes via `publish.yml` once automated publishing is enabled) |
| SDK | `>=3.12.0 <4.0.0` |
| Runtime dependencies | `pqforge ^0.4.4`, `swissarmyknife ^0.1.0` |
| Native / FFI | None. No `dart:ffi`. No platform TLS (`SecureSocket`) on the PQ path. |
| Hybrid groups | RFC 10024 codecs **and live handshakes** for X25519MLKEM768, SecP256r1MLKEM768, SecP384r1MLKEM1024 |
| Live handshake | All three groups. P-384 requires `PqForgeProfile.maximum`. Profile/group mismatch is refused. |
| TLS wire | RFC 8446 ClientHello/ServerHello (OPEN-01). Raw-pk negotiated (OPEN-04). HRR + cookie (OPEN-05). IANA `0x1302` (SHA-384) default; `0x1303` (ChaCha) offered. `0xFF00` retired. |
| Tests | `dart analyze` clean; **140** tests pass; **90.7%** line coverage of `lib/` |
| OpenSSL interop | Not started. Do not claim it. [OPENSSL_INTEROP.md](OPENSSL_INTEROP.md) |
| CMVP / FIPS 140 | Not claimed. [CLAIM_BOUNDARY.md](CLAIM_BOUNDARY.md) |

## Read this first

| Need | Start here | Then read |
|---|---|---|
| What 0.1.0 actually shipped | [ACHIEVEMENTS.md](ACHIEVEMENTS.md) | [FEATURES.md](FEATURES.md) |
| How the stack is laid out | [ARCHITECTURE.md](ARCHITECTURE.md) | [API.md](API.md) |
| Public API and barrels | [API.md](API.md) | [PLATFORM_SUPPORT.md](PLATFORM_SUPPORT.md) |
| Known defects | [BUGS.md](BUGS.md) | [SECURITY_AUDIT.md](SECURITY_AUDIT.md) |
| Open work | [TRACKER.md](TRACKER.md) | [ROADMAP.md](ROADMAP.md) |
| What pqforge 0.4.4 exports | [PQFORGE_EXPORTS.md](PQFORGE_EXPORTS.md) | [IMPROVEMENTS.md](IMPROVEMENTS.md) |
| Claim language | [CLAIM_BOUNDARY.md](CLAIM_BOUNDARY.md) | [OPENSSL_INTEROP.md](OPENSSL_INTEROP.md) |
| Contributor loop | [ENGINEERING_GUIDE.md](ENGINEERING_GUIDE.md) | [TRACKER.md](TRACKER.md) |

## Documents

| Document | Purpose |
|---|---|
| [ACHIEVEMENTS.md](ACHIEVEMENTS.md) | What 0.1.0 delivered, with evidence (tests, coverage, gates). |
| [FEATURES.md](FEATURES.md) | Feature matrix: done / partial / fail-closed / not started. |
| [ARCHITECTURE.md](ARCHITECTURE.md) | Module layout, data flow, barrels, swissarmyknife/pqforge mapping. |
| [API.md](API.md) | Public types, barrels, consume examples. |
| [PLATFORM_SUPPORT.md](PLATFORM_SUPPORT.md) | VM / mobile / desktop vs web. |
| [CLAIM_BOUNDARY.md](CLAIM_BOUNDARY.md) | Allowed vs forbidden wording. Why this is not a FIPS 140 module. |
| [SECURITY_AUDIT.md](SECURITY_AUDIT.md) | Risk register for the transport layer. |
| [BUGS.md](BUGS.md) | Open and fixed defects. |
| [TRACKER.md](TRACKER.md) | Cross-document tracker for gates and open work. Canonical tracker. |
| [PROGRESS_TRACKER.md](PROGRESS_TRACKER.md) | Pointer to [TRACKER.md](TRACKER.md) (sister-package name). |
| [ROADMAP.md](ROADMAP.md) | 0.2 → 0.5 direction. Order is not optional. |
| [IMPROVEMENTS.md](IMPROVEMENTS.md) | Prioritized engineering improvements. |
| [PQFORGE_EXPORTS.md](PQFORGE_EXPORTS.md) | Consumed vs not-wired pqforge 0.4.4 APIs. Do not vendor crypto. |
| [OPENSSL_INTEROP.md](OPENSSL_INTEROP.md) | Interop milestone status (not claimed). |
| [ENGINEERING_GUIDE.md](ENGINEERING_GUIDE.md) | Setup, test commands, invariants, coding laws. |
| [SITE.md](SITE.md) | Jaspr documentation site. Why github.io was dark; how to build. |
| [ci/RELEASE_CHECKLIST.md](ci/RELEASE_CHECKLIST.md) | Tag + GitHub Release + pub.dev OIDC publish loop. |

## Verification snapshot (this documentation pass)

- `dart analyze` — no issues.
- `dart test` — 140 passed.
- Line coverage of `lib/` — 90.7% (`2404/2650`).
- Invariant script: no `import 'dart:ffi'`, no stray `1184|1216|1120|1249|1153|0x11EC|0x11EB` outside `lengths.dart`, claim language clean.
- Live X25519MLKEM768 / SecP256r1MLKEM768 / SecP384r1MLKEM1024 handshake
  tests green. RFC 8446-shaped hellos (OPEN-01). Raw-pk negotiated
  (OPEN-04). HelloRetryRequest on the wire (OPEN-05). IANA `0x1302` /
  `0x1303` (OPEN-02, OPEN-13). Leftover error-path coverage (OPEN-12).
  Profile/group mismatch refused (`requireGroup`).
- HTTP/1.1 GET over `PqTlsSocket` green.
- `doc/` set complete: achievements, architecture, features, API, platform,
  claim boundary, security audit, bugs, tracker, progress-tracker alias,
  roadmap, improvements, pqforge exports, OpenSSL interop, engineering guide.

## Family rule

A later role (Client Integration) may not upgrade a claim made here.
This layer may not upgrade a claim [CLAIM_BOUNDARY.md](CLAIM_BOUNDARY.md)
or the sister `pqcrypto` evidence ledger forbids.
