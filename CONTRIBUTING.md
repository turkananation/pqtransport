# Contributing to pqtransport

Thank you for your interest. This package sits on top of
[`pqforge`](https://github.com/turkananation/pqforge) and
[`swissarmyknife`](https://github.com/turkananation/swissarmyknife).
Read [doc/INDEX.md](doc/INDEX.md) and [doc/CLAIM_BOUNDARY.md](doc/CLAIM_BOUNDARY.md)
before writing code.

## 1. Development setup

Pure Dart. No native bindings. No `dart:ffi`.

### Prerequisites

- Dart SDK `>=3.12.0 <4.0.0`

### Installation

1. Fork and clone this repository.
2. `dart pub get`
3. Verify:

   ```bash
   dart format --output=none --set-exit-if-changed .
   dart analyze --fatal-infos
   bash tool/check_invariants.sh .
   dart test
   ```

## 2. Core principles

- **Crypto stays in pqforge.** Do not reimplement ML-KEM, ML-DSA, AES-GCM,
  HMAC, or X25519 here. If a primitive is missing, open BLK- against pqforge
  ([doc/PQFORGE_EXPORTS.md](doc/PQFORGE_EXPORTS.md)) rather than vendoring it.
- **Infrastructure stays in swissarmyknife.** `Result`, `StateMachine`,
  `CircuitBreaker`, `Cache`, `Throttler`, `EventBus`.
- **RFC 10024 concatenation is group-dependent.** X25519MLKEM768 is
  ML-KEM then X25519. NIST-curve groups are ECDHE then ML-KEM.
  `PqForgeCombiner` is always classical then PQ — do not use it as the TLS
  combiner.
- **Fail closed.** Missing P-256/P-384 ECDH must not silently drop to
  classical. Parses return `Result`.
- **Claim boundary.** This is not a FIPS 140 module, not OpenSSL-interop
  in 0.1.0, and not IANA `0x1302` on a SHA-256 schedule.

## 3. Branching and commits

- Default branch is `main`. Open PRs against `main`.
- Conventional commits: `feat:`, `fix:`, `docs:`, `test:`, `ci:`, `chore:`.
- One concern per PR. Wire-format changes need a test.

## 4. Pull request checklist

Use `.github/pull_request_template.md`. In short:

- [ ] Format / analyze / invariants / tests green
- [ ] `CHANGELOG.md` and `doc/BUGS.md` / `doc/TRACKER.md` updated
- [ ] No forbidden claim language
- [ ] No size literals outside `lib/src/core/lengths.dart`

## 5. Security vulnerabilities

Do **not** open a public issue. Follow [SECURITY.md](SECURITY.md).

## 6. Documentation

Canonical root: [doc/INDEX.md](doc/INDEX.md). Architecture, features, bugs,
tracker, roadmap, and the claim boundary all live under `doc/`.
