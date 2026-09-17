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
  HMAC, X25519, or P-256/P-384 ECDH here. If a primitive is missing, open
  an ID against pqforge ([doc/PQFORGE_EXPORTS.md](doc/PQFORGE_EXPORTS.md))
  rather than vendoring it. pqforge 0.4.4 already exports NIST ECDH, RFC
  5869 SHA-256/SHA-384 HKDF, concat-order helper, and sync ChaCha.
- **Infrastructure stays in swissarmyknife.** `Result`, `StateMachine`,
  `CircuitBreaker`, `Cache`, `Throttler`, `EventBus`.
- **RFC 10024 concatenation is group-dependent.** X25519MLKEM768 is
  ML-KEM then X25519. NIST-curve groups are ECDHE then ML-KEM.
  `PqForgeCombiner.combine()` is always classical then PQ — do not use it
  as the TLS combiner. Concat uses `concatenateSharedSecrets`.
- **Fail closed.** Profile/group mismatches (`requireGroup`) must not
  silently drop the classical share. Parses return `Result`. All three
  RFC 10024 groups are live; do not re-introduce fail-closed ECDH.
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

## 7. Releasing

Tag `v<version>` on `main` after the version bump. That tag drives both:

- `.github/workflows/release.yml` — verify, then create the GitHub Release
- `.github/workflows/publish.yml` — `dart pub publish` via GitHub Actions OIDC
  (environment name `pub.dev`)

Full checklist: [doc/ci/RELEASE_CHECKLIST.md](doc/ci/RELEASE_CHECKLIST.md).
Do not run `dart pub publish` by hand for a tagged release once automated
publishing is enabled on
[pub.dev/packages/pqtransport/admin](https://pub.dev/packages/pqtransport/admin).

The first version on pub.dev is a one-time manual publish; automated publishing
cannot be enabled until the package exists.
