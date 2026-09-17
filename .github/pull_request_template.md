# Pull request

Thank you for contributing to `pqtransport`. Complete this checklist before
requesting review.

## Description

<!-- Why this change exists. Link OPEN-/BLK-/IMP- IDs and issues. -->

## Claim boundary (mandatory)

- [ ] This PR does not introduce wording that reads as a FIPS 140 / CMVP
      module listing, hard constant-time execution, or hard memory erasure.
      Language matches [doc/CLAIM_BOUNDARY.md](doc/CLAIM_BOUNDARY.md).
- [ ] Concatenation for `X25519MLKEM768` stays **ML-KEM then X25519**.
      `PqForgeCombiner` is **not** used as the TLS combiner.
- [ ] No `dart:ffi` and no platform `SecureSocket` on the PQ path.
      IO stays behind `package:pqtransport/pqtransport_io.dart`.
- [ ] Parses that can fail on the wire return `Result` (swissarmyknife),
      not thrown exceptions at the codec boundary.
- [ ] Size / codepoint literals live in `lib/src/core/lengths.dart`.
- [ ] P-256 / P-384 ECDH is **not** vendored here. Those groups fail closed
      until pqforge exports ECDH (see [doc/PQFORGE_EXPORTS.md](doc/PQFORGE_EXPORTS.md)).

## Verification

- [ ] `dart format --output=none --set-exit-if-changed .`
- [ ] `dart analyze --fatal-infos`
- [ ] `bash tool/check_invariants.sh .`
- [ ] `dart test`
- [ ] New behaviour has a test (codec, live X25519MLKEM768 handshake, or both)
- [ ] `CHANGELOG.md` updated (`## Unreleased` or the current version)
- [ ] `doc/BUGS.md` / `doc/TRACKER.md` updated if an OPEN/BLK/FIX moved

## Protocol notes

<!-- Hybrid group, record epoch, DNS type, QUIC frame, HTTP version. -->

---
By submitting this PR you license the contribution under the MIT license.
