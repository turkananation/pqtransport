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
      `PqForgeCombiner.combine()` is **not** used as the TLS combiner.
      Concat uses `concatenateSharedSecrets` after length / all-zero checks.
- [ ] No `dart:ffi` and no platform `SecureSocket` on the PQ path.
      IO stays behind `package:pqtransport/pqtransport_io.dart`.
- [ ] Parses that can fail on the wire return `Result` (swissarmyknife),
      not thrown exceptions at the codec boundary.
- [ ] Size / codepoint literals live in `lib/src/core/lengths.dart`.
- [ ] Cryptography stays in pqforge. Do not vendor P-256 / P-384 ECDH,
      HKDF, or ChaCha. All three RFC 10024 groups are live via pqforge
      0.4.4. See [doc/PQFORGE_EXPORTS.md](doc/PQFORGE_EXPORTS.md).
- [ ] IANA `0x1302` is not put on a SHA-256 schedule (OPEN-02).

## Verification

- [ ] `dart format --output=none --set-exit-if-changed .`
- [ ] `dart analyze --fatal-infos`
- [ ] `bash tool/check_invariants.sh .`
- [ ] `dart test`
- [ ] New behaviour has a test (codec, live handshake, or both)
- [ ] `CHANGELOG.md` updated (`## Unreleased` or the current version)
- [ ] `doc/BUGS.md` / `doc/TRACKER.md` updated if an OPEN/BLK/FIX moved

## Protocol notes

<!-- Hybrid group, record epoch, DNS type, QUIC frame, HTTP version. -->

---
By submitting this PR you license the contribution under the MIT license.
