# Copilot instructions for pqtransport

- Treat `doc/` as the canonical documentation root. Start at `doc/INDEX.md`.
- Cryptography is exclusively `package:pqforge`. Infrastructure is exclusively
  `package:swissarmyknife`. Do not add a third crypto or utility dependency.
- No `dart:ffi`. No platform TLS (`SecureSocket`) on the PQ path.
  `dart:io` belongs only in `lib/src/socket/io_socket.dart` and the
  `pqtransport_io.dart` barrel.
- Hybrid concatenation is group-dependent (RFC 10024):
  `X25519MLKEM768` is ML-KEM then X25519; NIST-curve groups are ECDHE then
  ML-KEM. Never use `PqForgeCombiner.combine()` as the TLS combiner (it is
  always classical then PQ). Concat uses `concatenateSharedSecrets`.
- Parses return swissarmyknife `Result`. Handshake/UDP/QUIC/DNS/mDNS/HTTP
  machines use `StateMachine.trigger` → `Result`.
- Size and codepoint literals live in `lib/src/core/lengths.dart`.
- Do not vendor P-256 / P-384 ECDH. Call `PqTransportCrypto` (pqforge 0.4.4
  already exports it). All three RFC 10024 groups are live. Profile/group
  mismatches fail closed via `requireGroup`.
- Do not put IANA `0x1302` on a SHA-256 schedule (OPEN-02). SHA-384
  Extract/Expand is exported but the TLS schedule is still SHA-256.
- Do not claim FIPS 140 / CMVP module status, OpenSSL interop without a
  recorded fixture, hard constant-time execution, or hard memory erasure.
- Run `bash tool/check_invariants.sh .` before finishing a change.
