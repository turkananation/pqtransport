# Copilot instructions for pqtransport

- Treat `doc/` as the canonical documentation root. Start at `doc/INDEX.md`.
- Cryptography is exclusively `package:pqforge`. Infrastructure is exclusively
  `package:swissarmyknife`. Do not add a third crypto or utility dependency.
- No `dart:ffi`. No platform TLS (`SecureSocket`) on the PQ path.
  `dart:io` belongs only in `lib/src/socket/io_socket.dart` and the
  `pqtransport_io.dart` barrel.
- Hybrid concatenation is group-dependent (RFC 10024):
  `X25519MLKEM768` is ML-KEM then X25519; NIST-curve groups are ECDHE then
  ML-KEM. Never use `PqForgeCombiner` as the TLS combiner (it is always
  classical then PQ).
- Parses return swissarmyknife `Result`. Handshake/UDP/QUIC/DNS/mDNS/HTTP
  machines use `StateMachine.trigger` → `Result`.
- Size and codepoint literals live in `lib/src/core/lengths.dart`.
- Do not vendor P-256 / P-384 ECDH. Fail closed until pqforge exports it.
- Do not claim FIPS 140 / CMVP module status, OpenSSL interop without a
  recorded fixture, IANA `0x1302` on a SHA-256 schedule, hard constant-time
  execution, or hard memory erasure.
- Run `bash tool/check_invariants.sh .` before finishing a change.
