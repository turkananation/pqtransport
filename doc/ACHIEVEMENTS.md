# Achievements — pqtransport 0.1.0

Last updated: 2026-09-17

This is an evidence list, not marketing. Every row cites a test or a
file. If a row cannot be cited, it does not belong here.

## Release snapshot

| Item | Value | Evidence |
|---|---|---|
| Version | `0.1.0` | `pubspec.yaml` |
| SDK | `>=3.12.0 <4.0.0` | `pubspec.yaml` (blueprint's `>=3.8.0` was stale) |
| Crypto | `pqforge ^0.4.4` | `pubspec.yaml` |
| Infra | `swissarmyknife ^0.1.0` | `pubspec.yaml` |
| Analyzer | clean | `dart analyze` |
| Tests | 104 passed | `dart test` |
| Coverage | 90.5% of `lib/` on the codec pass; NIST live tests added after | `coverage/lcov.info` |
| FFI | none | `grep` of `lib/` + `test/` |
| Platform TLS on PQ path | none | web barrel does not import `dart:io` |

## Distinguished Engineer loop (executed)

Build order from the skill was respected:

`core lengths/errors` → `socket` → `udp` → `tls` → `dns` → `mdns` → `quic` → `http`

| Phase | Delivered | Gate |
|---|---|---|
| 0 Core | `lengths.dart` holds every protocol size; `requireLength`; hybrid concat for **three** groups including ML-KEM-1024 | `test/core/` |
| 1 Socket | `PqTransportSocket`, `MemoryByteSocket` (buffers until listen), `MemoryDatagramNetwork` (unicast + mDNS multicast flood), `IoDatagramChannel` | `test/io/`, `test/extra_coverage_test.dart` |
| 2 UDP | `PqDatagram` AES-256-GCM, replay peek **before** AEAD, Throttler, `PqEncryptedUdpSocket` for all three RFC 10024 groups | `test/udp/datagram_test.dart` |
| 3 TLS | `StateMachine`, compact ClientHello/ServerHello, ML-DSA-65 CertificateVerify, Finished HMAC, exporter, epoch-separated record sequences, `PqTlsSocket`, live NIST groups | `test/tls/` |
| 4 DNS | Wire codec for v1 RRs including PTR/NS; CircuitBreaker; TTL Cache; DoH/DoT helpers | `test/dns/wire_test.dart` |
| 5 mDNS | Probe/announce/browse; ML-DSA-65 TXT sign/verify | `test/mdns/mdns_test.dart` |
| 6 HTTP/1.1 | Encoder/decoder; GET over a completed `PqTlsSocket` | `test/tls/socket_http_test.dart` |
| 7 QUIC (minimum) | 1-RTT protect, CRYPTO/STREAM frames, flow control | `test/quic/quic_test.dart` |

HTTP/2 was **not** implemented (blueprint phase 6 second half). HTTP/3 is frames only.

## Hybrid (the #1 interop bug, pinned)

RFC 10024 concatenation is **group-dependent**. Tests prove the two 64-byte
combiners differ for the same `(ssKem, ssEcdh)` pair.

| Group | Codepoint | Client | Server | SS | Order | Live KEX |
|---|---|---|---|---|---|---|
| X25519MLKEM768 | 0x11EC | 1216 | 1120 | 64 | **ML-KEM then X25519** | Yes |
| SecP256r1MLKEM768 | 0x11EB | 1249 | 1153 | 64 | ECDHE then ML-KEM; leading `0x04` | Yes (`balanced`) |
| SecP384r1MLKEM1024 | 0x11ED | 1665 | 1665 | 80 | ECDHE then ML-KEM; leading `0x04` | Yes (`maximum`) |

Concat uses `PqForgeCombiner.concatenateSharedSecrets` after length /
all-zero checks. `combine()` is **not** the TLS combiner: it always does
`classical \|\| PQ`, which would reverse X25519MLKEM768.

Evidence: `test/core/hybrid_share_test.dart`.

## Live cryptography (not stubs)

| Path | What actually runs |
|---|---|
| ML-KEM-768 / ML-KEM-1024 | `PqKemPrimitives.generateKeyPair` / `encapsulate` / `decapsulate` |
| X25519 | `PqForgeHybridKeyAgreement.generateClassicalKeyPairBytes` + `x25519SharedSecret` |
| P-256 ECDH | `generateP256KeyPairBytes` / `p256SharedSecret` (uncompressed SEC1, x-coordinate) |
| P-384 ECDH | `generateP384KeyPairBytes` / `p384SharedSecret` |
| ML-DSA-65 / ML-DSA-87 | `PqSignaturePrimitives.sign` / `verify` on CertificateVerify and mDNS TXT |
| AES-256-GCM | `PqSymmetricPrimitives.aesGcmEncrypt` / `aesGcmDecrypt` |
| HKDF-SHA-256 | pqforge `hkdfExtractSha256` / `hkdfExpandSha256` (RFC 5869 A.1 vector) |
| KEM check | `PqKemPrimitives.checkEncapsulationKey` before encapsulate |
| Transcript | SHA-256 of concatenated handshake messages |

Peer stubs (fake flights) were allowed. Crypto stubs were not.

## swissarmyknife mapping (mandatory, done)

| Concern | Primitive | Where |
|---|---|---|
| TLS / UDP reliability / mDNS / QUIC | `StateMachine` | `tls/machines.dart`, `udp/reliable_window.dart`, `mdns/pq_mdns.dart`, `quic/packet.dart` |
| Parses | `Result<T, PqTransportError>` | every codec |
| DoH/DoT/UDP resolver hops | `CircuitBreaker` | `PqDnsClient` |
| DNS/mDNS answers | `Cache` with injected clock | `PqDnsClient`, mDNS registry |
| UDP send rate | `Throttler` | `PqUdpSocket` (`Duration.zero` skips) |
| mDNS events | `EventBus` (instance, not global) | `PqMdnsClient` |

## Test gates (skill `09-test-gates.md`) — 0.1.0

| Gate | Status |
|---|---|
| `requireLength` exact / n-1 / n+1 | Done |
| Combiner order differs X25519 vs P-256 | Done |
| `zeroize` overwrites the buffer | Done |
| AEAD round trip; bit-flip fails | Done |
| Replay window drops duplicates | Done |
| Throttler blocks extra send | Done |
| Client 1216 / server 1120 / ss 64, ML-KEM first | Done |
| P-256 1249 / 1153, ECDHE first, leading `0x04` | Done |
| Happy path `handshakeCompleted` | Done |
| Illegal event → `failed` + `Result.failure` | Done |
| HRR once; second HRR fails | Done (state-machine API, not a wire HRR) |
| Wrong-length ek → `illegal_parameter` | Done |
| Bad-modulus ek → `illegal_parameter` without catch | Done |
| Profile/group mismatch refused | Done (`requireGroup`) |
| Two IKMs → two application keys; exporter deterministic | Done |
| DNS RR round-trip; pointer cycle rejected | Done |
| CircuitBreaker opens; cache expires at TTL | Done |
| mDNS probe/announce/browse; ML-DSA TXT verify / mutate-fail | Done |
| CRYPTO frame carries 1216-byte share | Done (size; share body is zeros in that test) |
| Packet protect round trip; bit-flip fails | Done |
| Flow control violation is an error | Done |
| HTTP/1.1 GET over mock TLS | Done |
| OpenSSL interop fixture | **Not a 0.1.0 claim** |

## What this release does *not* achieve

Recorded so achievements cannot be misread:

- RFC 8446-shaped ClientHello / ServerHello / X.509 certificates.
- IANA `TLS_AES_256_GCM_SHA384` (0x1302) or `TLS_CHACHA20_POLY1305_SHA256` (0x1303).
- OpenSSL 3.5+ / BoringSSL interop (needs OPEN-01 hellos, not ECDH).
- Full RFC 9000 QUIC, HTTP/2, HTTP/3+QPACK.
- Production DoH/DoT with ALPN.
- Real multicast join on `IoDatagramChannel`.
- CMVP / FIPS 140 module validation.
