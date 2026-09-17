# Bugs

Last updated: 2026-09-17

Status key:

| Status | Meaning |
|---|---|
| Open | Reproduced or structurally true in 0.1.0 |
| Blocked | Fix lives in pqforge (or an interop peer), not here |
| Fixed | Corrected in this tree; cite the test |
| Won't fix in 0.1 | Honest limit, tracked on the roadmap |

Severity: **P0** stop-ship for the claimed surface, **P1** wrong-on-the-wire
or fail-open, **P2** incomplete protocol, **P3** hygiene.

This file records **transport** defects. Primitive KATs live in pqcrypto.

## Open bugs

| ID | Sev | Component | Summary | Evidence / next step |
|---|---|---|---|---|
| OPEN-01 | P1 | TLS | Handshake messages are a compact private encoding, not RFC 8446 ClientHello/ServerHello (no legacy_version, cipher_suites, extensions, key_share, supported_versions, SNI, ALPN). Self-interop works; OpenSSL will not parse us. | `lib/src/tls/handshake.dart`. Roadmap 0.2. |
| OPEN-02 | P1 | TLS | Record cipher is AES-256-GCM with an HKDF-**SHA-256** schedule. That is not IANA `TLS_AES_256_GCM_SHA384` (0x1302) and not `TLS_CHACHA20_POLY1305_SHA256` (0x1303). Putting 0x1302 on the wire would be a lie. | `lib/src/tls/key_schedule.dart`. Needs pqforge SHA-384 HKDF or ChaCha sync. |
| OPEN-03 | P1 | TLS / crypto | `PqTransportCrypto(profile: PqForgeProfile.maximum)` selects ML-KEM-1024 + ML-DSA-87 while the live TLS path is sized for ML-KEM-768 + ML-DSA-65. The API lets you construct the inconsistent pair. | `lib/src/core/crypto.dart` vs `pq_tls_client.dart`. Refuse mismatched profile/group. |
| OPEN-04 | P1 | TLS | Certificate is a raw ML-DSA-65 public key, not an X.509 `Certificate` message. | `encodeCertificate` / `decodeCertificate`. |
| OPEN-05 | P2 | TLS | HelloRetryRequest is a counter (`noteHelloRetry`) plus a machine edge. No HRR cookie, no actual HRR flight. | `test/tls/state_machine_test.dart` |
| OPEN-06 | P2 | QUIC | No header protection, no ACK processing, no RFC 9001 TLS-in-QUIC. CRYPTO-frame test uses a 1216-byte **zero** share (size gate, not a live encapsulate). | `lib/src/quic/packet.dart`, `test/quic/quic_test.dart` |
| OPEN-07 | P2 | HTTP | HTTP/2 not implemented. HTTP/3 is frames without QPACK or a QUIC stream mapping. | `lib/src/http/pq_http_client.dart` |
| OPEN-08 | P2 | DNS | Rdata name compression that points into the **outer** message is not resolved (`_DnsReader` on rdata is a fresh buffer). Round-trips of our encoder are fine (we emit uncompressed names). | `lib/src/dns/wire.dart` |
| OPEN-09 | P2 | mDNS / IO | `IoDatagramChannel` does not `joinMulticast` on 224.0.0.251 / ff02::fb. In-memory flood works; real LAN discovery does not. | `lib/src/socket/io_socket.dart` |
| OPEN-10 | P2 | DoH/DoT | `DohExchange` / `DotExchange` are thin adapters. No ALPN `dot`/`h2`, no production URI template. | `lib/src/dns/pq_dns_client.dart` |
| OPEN-11 | P3 | UDP | Public `role` named args on `initiate`/`accept` are unused (deliberate: putting role in HKDF extra desynchronises peers). API noise. | `pq_encrypted_udp_socket.dart` |
| OPEN-12 | P3 | Coverage | ~9.5% of `lib/` unhit: leftover error paths in DNS wire, encrypted UDP, TLS decode, unused `concatInfo`. | `coverage/lcov.info` |

## Blocked on pqforge

| ID | Sev | Summary | What pqforge must export |
|---|---|---|---|
| BLK-01 | P0 for 0.2 NIST groups | No P-256 / P-384 ECDH. `PqEcdsaP256` is a **signature**. `PqClassicalKeyAgreementAlgorithm` is X25519-only. | Byte-oriented `p256SharedSecret` / `p384SharedSecret` (x-coordinate), uncompressed `0x04\|\|X\|\|Y`, reject infinity / all-zero. See [PQFORGE_EXPORTS.md](PQFORGE_EXPORTS.md). |
| BLK-02 | P1 | No RFC 5869 Expand / RFC 8446 Expand-Label. Combined `hkdfSha256` only. | `hkdfExpandSha256`; optionally SHA-384 Extract/Expand. |
| BLK-03 | P2 | No sync ChaCha20-Poly1305 primitive (only `PqForgeSecureSession`). | `chacha20Poly1305Encrypt/Decrypt` matching AES-GCM. |
| BLK-04 | P2 | `PqForgeCombiner` is always `classical \|\| PQ`. Using it for X25519MLKEM768 would reverse the RFC. | Group-aware combiner, **or** leave TLS concat in pqtransport (current). |
| BLK-05 | P3 | FIPS 203 §7.2 modulus check is inside pqcrypto `encapsulate` (throws). No pqforge `Result`/bool **before** encapsulate. | Optional `checkEncapsulationKey` so we can return `illegal_parameter` without catching. |

## Won't fix in 0.1 (honest limits)

| ID | Summary | Why |
|---|---|---|
| LIM-01 | OpenSSL / BoringSSL handshake | Needs OPEN-01 plus a recorded transcript. Milestone, not a default claim. |
| LIM-02 | CMVP / FIPS 140 | Portable Dart library. [CLAIM_BOUNDARY.md](CLAIM_BOUNDARY.md). |
| LIM-03 | Hard constant-time / hard erasure | VM / dart2js / dart2wasm cannot guarantee either. |
| LIM-04 | Browser raw UDP / mDNS | Browsers do not expose generic UDP or multicast. |
| LIM-05 | QUIC 0-RTT | Explicit non-goal. |

## Fixed in 0.1.0

| ID | Component | Summary | Evidence |
|---|---|---|---|
| FIX-01 | Core | SDK pin was the blueprint's stale `>=3.8.0`; both foundations publish `^3.12.0`. | `pubspec.yaml` |
| FIX-02 | Hybrid | Temptation to use `PqForgeCombiner` as the TLS combiner (would put X25519 first). | `hybrid.dart` + combiner-order test |
| FIX-03 | TLS | `late final` application traffic secrets blew up on `deriveApplication` (`LateInitializationError`). | `key_schedule.dart`; handshake test |
| FIX-04 | TLS | Single sequence counter across handshake and application epochs. | `TlsRecordEpoch`; `record_test.dart` |
| FIX-05 | TLS | `PqTlsSocket` dropped post-handshake bytes; handshake did not wait for completion; async `listen` raced. | Serial `_inbox` + completer; `socket_http_test.dart` |
| FIX-06 | UDP | Replay ran **after** AEAD open. | `peekDatagramSequence` then `isDuplicate` |
| FIX-07 | Socket | Broadcast `MemoryByteSocket` dropped send-before-listen. | Buffer until `onListen` |
| FIX-08 | mDNS | Announce targeted 224.0.0.251 but the memory network was unicast-only. | Multicast flood in `MemoryDatagramNetwork` |
| FIX-09 | QUIC | `idle` had no `fatal` edge; illegal-event test could not reach `failed`. | `quicConnMachine` |
| FIX-10 | DNS | NS decoded as `DnsPtr` (type 12 on the way back). | `DnsNs` |
| FIX-11 | Analyze | Example missing `dart:typed_data`; unused import/field. | `dart analyze` clean |
| FIX-12 | UDP | `requireLength` collided with pqforge's same-named helper. | Hide pqforge `requireLength` |
