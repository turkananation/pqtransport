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
| OPEN-02 | P1 | TLS | Record cipher is AES-256-GCM with an HKDF-**SHA-256** schedule. That is not IANA `TLS_AES_256_GCM_SHA384` (0x1302) and not `TLS_CHACHA20_POLY1305_SHA256` (0x1303). Putting 0x1302 on the wire would be a lie. | `lib/src/tls/key_schedule.dart`. pqforge 0.4.4 exported SHA-384 Extract/Expand; the **schedule** is still SHA-256. Do not put 0x1302 on the wire until 0.3.5. |
| OPEN-05 | P2 | TLS | HelloRetryRequest is a counter (`noteHelloRetry`) plus a machine edge. No HRR cookie, no actual HRR flight. | `test/tls/state_machine_test.dart` |
| OPEN-06 | P2 | QUIC | No header protection, no ACK processing, no RFC 9001 TLS-in-QUIC. CRYPTO-frame test uses a 1216-byte **zero** share (size gate, not a live encapsulate). | `lib/src/quic/packet.dart`, `test/quic/quic_test.dart` |
| OPEN-07 | P2 | HTTP | HTTP/2 not implemented. HTTP/3 is frames without QPACK or a QUIC stream mapping. | `lib/src/http/pq_http_client.dart` |
| OPEN-08 | P2 | DNS | Rdata name compression that points into the **outer** message is not resolved (`_DnsReader` on rdata is a fresh buffer). Round-trips of our encoder are fine (we emit uncompressed names). | `lib/src/dns/wire.dart` |
| OPEN-09 | P2 | mDNS / IO | `IoDatagramChannel` does not `joinMulticast` on 224.0.0.251 / ff02::fb. In-memory flood works; real LAN discovery does not. | `lib/src/socket/io_socket.dart` |
| OPEN-10 | P2 | DoH/DoT | `DohExchange` / `DotExchange` are thin adapters. No ALPN `dot`/`h2`, no production URI template. | `lib/src/dns/pq_dns_client.dart` |
| OPEN-11 | P3 | UDP | Public `role` named args on `initiate`/`accept` are unused (deliberate: putting role in HKDF extra desynchronises peers). API noise. | `pq_encrypted_udp_socket.dart` |
| OPEN-12 | P3 | Coverage | leftover error paths in DNS wire, encrypted UDP, TLS decode, unused `concatInfo`. | `coverage/lcov.info` |
| OPEN-13 | P2 | TLS | No ChaCha20-Poly1305 records / IANA `0x1303`. pqforge 0.4.4 exported sync `chacha20Poly1305Encrypt/Decrypt`; not wired into `PqTransportCrypto.aeadSeal` yet. | Roadmap 0.3.6. |

## Blocked on pqforge

None. pqforge **0.4.4** shipped BLK-01 … BLK-05. Remaining crypto work is
**this package**: OPEN-02 (SHA-384 schedule / 0x1302) and OPEN-13 (ChaCha
records / 0x1303). Do not vendor either.

## Won't fix in 0.1 (honest limits)

| ID | Summary | Why |
|---|---|---|
| LIM-01 | OpenSSL / BoringSSL handshake | Needs OPEN-04 (cert) plus a recorded transcript. Hellos are RFC 8446-shaped. NIST live KEX is no longer the blocker. |
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
| OPEN-03 | TLS / crypto | Profile/group mismatch is constructible. | `PqTransportCrypto.requireGroup`; tests in `handshake_test.dart` / `crypto_facade_test.dart`. |
| BLK-01 | TLS / UDP | No P-256 / P-384 ECDH. | pqforge 0.4.4 + live handshakes for all three RFC 10024 groups. |
| BLK-02 | TLS | Local HMAC Expand only. | `hkdfExtract`/`hkdfExpand` call pqforge SHA-256 RFC 5869; A.1 pin kept. SHA-384 **schedule** remains OPEN-02. |
| BLK-04 | Hybrid | Temptation to call `PqForgeCombiner.combine()`. | `concatenateSharedSecrets` after length checks; pin tests; still no `combine()`. |
| BLK-05 | KEM | encapsulate throws on a bad modulus. | `checkEncapsulationKey` → `illegalKemKey` before encapsulate. |
| OPEN-01 | TLS | Compact private hellos. | RFC 8446 ClientHello/ServerHello + extensions. Compact body retired. Cipher `0xFF00`, not IANA `0x1302`. `test/tls/rfc8446_hello_test.dart`. |
| OPEN-04 | TLS | Silent raw ML-DSA cert. | RFC 7250 `server_certificate_type = RawPublicKey` on CH + EncryptedExtensions. Payload still raw ML-DSA-65, not X.509. |
