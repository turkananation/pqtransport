## Unreleased

### Added

- HTTP/2 on `PqTlsSocket` (OPEN-07 / slice 0.5.3). RFC 9113 preface,
  SETTINGS, HEADERS, DATA, CONTINUATION, PING, WINDOW_UPDATE, GOAWAY.
  RFC 7541 HPACK (static table, dynamic table, Huffman encode/decode).
  ALPN `h2` is selected in EncryptedExtensions (RFC 7301). Default
  ClientHello ALPN stays `http/1.1`. `PqHttpClient.roundTrip` uses
  negotiated ALPN; silent h2→h1 is refused unless `allowDowngrade`.
  HTTP/3 QPACK and QUIC STREAM mapping are **not** in this slice
  (0.5.4).
- `PqTlsClient` / `PqTlsServer` / `PqTlsSocket` take `alpnProtocols`.
  No overlap is `no_application_protocol` (alert 120).
- RFC 9001 TLS-in-QUIC (OPEN-06). Handshake messages travel in CRYPTO
  frames with **no TLS record layer** (`PqTlsClient`/`PqTlsServer`
  `quic: true`, `QuicTlsHandshake`). Live X25519MLKEM768 encapsulate,
  not a zero share.
- QUIC header protection (RFC 9000 §5.4): AES-ECB mask from pqforge
  `aesEncryptBlock` (0.4.6). Short-header 1-RTT (`0x1f`) and Initial
  long-header (`0x0f`). Receive path accepts 1–4 byte packet numbers;
  send defaults to 4 bytes (RFC 9001 A.2).
- QUIC ACK frames + `QuicAckProcessor` (RFC 9000 §19.3).
- Initial secrets from DCID + salt (RFC 9001 §5.2 / Appendix A.1 pin).
  AES-128-GCM via pqforge `aes128GcmEncrypt`. Floor **pqforge ^0.4.6**.
- ChaCha20 QUIC header protection is **not** implemented; 1-RTT ChaCha
  fails closed. 0-RTT remains a non-goal (LIM-05).

### Tests

- RFC 7541 C.2.1–C.2.3, C.3.1–C.3.3 (no Huffman), C.4.1 (Huffman).
  HTTP/2 frame header, SETTINGS, pad overflow. `selectAlpn` overlap
  and fatal miss. Live GET and POST over `PqTlsSocket` with ALPN `h2`.
  Default handshake still selects `http/1.1`. Prefer-h2 refuses silent
  downgrade. HPACK index 0 / truncated int / table-size 4097 fail
  closed.

- RFC 9001 Appendix A.1 Initial secrets; Appendix A.2 client Initial
  packet (HP sample, mask, 1200-byte datagram). FIPS 197 C.1 AES-128
  and C.3 AES-256 blocks (HP). Live CRYPTO ClientHello (non-zero
  share). Initial + 1-RTT HP round trips including 2-byte packet
  numbers; header/tag bit-flips fail. ACK ranges. TLS-in-QUIC
  exporters (X25519 and P-256). Out-of-order and fragmented CRYPTO
  frames reassemble into handshake messages. Initial packets carry
  the live handshake with ≥1200-byte client datagrams; 1-RTT keys
  from TLS application traffic secrets round-trip. ChaCha HP and
  STREAM / ACK-ECN payload types fail closed.

## 0.1.0

### Added

- IANA `TLS_AES_256_GCM_SHA384` (`0x1302`) on the wire (OPEN-02). The
  TLS schedule is HKDF-SHA-384. Finished verify_data is 48 bytes.
  Private-use `0xFF00` is retired (0.1.0 unpublished).
- IANA `TLS_CHACHA20_POLY1305_SHA256` (`0x1303`) (OPEN-13). Client offers
  `0x1302` then `0x1303`. Server prefers `0x1302`. ChaCha records call
  pqforge `chacha20Poly1305Encrypt` / `Decrypt` through `PqTransportCrypto`.
- `TlsCipherSuite` binds Hash and AEAD. `TransportAead` selects AES-GCM or
  ChaCha. UDP stays AES-256-GCM.

- Live **SecP256r1MLKEM768** and **SecP384r1MLKEM1024** TLS and encrypted-UDP
  handshakes via pqforge 0.4.4 P-256 / P-384 ECDH (`PqTransportCrypto.p256*` /
  `p384*` / `classicalKeyGen` / `classicalAgree`). NIST groups no longer
  fail-closed.
- `PqTransportCrypto.requireGroup` — refuses `PqForgeProfile.maximum` with
  ML-KEM-768 groups and `balanced`/`compact` with SecP384r1MLKEM1024 (OPEN-03).
- `PqKemPrimitives.checkEncapsulationKey` before encapsulate; a bad modulus
  is `illegal_parameter` without catching pqcrypto (BLK-05).
- `PqTlsSocket` accepts `HybridGroup`.
- RFC 8446-shaped ClientHello / ServerHello: `legacy_version` 0x0303,
  `legacy_session_id`, `cipher_suites`, `legacy_compression_methods`,
  extensions `supported_versions`, `supported_groups`, `key_share`,
  `signature_algorithms`, SNI, ALPN (OPEN-01). Compact 0.1 hello body is
  retired (0.1.0 unpublished). Cipher on the wire is IANA `0x1302` /
  `0x1303` (OPEN-02, OPEN-13). Private-use `0xFF00` is refused.
- EncryptedExtensions is a real extensions vector carrying RFC 7250
  `server_certificate_type = RawPublicKey` (OPEN-04). Certificate payload
  is still raw ML-DSA-65, but the raw-pk path is **negotiated**, not silent.
  ClientHello offers the same type. Not X.509.
- HelloRetryRequest on the wire (OPEN-05): `random` is
  SHA-256("HelloRetryRequest"), `key_share` is `selected_group` only,
  cookie extension 44 is required. Client echoes the cookie on ClientHello2
  and the transcript uses the RFC 8446 §4.4.1 `message_hash` wrapper.
  Once-only machine edge kept. Same-group handshakes do not emit HRR.
- DNS rdata name compression into the **outer** message (OPEN-08). CNAME /
  NS / PTR / MX / SRV / HTTPS / SVCB names that are RFC 1035 pointers are
  resolved against the full datagram. A truncated rdata name cannot
  consume the next RR. Our encoder still emits uncompressed names.
- `PqDatagramChannel.joinMulticast` / `leaveMulticast` (OPEN-09).
  `IoDatagramChannel` calls `RawDatagramSocket.joinMulticast` on
  `224.0.0.251` / `ff02::fb` (TTL 255 for mDNS). Memory channels record
  membership so flood delivery only hits sockets that joined. `PqMdnsClient.browse`
  and `PqMdnsServer.beginProbe` join both families (`joinMdnsGroups`).
  `beginProbe` is now `Future`. Browsers still have no raw UDP (LIM-04).

### Changed

- Floor is **pqforge ^0.4.5**. Sync ChaCha20-Poly1305 uses that package's
  Dart engine (`DartChacha20.poly1305Aead`), so IANA `0x1303` completes
  on dart2js as well as the VM and dart2wasm. Default ClientHello always
  offers `[0x1302, 0x1303]`. The dart2js protocol guard
  (`transportHasFullWidthInteger`, `chachaUnavailableMessage`,
  `TlsCipherSuite.select(chachaOk:)`, `tlsOfferedCipherSuitesForRuntime`)
  is deleted — capability is `PqSymmetricPrimitives.supportsChaCha20Poly1305`
  (always `true`). Do not wrap a PointyCastle `PlatformException` as `kex`.
- TLS default Hash is SHA-384. SHA-256 remains for UDP HKDF and for the
  ChaCha suite (`0x1303`).
- `hkdfExtract` / `hkdfExpand` now call pqforge RFC 5869 SHA-256 helpers
  (local HMAC loop deleted). Expand-Label stays in TLS. RFC 5869 A.1 pin
  unchanged (BLK-02 SHA-256 half).
- `combineSharedSecret` uses `PqForgeCombiner.concatenateSharedSecrets` after
  length / all-zero checks. TLS still does **not** call `combine()` (BLK-04).
- `PqEncryptedUdpSocket.completeInitiate` parameter renamed
  `responderClassicalPublic` (0.1.0 is unpublished).
- `PqEncryptedUdpSocket.initiate` / `accept` no longer take unused `role`
  named args (OPEN-11). Putting a role string in HKDF extra would
  desynchronise peers; the info string stays `"pqtransport udp-session v1|udp"`.
- Tag `vX.Y.Z` now publishes to pub.dev via GitHub Actions OIDC
  (`.github/workflows/publish.yml`, environment `pub.dev`), matching pqforge.
  The GitHub Release workflow no longer treats pub.dev as a manual step.
  First package upload is still a one-time maintainer `dart pub publish`
  because pub.dev only enables automated publishing after the package exists.

### Tests

- Live P-256 / P-384 TLS and encrypted-UDP handshakes, `requireGroup` refuse
  tests, modulus-corrupted ek → `illegal_parameter`, concat pins against
  pqforge `concatenateSharedSecrets`. RFC 8446 hello structural tests.
  HelloRetryRequest flight, cookie echo, second-HRR fail-closed, live
- Live `0x1302` and `0x1303` handshakes on VM **and dart2js** (no
  platform branch). RFC 8439 §2.8.2 pin through `PqTransportCrypto`.
  Leftover DNS/UDP/TLS error paths (OPEN-12). Foreign-message rdata
  compression pointers (OPEN-08). `joinMulticast` IO loopback + memory
  membership (OPEN-09).

### Baseline release surface

#### Added

- Core length contracts and RFC 10024 hybrid share encode/decode/combine for
  X25519MLKEM768, SecP256r1MLKEM768, and SecP384r1MLKEM1024.
- `PqUdpSocket`, `PqDatagram` AEAD codec, replay window (sequence peek before
  AEAD), `PqEncryptedUdpSocket` (X25519MLKEM768 session).
- `PqTlsClient` / `PqTlsServer` / `PqTlsSocket` with swissarmyknife
  `StateMachine`, ML-DSA-65 CertificateVerify, Finished MAC, TLS exporter,
  handshake vs application record epochs.
- DNS wire codec for A, AAAA, CNAME, MX, TXT, SRV, CAA, HTTPS, SVCB, OPT, PTR,
  NS; `PqDnsClient` with `CircuitBreaker` + TTL `Cache`; DoH/DoT helpers.
- `PqMdnsClient` / `PqMdnsServer` plus optional ML-DSA-65 TXT signatures.
- QUIC 1-RTT packet protect, CRYPTO/STREAM frames, flow control.
- HTTP/1.1 encoder/decoder and HTTP/3 frames; `PqHttpClient.roundTripH1` over
  a completed `PqTlsSocket`.
- In-memory `MemoryByteSocket` / `MemoryDatagramNetwork` (multicast flood on
  224.0.0.251 / ff02::fb) so the stack is easy to consume in tests.

#### Tests

- Analyzer clean. `dart test` covers hybrid concat (all three groups), AEAD
  round-trip, replay-before-open, TLS machines, live X25519MLKEM768 handshake,
  HTTP/1.1 GET over mock TLS, DNS circuit-breaker + TTL cache, mDNS
  probe/announce/browse, ML-DSA-65 TXT, QUIC CRYPTO frames carrying the
  1216-byte share, and `dart:io` UDP bind.

#### Limits (honest)

- No OpenSSL interop fixture yet. Wording is RFC 10024-aligned encoding with
  unit-tested concatenation, not "interoperable with OpenSSL".
- No FIPS 140 module validation claim. Best-effort zeroization only.
- TLS schedule in the initial 0.1.0 snapshot was HKDF-SHA-256; this release
  records the IANA `0x1302` / `0x1303` update above.
- QUIC is 1-RTT packet protect + frames, not a full RFC 9000 stack.
- HTTP/3 is frames, not QPACK.
