## Unreleased

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

### Changed

- dart2js fail-closes IANA `0x1303` with `unsupported` (PointyCastle
  Poly1305 needs 64-bit integers). Default ClientHello on that runtime
  offers `0x1302` only. Do not wrap the PointyCastle `PlatformException`
  as `kex`. VM and dart2wasm still complete ChaCha.
- TLS default Hash is SHA-384. SHA-256 remains for UDP HKDF and for the
  ChaCha suite (`0x1303`).
- Floor is **pqforge ^0.4.4**.
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
  X25519→P-256 redirect with matching exporters. Live `0x1302` and
  `0x1303` handshakes. Leftover DNS/UDP/TLS error paths (OPEN-12).

## 0.1.0

### Added

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

### Tests

- Analyzer clean. `dart test` covers hybrid concat (all three groups), AEAD
  round-trip, replay-before-open, TLS machines, live X25519MLKEM768 handshake,
  HTTP/1.1 GET over mock TLS, DNS circuit-breaker + TTL cache, mDNS
  probe/announce/browse, ML-DSA-65 TXT, QUIC CRYPTO frames carrying the
  1216-byte share, and `dart:io` UDP bind.

### Limits (honest)

- No OpenSSL interop fixture yet. Wording is RFC 10024-aligned encoding with
  unit-tested concatenation, not "interoperable with OpenSSL".
- No FIPS 140 module validation claim. Best-effort zeroization only.
- TLS schedule in the 0.1.0 snapshot was HKDF-SHA-256. See Unreleased for
  IANA `0x1302` / `0x1303`.
- QUIC is 1-RTT packet protect + frames, not a full RFC 9000 stack.
- HTTP/3 is frames, not QPACK.
