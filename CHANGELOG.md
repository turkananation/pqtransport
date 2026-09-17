# Changelog

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
- P-256 / P-384 ECDH not performed (pqforge gap). Share codecs only.
- TLS schedule is HKDF-SHA-256, not SHA-384.
- QUIC is 1-RTT packet protect + frames, not a full RFC 9000 stack.
- HTTP/3 is frames, not QPACK.
