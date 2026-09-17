# Features

Last updated: 2026-09-17

Status vocabulary: **Done** (tested), **Partial** (exists, incomplete),
**Fail-closed** (codecs exist; live path refuses), **Not started**.

## Hybrid key exchange (RFC 10024)

| Feature | Status | Notes |
|---|---|---|
| X25519MLKEM768 share encode/decode/combine | Done | ML-KEM first. 1216 / 1120 / 64. |
| SecP256r1MLKEM768 share encode/decode/combine | Done | ECDHE first. Leading `0x04`. 1249 / 1153 / 64. |
| SecP384r1MLKEM1024 share encode/decode/combine | Done | ECDHE first. 1665 / 1665 / 80. |
| Length filter before crypto | Done | `requireLength` + `PqLengthLabel` |
| All-zero classical shared secret rejected | Done | |
| Live X25519MLKEM768 KEX | Done | pqforge X25519 + ML-KEM-768 |
| Live P-256 / P-384 ECDH | Fail-closed | pqforge gap. [PQFORGE_EXPORTS.md](PQFORGE_EXPORTS.md) |

## TLS 1.3

| Feature | Status | Notes |
|---|---|---|
| Client / server state machines | Done | swissarmyknife `StateMachine`; illegal event → `failed` |
| Compact ClientHello / ServerHello | Done | Private encoding, **not** RFC 8446 extensions |
| EncryptedExtensions + Certificate + CertVerify + Finished | Done | Certificate is raw ML-DSA-65 public key |
| AES-256-GCM records (TLSInnerPlaintext style) | Done | Handshake vs application epochs reset sequence |
| Finished verify-data (HMAC-SHA-256) | Done | |
| TLS exporter | Done | Deterministic on a fixture |
| HKDF-SHA-256 schedule | Done | Not SHA-384. Not IANA 0x1302. |
| `PqTlsSocket` over any byte channel | Done | Serialised ingest; applicationData stream |
| HelloRetryRequest on the wire | Partial | Counter + machine edge only |
| SNI, ALPN, supported_versions, key_share extensions | Not started | |
| X.509 / certificate chains | Not started | |
| ChaCha20-Poly1305 records | Not started | Need pqforge sync ChaCha primitive |
| OpenSSL interop | Not started | |

## UDP

| Feature | Status | Notes |
|---|---|---|
| Versioned datagram envelope | Done | `version \|\| hdrLen \|\| header \|\| nonce \|\| ct\|\|tag` |
| AES-256-GCM with AAD-bound sequence | Done | |
| Replay window | Done | Peek sequence **before** AEAD open |
| Send throttling | Done | `Throttler`; `Duration.zero` skips |
| Encrypted session (X25519MLKEM768) | Done | Identical HKDF extra both roles |
| Reliability machine | Partial | States exist; not a full ACK/retransmit protocol |
| P-256 encrypted UDP | Fail-closed | Same ECDH gap |

## DNS / DoH / DoT

| Feature | Status | Notes |
|---|---|---|
| A, AAAA, CNAME, MX, TXT, SRV, CAA, HTTPS, SVCB, OPT, PTR, NS | Done | Round-trip tests |
| Compression pointer cycle rejection | Done | |
| TTL cache (injected clock) | Done | |
| CircuitBreaker around exchange | Done | Opens after `failureThreshold` |
| Resolver failover DoH → DoT → UDP | Partial | Independent clients; skip-on-open |
| DoH POST `application/dns-message` | Partial | `DohExchange` helper, not a full HTTP client |
| DoT length-prefix framing | Partial | `DotExchange` over an already-PQ `PqTransportSocket` |
| DNSSEC (RRSIG/DS verify) | Not started | Types reserved in `lengths.dart` only |
| Compression pointers inside rdata | Partial | Inner reader does not jump into the outer message |

## mDNS

| Feature | Status | Notes |
|---|---|---|
| Probe / announce / browse | Done | In-memory multicast flood |
| ML-DSA-65 signed TXT | Done | `pqsig=` field; mutate fails |
| EventBus announcements | Done | Per-client bus |
| `IoDatagramChannel` multicast join | Not started | Bind/send/receive unicast only |
| SLH-DSA signed records | Not started | Sister profile: archival only, after ML-DSA |

## QUIC / HTTP

| Feature | Status | Notes |
|---|---|---|
| 1-RTT packet protect | Done | No header protection |
| CRYPTO / STREAM / padding-capable frames | Partial | CRYPTO + STREAM encode; no ACK processor |
| Flow control (MAX_DATA / MAX_STREAM_DATA) | Partial | `QuicFlowControl.consume` |
| Connection / stream state machines | Partial | Happy + illegal-event tests |
| TLS in QUIC (RFC 9001) | Not started | |
| 0-RTT | Not started | Explicit non-goal for v1 |
| HTTP/1.1 request/response | Done | |
| HTTP/1.1 GET over `PqTlsSocket` | Done | |
| HTTP/2 | Not started | |
| HTTP/3 frames | Partial | DATA/HEADERS/SETTINGS type bytes; no QPACK |
| Silent h3→h1 downgrade | Refused | `allowDowngrade: false` default |

## Platform

| Feature | Status | Notes |
|---|---|---|
| Web-safe barrel | Done | `package:pqtransport/pqtransport.dart` |
| IO barrel | Done | `package:pqtransport/pqtransport_io.dart` |
| In-memory sockets for tests | Done | Buffer-until-listen; multicast flood |
| Browser raw UDP / mDNS | Not applicable | Browsers do not expose it |

## Crypto claims we do **not** feature

- FIPS 140 / CMVP validation.
- Hard constant-time execution.

- Hard memory erasure (zeroize is best-effort).
- “Production-ready post-quantum TLS” in the OpenSSL sense.
