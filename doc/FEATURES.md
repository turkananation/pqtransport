# Features

Last updated: 2026-09-17

Status vocabulary: **Done** (tested), **Partial** (exists, incomplete),
**Fail-closed** (codecs exist; live path refuses), **Not started**.

## Hybrid key exchange (RFC 10024)

| Feature | Status | Notes |
| --- | --- | --- |
| X25519MLKEM768 share encode/decode/combine | Done | ML-KEM first. 1216 / 1120 / 64. |
| SecP256r1MLKEM768 share encode/decode/combine | Done | ECDHE first. Leading `0x04`. 1249 / 1153 / 64. |
| SecP384r1MLKEM1024 share encode/decode/combine | Done | ECDHE first. 1665 / 1665 / 80. |
| Length filter before crypto | Done | `requireLength` + `PqLengthLabel` |
| All-zero classical shared secret rejected | Done | |
| Live X25519MLKEM768 KEX | Done | pqforge X25519 + ML-KEM-768 |
| Live SecP256r1MLKEM768 KEX | Done | pqforge P-256 ECDH + ML-KEM-768 (`balanced`) |
| Live SecP384r1MLKEM1024 KEX | Done | pqforge P-384 ECDH + ML-KEM-1024 (`maximum`) |
| Profile / group refuse | Done | `requireGroup` (OPEN-03) |

## TLS 1.3

| Feature | Status | Notes |
| --- | --- | --- |
| Client / server state machines | Done | swissarmyknife `StateMachine`; illegal event → `failed` |
| RFC 8446 ClientHello / ServerHello | Done | `legacy_version` 0x0303, extensions, `key_share`. Compact 0.1 retired. |
| EncryptedExtensions + Certificate + CertVerify + Finished | Done | EE carries RFC 7250 RawPublicKey. Certificate payload is raw ML-DSA-65, negotiated not silent. |
| AES-256-GCM records (TLSInnerPlaintext style) | Done | Handshake vs application epochs reset sequence |
| Finished verify-data | Done | HMAC-SHA-384 for `0x1302`; HMAC-SHA-256 for `0x1303` |
| TLS exporter | Done | Deterministic on a fixture. Hash follows the suite. |
| HKDF-SHA-384 schedule | Done | IANA `TLS_AES_256_GCM_SHA384` (`0x1302`). Default. |
| HKDF-SHA-256 schedule | Done | ChaCha suite (`0x1303`) and UDP |
| `PqTlsSocket` over any byte channel | Done | Serialised ingest; applicationData stream |
| HelloRetryRequest on the wire | Done | Magic random, cookie ext 44, selected_group, ClientHello2 echo, `message_hash`. Once-only. |
| SNI, ALPN, supported_versions, key_share extensions | Done | On ClientHello. ServerHello has supported_versions + key_share. |
| X.509 / certificate chains | Not started | Raw-pk is explicit (OPEN-04). X.509 chains are a later interop extra. |
| ChaCha20-Poly1305 records | Done | IANA `0x1303`. VM, dart2wasm, **and dart2js** via pqforge 0.4.5 Dart engine. |
| OpenSSL interop | Not started | |

## UDP

| Feature | Status | Notes |
| --- | --- | --- |
| Versioned datagram envelope | Done | `version \|\| hdrLen \|\| header \|\| nonce \|\| ct\|\|tag` |
| AES-256-GCM with AAD-bound sequence | Done | |
| Replay window | Done | Peek sequence **before** AEAD open |
| Send throttling | Done | `Throttler`; `Duration.zero` skips |
| Encrypted session (X25519MLKEM768) | Done | Identical HKDF extra both roles |
| Encrypted session (SecP256r1MLKEM768) | Done | Same session install; P-256 ECDH |
| Encrypted session (SecP384r1MLKEM1024) | Done | Requires `PqForgeProfile.maximum` |
| Reliability machine | Partial | States exist; not a full ACK/retransmit protocol |

## DNS / DoH / DoT

| Feature | Status | Notes |
| --- | --- | --- |
| A, AAAA, CNAME, MX, TXT, SRV, CAA, HTTPS, SVCB, OPT, PTR, NS | Done | Round-trip tests |
| Compression pointer cycle rejection | Done | |
| TTL cache (injected clock) | Done | |
| CircuitBreaker around exchange | Done | Opens after `failureThreshold` |
| Resolver failover DoH → DoT → UDP | Partial | Independent clients; skip-on-open |
| DoH POST `application/dns-message` | Partial | `DohExchange` helper, not a full HTTP client |
| DoT length-prefix framing | Partial | `DotExchange` over an already-PQ `PqTransportSocket` |
| DNSSEC (RRSIG/DS verify) | Not started | Types reserved in `lengths.dart` only |
| Compression pointers inside rdata | Done | RFC 1035 §4.1.4 offsets from the start of the message (OPEN-08). |

## mDNS

| Feature | Status | Notes |
| --- | --- | --- |
| Probe / announce / browse | Done | Joins mDNS groups before receive (OPEN-09) |
| ML-DSA-65 signed TXT | Done | `pqsig=` field; mutate fails |
| EventBus announcements | Done | Per-client bus |
| `IoDatagramChannel` multicast join | Done | `224.0.0.251` / `ff02::fb`; family mismatch fails closed |
| SLH-DSA signed records | Not started | Sister profile: archival only, after ML-DSA |

## QUIC / HTTP

| Feature | Status | Notes |
| --- | --- | --- |
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
| --- | --- | --- |
| Web-safe barrel | Done | `package:pqtransport/pqtransport.dart` |
| IO barrel | Done | `package:pqtransport/pqtransport_io.dart` |
| In-memory sockets for tests | Done | Buffer-until-listen; multicast flood |
| Browser raw UDP / mDNS | Not applicable | Browsers do not expose it |

## Crypto claims we do **not** feature

- FIPS 140 / CMVP validation.
- Hard constant-time execution.

- Hard memory erasure (zeroize is best-effort).
- “Production-ready post-quantum TLS” in the OpenSSL sense.
