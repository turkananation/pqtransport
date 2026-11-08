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
| HelloRetryRequest on the wire | Done | Magic random, cookie ext 44 when we send one, selected_group, ClientHello2 echo, `message_hash`. Once-only. A peer HRR may omit the cookie (BoringSSL does). |
| SNI, ALPN, supported_versions, key_share extensions | Done | ClientHello ALPN default `http/1.1`. EncryptedExtensions carries the selected protocol (RFC 7301). `h2` is selectable. |
| X.509 / certificate chains | Done | Opt-in. pqforge 0.4.9 parses, checks, and path-validates a caller-supplied chain of 1 to 8. No AIA, no system trust store. Raw public key stays the default. |
| ChaCha20-Poly1305 records | Done | IANA `0x1303`. VM, dart2wasm, **and dart2js** via pqforge 0.4.5 Dart engine. |
| OpenSSL 3.5.9 RFC 10024 groups | Done | Three groups. raw-pk unchanged. X.509 client to `s_server` (ML-DSA-65, chain length 1) and `s_client -verify_return_error` against `PqTlsSocket` (ML-DSA-65 chain length 1 on all three, chain length 2 on X25519MLKEM768, one P-256 leaf on X25519MLKEM768). curl `--cacert` one HTTP/1.1 GET against each peer. BoringSSL 0.20261020.0 verifies the OpenSSL leaf, and handshakes X25519MLKEM768 both directions (ML-DSA-65 chain length 1, one P-256 leaf, ML-DSA-65 raw public key). Same two peers, both directions, also finish X25519, secp256r1, secp384r1, and MLKEM1024 with ML-DSA-65 chain length 1. Hybrid stays first. Not MLKEM512. Not MLKEM768. Not the two NIST hybrids on BoringSSL. Not a browser. Not WebPKI. |
| Encrypted Client Hello (RFC 9849) | Done | Self-interop, and BoringSSL 0.20261020.0 both directions on X25519MLKEM768. DHKEM(X25519, HKDF-SHA256) + HKDF-SHA256 + AES-128-GCM via `PqHpke`. `ech_required` on rejection. No cleartext retry. Not HelloRetryRequest. Not an OpenSSL flight. Not DNS. Not a browser. |

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
| Reliability | Done | Client Initial is a long header padded to 1200 bytes. The server discards a shorter datagram and answers with its own Initial. A peer opens the client packet with the client initial keys and the server packet with the server initial keys, both from the client's destination connection ID. Data is a 1-RTT short header. RFC 9002 loss recovery. Not ECN. Not `curl --http3`. |

## DNS / DoH / DoT

| Feature | Status | Notes |
| --- | --- | --- |
| A, AAAA, CNAME, MX, TXT, SRV, CAA, HTTPS, SVCB, OPT, PTR, NS | Done | Round-trip tests |
| Compression pointer cycle rejection | Done | |
| TTL cache (injected clock) | Done | |
| CircuitBreaker around exchange | Done | Opens after `failureThreshold` |
| Resolver failover DoH → DoT → UDP | Done | Independent clients; a failed hop opens its own breaker |
| DoH POST and GET `application/dns-message` | Done | RFC 8484. `DohClient.h2` / `DohClient.h3`. URI template `{?dns}`, unpadded base64url. Wrong media type fails closed. |
| DoT length-prefix framing | Done | RFC 7858. `DotClient` requires ALPN `dot` and reassembles split TCP frames. A non-`dot` ALPN fails closed. |
| nghttp2/curl and nghttp3 QPACK | Done | `tool/interop`. HTTP/2 prior-knowledge DoH via curl. QPACK both ways vs libnghttp3 1.11.0. Not live `curl --http3` (hybrid QUIC vs classical TLS). |
| DNSSEC (RRSIG/DS verify) | Done | Algorithms 5 (RSASHA1), 7 (RSASHA1-NSEC3-SHA1), 8 (RSASHA256), 10 (RSASHA512), 13 (ECDSAP256SHA256), 14 (ECDSAP384SHA384), 15 (Ed25519), and 16 (Ed448), each via pqforge. RSA is PKCS#1, moduli 1024, 2048, 3072, and 4096. A trust anchor may be a DS set. Ed448 is pure RFC 8032 with an empty context. Canonical RDATA order. Zone bit required. 32-bit serial validity. Wildcard owner when `labels` is smaller. DS digests SHA-1, SHA-256, and SHA-384. `test/dns/dnssec_test.dart`, `test/dns/resolve_test.dart`, `test/dns/stub_test.dart` |
| Validating stub | Done | DO bit, CD bit, matching id, TC retry over TCP, BADCOOKIE retry, CNAME chase. |
| Iterative resolver | Done | Root hints, referrals, glue, qname minimization, DNAME, secure / insecure / bogus. NSEC and NSEC3 spans are cached. NSEC3 ceiling defaults to 0 and can be raised up to 65535. The AD bit is not validation. Not an authoritative server. |
| SOA and unknown RR | Done | RFC 1035 SOA. RFC 3597 opaque type and rdata. |
| Compression pointers inside rdata | Done | RFC 1035 §4.1.4 offsets from the start of the message (OPEN-08). |

## mDNS

| Feature | Status | Notes |
| --- | --- | --- |
| Probe / announce / browse | Done | Joins mDNS groups before receive (OPEN-09). Cache key is the DNS canonical name |
| ML-DSA-65 signed TXT | Done | `pqsig=` field; mutate fails |
| EventBus announcements | Done | Per-client bus |
| `IoDatagramChannel` multicast join | Done | `224.0.0.251` / `ff02::fb`; family mismatch fails closed |
| TCP `IoTcpSocket` / `IoTcpServer` | Done | Record reassembly is in `PqTlsSocket` (RFC 8446 §5.1) |
| ML-DSA identity PEM | Done | RFC 7468 + RFC 5958 + RFC 9881. No encrypted PKCS#8. |
| SLH-DSA signed records | Not started | Sister profile: archival only, after ML-DSA |

## QUIC / HTTP

| Feature | Status | Notes |
| --- | --- | --- |
| 1-RTT packet protect | Done | Short-header HP (`0x1f` mask); AES-256-GCM |
| CRYPTO / STREAM / padding-capable frames | Done | CRYPTO + ACK + STREAM decode; offset reassembly + FIN |
| Flow control (MAX_DATA / MAX_STREAM_DATA) | Done | RFC 9000 §4. `flowWindow` is explicit. `test/quic/lifecycle_test.dart` |
| Connection / stream state machines | Done | Idle timeout, CONNECTION_CLOSE, drain, RESET_STREAM. `test/quic/lifecycle_test.dart` |
| TLS in QUIC (RFC 9001) | Done | CRYPTO stream, no TLS records. Initial AES-128-GCM + HP. OPEN-06. |
| Header protection | Done | AES-ECB for Initial and AES 1-RTT. ChaCha20 mask (RFC 9001 §5.4.4) via pqforge 0.4.8 `chacha20`. |
| ACK processing | Done | `QuicAckProcessor` RFC 9000 §19.3. One processor per packet number space feeds `QuicLossRecovery`. |
| Loss recovery | Done | RFC 9002 §5 RTT, §6 packet/time loss and PTO, §7 NewReno. Lost STREAM and CRYPTO are retransmitted under a new packet number. `test/quic/recovery_test.dart` (OPEN-15). |
| `PqQuicConn` 1-RTT STREAM | Done | Linked in-memory pair. `driveLossRecovery` / `bindLossTimer`. Handshake keys are not minted. |
| 0-RTT | Not implemented | LIM-05, issue 55. Permanent. RFC 9000 §12.3 would share the Application Data space with 1-RTT. This stack does not send early data. |
| HTTP/1.1 request/response | Done | |
| HTTP/1.1 GET over `PqTlsSocket` | Done | |
| HTTP/2 | Done | RFC 9113 + RFC 7541 on `PqTlsSocket` (ALPN `h2`). Preface, SETTINGS, HEADERS/DATA, HPACK static+dynamic+Huffman. Slice 0.5.3. |
| HTTP/3 + QPACK | Done | RFC 9114 + RFC 9204 on `PqQuicConn` (ALPN `h3`). Control SETTINGS, bidi HEADERS/DATA, QPACK static+dynamic (B.1–B.5). Slice 0.5.4. Not nghttp3. |
| Silent h2/h3→h1 downgrade | Refused | `allowDowngrade: false` default |

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
