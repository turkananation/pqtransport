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
| Client certificate | Slice | Opt-in `TlsClientAuth`: a raw public-key allow-list. An empty client Certificate is `certificate_required` (alert 116). Not sent when the handshake resumes with a PSK. Not an X.509 client chain. Not WebPKI. `test/tls/gap_slice_test.dart` |
| `compress_certificate` | Slice | RFC 8879 algorithm 1 (zlib) only, and only when the ClientHello offers it. Not brotli. Not zstd. Not the default ClientHello. The web build has no zlib. `test/tls/gap_slice_test.dart` |
| SLH-DSA CertificateVerify | Slice | Opt-in. IANA schemes `0x0911`–`0x091C` map to the 12 FIPS 205 sets. The handshake test is SHA2-128f only. Not the default. Not a foreign peer. A TLS record flight that does not fit is split. The QUIC CRYPTO path is not split. mDNS `pqslh=` stays SHA2-128f. `test/tls/gap_slice_test.dart` |

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
| Reliability | Done | Client Initial is a long header padded to 1200 bytes. The server discards a shorter datagram and answers with its own Initial. A peer opens the client packet with the client initial keys and the server packet with the server initial keys, both from the client's destination connection ID. Data is a 1-RTT short header. RFC 9002 loss recovery. An ECN-CE count increase is a NewReno event. Not CUBIC. Not `curl --http3`. |

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
| Iterative resolver | Done | Root hints, referrals, glue, qname minimization, DNAME, secure / insecure / bogus. NSEC and NSEC3 spans are cached. NSEC3 ceiling defaults to 0 and can be raised up to 65535. The AD bit is not validation. This resolver is not `DnsAuthoritativeZone`. |
| SOA and unknown RR | Done | RFC 1035 SOA. RFC 3597 opaque type and rdata. |
| In-memory authoritative zone | Slice | `DnsAuthoritativeZone`. AA on an answer, NODATA, and NXDOMAIN. A referral clears AA and may add in-zone glue. REFUSED is outside the zone or not class IN. FORMERR is a query that is not one question. A CNAME is returned and not chased. The AD bit is not set. The zone does not sign. Not `DnsIterativeResolver`. `test/dns/authoritative_test.dart` |
| Compression pointers inside rdata | Done | RFC 1035 §4.1.4 offsets from the start of the message (OPEN-08). |

## mDNS

| Feature | Status | Notes |
| --- | --- | --- |
| Probe / announce / browse | Done | Joins mDNS groups before receive (OPEN-09). Cache key is the DNS canonical name |
| ML-DSA-65 signed TXT | Done | `pqsig=` field; mutate fails. Default announce path |
| SLH-DSA-SHA2-128f archival TXT | Done | Optional `pqslh=`. Not the default announce path. mDNS stays this one set. TLS CertificateVerify may opt in to the 12 IANA schemes; the handshake test is SHA2-128f and is not the default. `test/mdns/mdns_test.dart` |
| `IoDatagramChannel` multicast join | Done | `224.0.0.251` / `ff02::fb`; family mismatch fails closed |
| TCP `IoTcpSocket` / `IoTcpServer` | Done | Record reassembly is in `PqTlsSocket` (RFC 8446 §5.1) |
| ML-DSA identity PEM | Done | RFC 7468 + RFC 5958 + RFC 9881. No encrypted PKCS#8. |
| EventBus announcements | Done | Per-client bus |

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
| Loss recovery | Done | RFC 9002 §5 RTT, §6 packet/time loss and PTO, §7 NewReno. An ACK whose ECN-CE count rose is a congestion event and does not mark packets lost. Not CUBIC. Lost STREAM and CRYPTO are retransmitted under a new packet number. `test/quic/recovery_test.dart` (OPEN-15). |
| `PqQuicConn` 1-RTT STREAM | Slice | Linked in-memory pair. Handshake packet protection, transport parameters, coalesced datagrams, HANDSHAKE_DONE, and one key update. UDP datagrams stay at or below 1200 bytes. `max_datagram_frame_size` is advertised as 65535 (RFC 9221). DATAGRAM frames are ack-eliciting and are not retransmitted. quiche 0.30.0 both ways receives one HTTP datagram and does not receive a second one that was never sent. `initial_max_path_id` (RFC 10069) is sent only when `initialMaxPathId` is set. The default does not send it, so multipath is not negotiated with quiche or OpenSSL. A peer value above 2^32-1 is a transport parameter error. Frames and the path-id nonce are implemented. A path id above 0 has its own PTO in memory: one PATH_CHALLENGE probe, and that timeout does not declare packets lost. Not every RFC 10069 frame. No new per-path PTO peer flight. The interop job runs picoquic 1.1.54.0 as a client, single-path and with `-M`. Its ClientHello did not offer ML-DSA-65. This server sent unsupported_certificate for signature scheme 2309 (0x0905). The demo printed `Enable multipath: Refused` and used one client port. The handshake did not finish. Picotls in that tree has no ML-DSA. A classical leaf was not minted. noq 1.5.0 (`bb1c63ee`) with rustls 0.23.46 on aws-lc-rs did complete: ML-DSA-65 checked by rustls, X25519MLKEM768 after HelloRetryRequest (the first ClientHello offers only an X25519 share), ALPN `h3`, `initial_max_path_id` 1, and path 1 established (`noq-mp handshake=ok multipath=1 path=1`). That is one second path, not every RFC 10069 frame. The noq flight does not prove the per-path PTO. OpenSSL 3.5.9 `s_client -quic` completes and verifies an ML-DSA-65 localhost certificate. `PqQuicConn.client` completes against OpenSSL `demos/quic/server` (Retry, ALPN `ossltest`, ML-DSA-65 checked). quiche 0.30.0 linked to BoringSSL 0.20261020.0 completes both directions (X25519MLKEM768, ALPN `h3`, ML-DSA-65 checked). Trailing zeros after a long-header packet are discarded. Not `curl --http3`. |
| 0-RTT | Slice | Long header in the Application Data space (RFC 9000 §12.3). The 0-RTT ClientHello sends `psk_key_exchange_modes` with `psk_dhe_ke` before `pre_shared_key` (RFC 8446 §4.2.9). A `pre_shared_key` without that extension is `illegal_parameter`. `psk_ke` is not selected. A selected PSK omits Certificate and CertificateVerify. `resumption_master` is Hash(ClientHello..client Finished). The ticket remembers the server flow-control limits. `writeEarly` refuses bytes past them. A second `writeEarly` before `start` appends, including on a client-initiated unidirectional stream. `fin` is kept when a rejected STREAM is sent again as 1-RTT. One in-memory HTTP/3 request rides the early bidirectional stream (QPACK static table only; the control stream is still 1-RTT). A 0-RTT DATAGRAM is delivered once and is not resent. An accepted flight leaves the send offset after those bytes. quiche 0.30.0 sent `pq-0rtt` on stream 4 once. The same ticket then completed and accepted none. That quiche flight is not an HTTP/3 request. More than one PSK identity may be offered. The server selects the first identity it recognizes whose binder matches. A bad binder on a known identity is `decrypt_error`. Early data is accepted only for index 0. `QuicEarlyDataStore(ticketKey:)` seals the PSK into the identity. A store that did not issue the ticket resumes and refuses 0-RTT. Not an external PSK (RFC 9258). Not `curl --http3`. |
| HTTP/1.1 request/response | Slice | Chunked bodies and trailers, registered reason phrases, obs-fold rejected, Content-Length conflicts rejected. The same Content-Length twice is one length. A chunk extension is ignored. A missing, empty, or duplicate Host on HTTP/1.1 fails. curl linked to OpenSSL 3.5.9 `--http1.1` reads chunked `pq-h1` from `PqHttpServer`, reuses one connection for a second response, and opens a new connection after `Connection: close`. A body split across 32-byte TLS records is one message in the in-memory client. OpenSSL `s_server -max_send_frag 512` serves a 2048-octet body; every record ciphertext is at most 529 octets and `PqHttpClient` reassembles it. That flight also fragments ServerHello (RFC 8446 §5.1). `Expect: 100-continue` is answered with `100 Continue` only while the body is not yet buffered (RFC 9110 §10.1.1). Any other Expect is 417. The client skips a 1xx and keeps reading the final response. Content coding `deflate` is the zlib wrapper (RFC 1950, RFC 9110 §8.4.1.2). curl 8.16.0 linked to OpenSSL 3.5.9, built without libz, saved `Content-Encoding: deflate`. CPython `zlib.decompress` of that body is `pq-deflate`. CPython `zlib.compress` of `pq-in`, sent by that curl, is the body the handler sees. `gzip` is RFC 1952. The same curl saved `Content-Encoding: gzip`. CPython `gzip.decompress` of that body is `pq-gzip`. HTTP/2 and HTTP/3 inflate one request content coding and may encode one response coding from `Accept-Encoding`. The HTTP/2 check is in-memory. Not `curl --compressed`. Not a complete RFC 9112 recipient. |
| HTTP/1.1 GET over `PqTlsSocket` | Slice | One application-data event, plus the chunked `PqHttpServer` flight above. |
| HTTP/2 | Slice | Self-interop. Connection and stream windows, SETTINGS limits, idle/open/half-closed/closed, GOAWAY, RST_STREAM, trailers, CONTINUATION, and 1xx then the final response. PRIORITY_UPDATE on HTTP/2 is still in-memory (RFC 9218). HTTP/3 extended CONNECT and PRIORITY_UPDATE are the quiche flights. The server sends SETTINGS_ENABLE_CONNECT_PROTOCOL and SETTINGS_NO_RFC7540_PRIORITIES. The server does not send ENABLE_PUSH. Push is off. The old PRIORITY frame is ignored. Unknown frame types are ignored (RFC 9113 §5.5). curl 8.23.0 linked to nghttp2 1.66.0 and OpenSSL 3.5.9 completed one HTTPS GET: ALPN `h2`, `using HTTP/2`, `HTTP/2 200`, body `pq-h2`, group X25519MLKEM768, ML-DSA-65 verified by OpenSSL. The same curl's `wss:// --http2` sent `GET /tunnel HTTP/1.1` with `Upgrade: websocket` and did not offer ALPN `h2`. It did not send `:protocol`. That is not RFC 8441. libnghttp2 1.66.0 (`h2connect.c`, the library curl links) sent `CONNECT` with `:protocol websocket` and received 200 with END_STREAM clear: ALPN `h2`, X25519MLKEM768, `id-ml-dsa-65`. That peer is not the curl binary. One in-memory masked RFC 6455 text frame rides extended CONNECT after a 200 that does not end the stream (`test/http/websocket_connect_test.dart`). Not `curl wss://`. Not Autobahn. Not a browser. RFC 7692 stays on the HTTP/1.1 carriage. Not a complete RFC 9113 stack. |
| HTTP/3 + QPACK | Slice | quiche 0.30.0 GET both ways: body `pq-h3` and `quiche-h3`, ML-DSA-65 checked. The same peer, both ways, does extended CONNECT (`:protocol websocket`), PRIORITY_UPDATE (`u=1,i` and `u=1, i`), and an HTTP datagram (`qd-quiche`, `qd-pq`). A dropped QUIC DATAGRAM is not delivered after loss detection. QPACK capacity 0 against that peer. SETTINGS_H3_DATAGRAM=1 is sent only when the peer advertised a non-zero `max_datagram_frame_size`. The Capsule Protocol parses a DATAGRAM capsule and skips an unknown type. connect-ip-go v0.6.0 parsed ADDRESS_ASSIGN and ROUTE_ADVERTISEMENT. masque-go v0.6.0 completed one CONNECT-UDP echo. Both checked ML-DSA-65. The reverse was run. `PqHttp3Session` as the client against a masque-go v0.6.0 proxy echoed `ping-reverse` (`reverse-udp leaf=mlDsa65 group=x25519MlKem768 echoed=true quicDatagrams=true`). The proxy logged `connect-udp target=127.0.0.1:<port>`. The response includes `capsule-protocol: ?1`. The proxy sets that field before `masque.Proxy`, because masque-go v0.6.0 sets it after `HTTPStream` flushes and quic-go then ignores the later `Header.Set`. Against a connect-ip-go v0.6.0 proxy the same client parsed ADDRESS_ASSIGN `192.0.2.11/32` and one ROUTE_ADVERTISEMENT, sent one 20-byte IPv4 packet, and received the swapped reply (`reverse-ip leaf=mlDsa65 group=x25519MlKem768 echoed=true quicDatagrams=true`; proxy `ip-got n=20 src=192.0.2.11 dst=198.51.100.1 proto=17` and `ip-echo n=20`). Payloads are QUIC DATAGRAMs, not DATAGRAM capsules. Unknown control frames are ignored (RFC 9114 §9). Push is off. One in-memory masked RFC 6455 text frame rides extended CONNECT the same way. DNS_ASSIGN (`0x1ACE79EC`) and PREF64 (`0x274C0FBC`) encode and decode only. Those types are draft-ietf-masque-connect-ip-dns-07 provisional values, not stable IANA. An empty capsule withdraws. Service priority 0 is refused. `ipv4hint` and `ipv6hint` are refused. Not a masque-go flight. Not a complete RFC 9114 stack. Not nghttp3. Not `curl --http3`. |
| Shelf / Relic | Slice | `serveShelf` replaces `shelf_io.serve` plus `SecurityContext`. HTTP/1.1 `Request.hijack` takes the connection. `PqRelicAdapter` detaches HTTP/1.1 (`Hijack`) and completes an RFC 6455 opening handshake (`WebSocketUpgrade`), including permessage-deflate on the VM. That carriage test is this package, not a browser. HTTP/2 does not hijack. HTTP/2 and HTTP/3 extended CONNECT can carry one RFC 6455 data frame in memory after a 200 that does not end the stream. That is not `curl wss://`, not Autobahn, and not RFC 7692. Serverpod's API and insights servers still build a `SecurityContext` inside Serverpod. `PqHttpServerConfig` is one listener limit. |
| Silent h2/h3→h1 downgrade | Refused | `allowDowngrade: false` default |

## Platform

| Feature | Status | Notes |
| --- | --- | --- |
| Web-safe barrel | Done | `package:pqtransport/pqtransport.dart` |
| IO barrel | Done | `package:pqtransport/pqtransport_io.dart` |
| Handshake offload | Done | ML-KEM and ML-DSA run on one long-lived VM worker isolate so a Shelf handler is not stuck behind the handshake. The web path is those same functions, in-process, because there is no isolate. The worker wipes its copies of secret inputs. That is not secure erasure. |
| In-memory sockets for tests | Done | Buffer-until-listen; multicast flood |
| Browser raw UDP / mDNS | Not applicable | Browsers do not expose it |

## Crypto claims we do **not** feature

- FIPS 140 / CMVP validation.
- Hard constant-time execution.

- Hard memory erasure (zeroize is best-effort).
- “Production-ready post-quantum TLS” in the OpenSSL sense.
