# RFC completion TODO

Branch: `feat/quic-0rtt-slh`. One pull request.

The bar is another implementation on the wire. An in-memory pair is a
unit test, not completion. No classical fallback, no private header,
no pre-shared connection ID. QUIC included. Issues 50 and 55 stay out
of this list.

## 0. Stop the false Done

- [x] C0. FEATURES, CLAIM_BOUNDARY, and the site protocol pages say
  "self-interop slice" until the section that completes the RFC has
  landed. They do not say Done for a partial row.
- [x] C1. Do not close GitHub issues 50 or 55 from this work.

## 1. QUIC (RFC 9000, 9001, 9002)

- [x] Q1. Transport parameters, both sides. Required CIDs. Idle timeout,
  flow-control limits, stream limits, ack delay, active connection
  id limit. A missing or duplicate required parameter is a connection
  error.
- [x] Q2. Handshake packet protection. ClientHello and ServerHello stay
  in Initial. EncryptedExtensions through Finished move to Handshake
  packets. NewSessionTicket stays in 1-RTT.
- [x] Q3. Coalesced datagrams. A short header packet is last. Retry is
  not coalesced.
- [x] Q4. Server sends HANDSHAKE_DONE once in 1-RTT. The client confirms
  the handshake on that frame.
- [x] Q5. Parse ACK_ECN (0x03). Ignore ECN counts unless a mark was seen.
- [x] Q6. STOP_SENDING, MAX_STREAMS, STREAMS_BLOCKED, NEW_CONNECTION_ID,
  RETIRE_CONNECTION_ID, NEW_TOKEN, PATH_CHALLENGE, PATH_RESPONSE.
  Unknown frame types remain a connection error.
- [x] Q7. DATA_BLOCKED and STREAM_DATA_BLOCKED move the window or are sent
  when the local send is blocked.
- [x] Q8. Stream limits from transport parameters. Excess streams fail.
- [x] Q9. Connection IDs up to the active limit. Retire on request.
- [x] Q10. Retry with the RFC 9001 integrity tag, Version Negotiation,
  stateless reset. Not forced on every handshake.
- [x] Q11. Anti-amplification: three times the bytes received until a
  Handshake packet validates the client address (RFC 9000 §8.1).
  Datagrams stay at or below 1200 bytes until the path is known
  (RFC 9000 §14). Every client Initial datagram is padded to 1200.
  The server discards an Initial carried in a smaller datagram.
- [x] Q12. One QUIC key update. A second update before confirmation fails.
- [x] Q13. PATH_CHALLENGE is answered on the same path. Migration waits
  for a matching PATH_RESPONSE.
- [x] Q14. ECN counts are parsed. This stack does not claim the mark is
  visible on a memory datagram.
- [x] Q15. The resumption ticket remembers the server flow-control limits.
  writeEarly refuses bytes past them.
- [x] Q16. Tests for each frame, a coalesced datagram, Retry, key update,
  and path challenge. The existing suite still passes.

OpenSSL 3.5.9 QUIC is a handshake flight in both directions, not a
completed protocol. `s_client -quic` against `PqQuicConn.server`
(ALPN `h3`). `PqQuicConn.client` against `demos/quic/server`
(ALPN `ossltest`, Retry, ML-DSA-65 checked). Both run from
`tool/interop/openssl/run.sh`. Not `curl --http3`. Not HTTP/3.
BoringSSL 0.20261020.0 is the TLS client, server, and reverse in
`tool/interop/boringssl/run.sh`. That `bssl` has no QUIC transport.
quiche 0.30.0 (`fa0e480`), linked to that BoringSSL, completes the
QUIC handshake both ways and one HTTP/3 GET both ways
(`tool/interop/quiche/run.sh`). X25519MLKEM768,
`TLS_AES_256_GCM_SHA384`, ALPN `h3`, ML-DSA-65 checked. The quiche
client checks the peer certificate. quiche 0.30 encodes static and
literal QPACK only, so that flight leaves the table capacity at 0.
libnghttp3 1.11.0 at capacity 4096 completed a dynamic-table section
both ways. The encoder stream was not empty. quiche stays at 0.
Not `curl --http3`. Not a complete RFC 9114 stack.

## 2. HTTP/2 (RFC 9113, RFC 7541)

- [x] H2-1. Connection and stream windows. WINDOW_UPDATE is applied.
  DATA is not written past the window. Received DATA is answered
  before the peer stalls at 65535. Overflow is FLOW_CONTROL_ERROR.
- [x] H2-2. Enforce MAX_CONCURRENT_STREAMS, MAX_FRAME_SIZE,
  MAX_HEADER_LIST_SIZE, and INITIAL_WINDOW_SIZE.
- [x] H2-3. Stream states: idle, open, half-closed, closed.
- [x] H2-4. close() sends GOAWAY. A stream error sends RST_STREAM.
- [x] H2-5. A second HEADERS block with END_STREAM is trailers.
- [x] H2-6. CONTINUATION follows HEADERS on the same stream with no
  other frames between them.
- [x] H2-7. Tests: body larger than 65535, window overflow, trailer,
  GOAWAY. Push stays off. PRIORITY stays ignored.

## 3. HTTP/3 (RFC 9114, RFC 9204)

Starts after section 1. The session speaks the QUIC from that section.

- [x] H3-1. Control stream: SETTINGS first. GOAWAY, MAX_PUSH_ID, and
  CANCEL_PUSH are legal afterwards and are acted on. They are errors
  on a request stream.
- [x] H3-2. QPACK encoder and decoder streams carry the codec bytes.
  Dynamic table follows the peer limits. A blocked section waits.
- [x] H3-3. Trailers are one HEADERS block after DATA.
- [x] H3-4. A request can be cancelled with RESET_STREAM and STOP_SENDING.
- [x] H3-5. One control, one encoder, one decoder stream. A second is an
  error. Unknown stream types, unknown control frames, and unknown
  request frames are ignored.
- [x] H3-6. Tests: SETTINGS, GOAWAY, dynamic table, trailer, cancel.

## 4. HTTP/1.1 (RFC 9110, RFC 9112)

- [x] H1-1. Decode and send chunked transfer coding, including trailers.
  curl 8 linked to OpenSSL 3.5.9 `--http1.1` reads the chunked body
  `pq-h1` from `PqHttpServer`.
- [x] H1-2. decodeHttp1Request. Reason phrases match the status.
- [x] H1-3. A response split across TLS records is one message.
  `PqTlsSocket.maxRecordPlaintext` splits a send. The in-memory
  client reassembles a 180-byte body sent as 32-byte records
  (`test/tls/socket_http_test.dart`). OpenSSL 3.5.9
  `s_server -max_send_frag 512` (the floor that binary accepts)
  serves a 2048-octet body. Every record ciphertext is at most 529
  octets. `PqHttpClient` reassembles it
  (`tool/interop/openssl/http1_frag_flight.dart`). That flight also
  fragments ServerHello: the ML-KEM share does not fit in 512
  octets. The client buffers a cleartext handshake message until
  it is complete (RFC 8446 §5.1).
- [x] H1-4. Content-Length must match. Two different values fail.
  The same value twice is one length. Both Content-Length and
  chunked is a failure. Obsolete line folding is a failure. A
  chunk extension is ignored (RFC 9112 §7.1.1). A response with
  neither length nor chunked ends when the connection closes.
- [x] H1-5. Honor Connection: close. Kept-alive responses are sequential.
  curl 8.16 linked to OpenSSL 3.5.9, one process and two URLs, reuses
  the connection. A `Connection: close` response is followed by a new
  connection for the next URL. An HTTP/1.1 request with a missing,
  empty, or duplicate Host fails. HTTP/1.0 may omit Host.
- [x] H1-6. Tests for chunked, split records, length mismatch, close.
  Chunked and close are the curl flight. Length mismatch is a unit
  test. Split records are the OpenSSL `-max_send_frag` flight and
  the in-memory test in H1-3.

HTTP/1.0 is parsed and answered by `PqHttpServer` (close unless
`keep-alive`, no chunked, Host optional). RFC 6455 and RFC 7692 run
on the Relic HTTP/1.1 carriage. That test is this package's client.
HTTP/2 and HTTP/3 extended CONNECT can carry one RFC 6455 data
frame in memory (G18). Autobahn, browsers, and `curl wss://` are
not peers here. RFC 7692 stays on this HTTP/1.1 carriage.

## 5. Extensions

- [x] E1. Extended CONNECT (RFC 8441, RFC 9220). `:protocol` is a
  token (RFC 9110 tchar) and only on CONNECT. Extended CONNECT also
  sends `:scheme`, `:path`, and `:authority`. Classic CONNECT stays
  `:method` and `:authority`. The server sends
  SETTINGS_ENABLE_CONNECT_PROTOCOL=1 and rejects a later 0. The
  client does not send that setting. RFC 9220 is quiche 0.30.0
  both ways: CONNECT with `:protocol websocket`, `:scheme https`,
  `:path /pq`, `:authority localhost`, and a 200. The ML-DSA-65
  certificate is checked. RFC 8441 against libnghttp2 1.66.0
  (`h2connect.c`) is CONNECT `:protocol websocket`, status 200,
  END_STREAM clear, ALPN `h2`, X25519MLKEM768, `id-ml-dsa-65`.
  curl 8.23.0 linked to that same nghttp2 and to OpenSSL 3.5.9
  completed one HTTP/2 GET (body `pq-h2`). Its `wss:// --http2`
  sent `GET /tunnel HTTP/1.1` and `Upgrade: websocket`. That is
  not RFC 8441. `h2connect` also sends PRIORITY_UPDATE. See E3.
- [x] E2. QUIC DATAGRAM (RFC 9221) types 0x30 and 0x31. This stack
  advertises `max_datagram_frame_size` 65535. A frame larger than
  that, or a DATAGRAM outside 0-RTT/1-RTT, is PROTOCOL_VIOLATION.
  Frames are ack-eliciting and are not retransmitted. HTTP/3
  datagrams (RFC 9297) carry the quarter stream id.
  SETTINGS_H3_DATAGRAM=1 is sent only after the peer's transport
  parameter is non-zero. A datagram for a stream past the local
  limit is H3_ID_ERROR. A datagram after FIN or RESET is dropped.
  quiche 0.30.0 both ways carries the quarter stream id. Payloads
  are `qd-quiche` and `qd-pq`. A second datagram is not put on
  the wire. The peer waits through loss detection and does not
  receive it. The frame is ack-eliciting. The Capsule Protocol
  parses a DATAGRAM capsule and skips an unknown type. A capsule
  cut off by FIN is H3_DATAGRAM_ERROR. quiche does not parse
  capsules. connect-ip-go v0.6.0 (quic-go v0.63.0, Go 1.27.3)
  parsed ADDRESS_ASSIGN and ROUTE_ADVERTISEMENT from this stack.
  masque-go v0.6.0 completed CONNECT-UDP: one context-ID-0 payload
  forwarded to a local UDP echo and returned. Both peers checked
  the ML-DSA-65 leaf. The reverse was run. A masque-go v0.6.0
  proxy echoed `ping-reverse` (`reverse-udp leaf=mlDsa65
  group=x25519MlKem768 echoed=true quicDatagrams=true`). Its
  response includes `capsule-protocol: ?1`. A connect-ip-go
  v0.6.0 proxy logged `ip-got n=20 src=192.0.2.11
  dst=198.51.100.1 proto=17` and `ip-echo n=20`
  (`reverse-ip` with the same leaf and group). The UDP and IP
  payloads are QUIC DATAGRAMs, not DATAGRAM capsules. DNS_ASSIGN
  and PREF64 are encode/decode only (G24). Not a masque-go flight.
- [x] E3. PRIORITY_UPDATE (RFC 9218), not the old PRIORITY frame.
  HTTP/2 type 0x10 on stream 0. A prioritized stream id of 0, a
  reserved bit, or a payload shorter than 4 octets is an error.
  HTTP/3 types 0xF0700 (request stream id) and 0xF0701 (push id)
  are legal only on the client control stream. On a request stream
  they are H3_FRAME_UNEXPECTED. Push ids are H3_ID_ERROR because
  push is off. The server sends SETTINGS_NO_RFC7540_PRIORITIES=1.
  The old PRIORITY frame is ignored. HTTP/3 is quiche 0.30.0 both
  ways. quiche sends `u=1,i`. This stack sends `u=1, i` and quiche
  returns that field value. HTTP/2 PRIORITY_UPDATE is libnghttp2
  1.66.0 on the extended CONNECT flight:
  `nghttp2_submit_priority_update` with `u=1, i`. This server
  recorded urgency 1, incremental. curl 8.23.0 does not send it.
- [x] E4. Server push stays off. The client sends ENABLE_PUSH=0.
  The server does not send that setting (RFC 9113); a client that
  receives it is a connection error. PUSH_PROMISE is a connection
  error. HTTP/3 rejects a push stream. A client that sends
  ENABLE_PUSH 0 and then 1 is a connection error.
- [x] E5. Multipath is RFC 10069, not RFC 9369. `initial_max_path_id`
  (0x3e) is stored when the value is at most 2^32-1. A larger value
  is a transport parameter error. The endpoint sends 0x3e only when
  `PqQuicConn` is constructed with `initialMaxPathId`. The default
  is null, so existing quiche and OpenSSL flights do not advertise
  it. When both sides send it, PATH_ACK (0x3e–0x3f), PATH_ABANDON
  (0x3e75), PATH_STATUS (0x3e76–0x3e77), PATH_NEW_CONNECTION_ID
  (0x3e78), PATH_RETIRE_CONNECTION_ID (0x3e79), MAX_PATH_ID (0x3e7a),
  PATHS_BLOCKED (0x3e7b), and PATH_CIDS_BLOCKED (0x3e7c) are parsed.
  The same frames before negotiation, or outside 1-RTT, are
  PROTOCOL_VIOLATION. The 1-RTT nonce is the RFC 10069
  path-and-packet-number. Path 0 matches RFC 9001. A zero-length
  connection ID while both sides advertise the parameter is
  PROTOCOL_VIOLATION. Extra paths have their own packet numbers
  and, in memory, their own PTO (G5). The interop job runs
  picoquic 1.1.54.0. It did not offer ML-DSA-65, this server
  refused scheme 0x0905, and `-M` printed `Enable multipath:
  Refused` on one path. That peer is not a completed handshake.
  quiche 0.30.0 has ML-DSA and only RFC 9000 path
  migration. quic-go in the masque tree is RFC 9000 path probing,
  not `initial_max_path_id`. msquic has no multipath release. A
  classical leaf was not minted. noq 1.5.0 (`bb1c63ee`), rustls
  0.23.46 on aws-lc-rs, completed the handshake and established
  path 1. rustls checked the ML-DSA-65 chain. The group is
  X25519MLKEM768 after HelloRetryRequest, because the first
  ClientHello has only an X25519 share. ALPN is `h3`. The client
  sends `initial_max_path_id` 1. This is not every RFC 10069 frame.
  Single-path migration stays in section 1.

## 6. Remaining RFC gaps

Same branch: `fix/0.2.1-psk-coding`. Version stays 0.2.1.
An in-memory pair is not a foreign flight. A peer that cannot speak
the bytes is not closed by a comment. Items under "Do not implement"
are non-goals from [ROADMAP.md](doc/ROADMAP.md) and
[CLAIM_BOUNDARY.md](doc/CLAIM_BOUNDARY.md). Do not code them.

### Started

- [x] G1. Rejected 0-RTT is sent again as 1-RTT (RFC 9000 / RFC 9001).
  Accepted 0-RTT advances the STREAM send offset, so a later
  `writeStream` does not overlap those bytes. `writeEarly` may be
  called again before `start`, including on another client bidi
  stream. `test/quic/early_data_test.dart`.
- [x] G2. HTTP/3 0-RTT. One request on the early bidi stream, accepted
  once. QPACK uses the static table only. The control stream is still
  1-RTT. Replay leaves `earlyData` empty; the same bytes are then read
  as 1-RTT because G1 resends a rejected STREAM. Not `curl --http3`.
  The quiche proof is still the raw STREAM `pq-0rtt` on stream 4.
  `encodeHttp3EarlyRequest`, `PqHttp3Session.writeEarlyRequest`,
  `test/quic/early_data_test.dart`.
- [x] G3. 0-RTT DATAGRAM (RFC 9221) under the same accept / reject /
  replay rule. A rejected datagram is not retransmitted. An empty
  payload is refused by `writeEarlyDatagram`. That is not an RFC 9221
  rule. `test/quic/early_data_test.dart`.
- [x] G4. Unidirectional 0-RTT. `writeEarly` on a client-initiated
  unidirectional stream (id 2) is accepted once, including FIN.
  `openUni` continues at the next id. A server-initiated id is refused.
  A stream past the ticket's `initial_max_streams_uni` is refused.
  Rejected bytes are sent again as 1-RTT, and FIN is kept.
- [x] G5. Per-path PTO (RFC 10069). Path 0 stays on `QuicLossRecovery`.
  A path id above 0 has its own RTT, PTO count, and deadline
  (`QuicPathPto`). A timeout sends one PATH_CHALLENGE and does not
  declare packets lost. Not time-threshold loss. Not every RFC 10069
  frame. No new per-path PTO peer flight. A short header ends a
  datagram (RFC 9000 §12.2), so two 1-RTT packets are not coalesced.
  `test/quic/recovery_test.dart`, `test/quic/resume_gap_test.dart`.
- [x] G6. `commitMigration` after PATH_RESPONSE switches the
  destination connection ID to a peer CID that is not the current
  one. `preferred_address` is not sent. The spin bit stays clear.
  ACK frequency is not sent. `QuicLossRecovery` does not move to the
  new path. `test/quic/resume_gap_test.dart`.
- [x] G7. An ACK whose ECN-CE count rose is a NewReno congestion
  event (RFC 9002). The same recovery round does not cut the window
  again. Packets are not declared lost. Not CUBIC (RFC 9438).
  `test/quic/recovery_test.dart`.
- [x] G8. `QuicEarlyDataStore(ticketKey:)` seals the PSK and the
  limits into the ticket identity (AES-256-GCM). The issuing store
  still accepts 0-RTT once. A new store with the same key resumes
  and refuses 0-RTT. A wrong key does not resume. Not an external
  PSK (RFC 9258). A sealed ticket is not a cross-process anti-replay
  cache: the same blob can resume again. `test/quic/resume_gap_test.dart`.
- [x] G9. More than one PSK identity in `pre_shared_key`. Every binder
  covers one Truncate(ClientHello). The server selects the first
  identity it recognizes whose binder matches. A bad binder on a
  known identity is `decrypt_error`; later identities are not tried.
  Early data is accepted only for index 0, and only when
  `allowEarlyData` is set. `test/quic/resume_gap_test.dart`.

### QUIC, this tree can still do the work

Nothing in this list is still a coding turn. G10 is the next gap,
and it is blocked on a peer.

### Blocked on a peer that does not speak the bytes

- [ ] G10. OpenSSL 3.5.9 QUIC early data. `SSL_write_early_data` does
  not send on a QUIC connection. The OpenSSL flight stays a
  handshake. Do not claim a ticket that this binary cannot resume.
- [ ] G11. `curl --http3`. No curl in this tree speaks QUIC to
  `PqQuicConn`.
- [ ] G12. picoquic 1.1.54.0 multipath. It does not offer ML-DSA-65.
  A classical certificate is not minted. The flight stays a refusal.
- [ ] G13. quiche QPACK dynamic table. quiche 0.30.0 rejects a
  dynamic-table reference. Capacity stays 0 against that peer.
  libnghttp3 1.11.0 at 4096 is the dynamic-table flight. Not nghttp3
  as the HTTP/3 session.
- [ ] G14. BoringSSL SecP256r1MLKEM768 and SecP384r1MLKEM1024. Those
  groups are not in BoringSSL 0.20261020.0.
- [ ] G15. ECH against OpenSSL, ECH with HelloRetryRequest, ECH from
  DNS HTTPS, and GREASE. The flight is BoringSSL plus self-interop,
  X25519MLKEM768, no cleartext retry.
- [ ] G16. `curl wss:// --http2` as RFC 8441. That curl sent
  HTTP/1.1 Upgrade. libnghttp2 1.66.0 is the extended CONNECT peer.
  The in-memory WebSocket data frame is G18. Not Autobahn. Not a
  browser. RFC 7692 permessage-deflate is VM only, on HTTP/1.1.

### Already in this tree, with the limits below

- [x] G17. HTTP/2 PRIORITY_UPDATE is already in-memory
  (`test/http/http2_flow_test.dart`) besides the one libnghttp2
  flight. The old PRIORITY frame stays ignored. Push stays off.
  Not a further coding turn.
- [x] G18. One masked RFC 6455 text frame on HTTP/2 and HTTP/3
  extended CONNECT, in memory, after a 200 that does not end the
  stream. `readData` / `writeData`. Not `curl wss://`. Not
  Autobahn. Not a browser. RFC 7692 stays on the HTTP/1.1
  carriage. `test/http/websocket_connect_test.dart`.
- [x] G19. Optional client certificates. `TlsClientAuth` is a raw
  public-key allow-list. The test uses one key. An empty client
  Certificate is `certificate_required` (alert 116). Not sent on
  PSK resume. Not an X.509 client chain. Not WebPKI.
  `test/tls/gap_slice_test.dart`.
- [x] G20. `compress_certificate` (RFC 8879) is zlib, algorithm 1,
  and only when the ClientHello offers it. Not brotli. Not zstd.
  Not the default ClientHello. The web build has no zlib.
  `test/tls/gap_slice_test.dart`.
- [x] G21. SLH-DSA as TLS CertificateVerify for the 12 IANA schemes
  `0x0911`–`0x091C`. The handshake test is SHA2-128f only. Not the
  default. Not a foreign peer. The TLS record path splits a flight
  that does not fit in one record. The QUIC CRYPTO path is not
  split. mDNS `pqslh=` stays SHA2-128f only.
  `test/tls/gap_slice_test.dart`.
- [ ] G22. `psk_ke`. Parsed and not selected. Resumption stays
  `psk_dhe_ke`. This is not a classical-only fallback. Do not
  select it.
- [ ] G23. ECH together with 0-RTT. Refused. G15 stays the ECH
  bound. Do not accept it.
- [x] G24. DNS_ASSIGN (`0x1ACE79EC`) and PREF64 (`0x274C0FBC`)
  encode and decode. Those types are
  draft-ietf-masque-connect-ip-dns-07 provisional values, not
  stable IANA. An empty capsule withdraws. Service priority 0 is
  refused. `ipv4hint` and `ipv6hint` are refused. Not a masque-go
  flight. CONNECT-UDP and CONNECT-IP stay the v0.6.0 peers.
  `test/http/connect_ip_dns_test.dart`.

### DNS

- [x] G25. `DnsAuthoritativeZone` is an in-memory zone: AA on an
  answer, NODATA, and NXDOMAIN; a referral clears AA and may
  include in-zone glue; REFUSED outside the zone; FORMERR when
  the query is not one question; a CNAME is returned and not
  chased. The AD bit is not set. It does not sign. It is not
  `DnsIterativeResolver`. `test/dns/authoritative_test.dart`.
- [ ] G26. DNSSEC algorithms outside 5, 7, 8, 10, 13, 14, 15, and
  16. NSEC3 iteration ceiling defaults to 0. pqforge does not
  verify the others. Do not pretend it does.
- [ ] G27. DoH over `curl --http3`. DoH and DoT in this tree are
  not that curl.

### Do not implement

- TLS 1.2, ML-KEM-512, standalone ML-KEM-768, X448.
- WebPKI, AIA, OCSP, CT, the system trust store, a chain longer
  than 8.
- A browser raw UDP, mDNS, or QUIC socket.
- CMVP / FIPS 140. Hard constant-time execution. Hard erasure.
- `dart:ffi` or `SecureSocket` on the PQ path.
- A classical-only handshake after a PQ ClientHello.
- `doc/ACHIEVEMENTS.md` must not list handshake protection,
  anti-amplification, ChaCha header protection, or DoH/DoT as
  missing. Those are in this tree. G5, G6, and G7 are in this tree
  with the limits above. G18 through G21, G24, and G25 are in this
  tree with the limits on those rows. Do not restore "ECN does not
  move the window", "extra paths have no separate PTO",
  "compress_certificate is not implemented", or "extended CONNECT
  is not the WebSocket codec" without the limits on those rows.

## Order

Section 0, then 1, then 2, then 3, then 4 and 5. HTTP/2 and HTTP/1
do not wait on QUIC. HTTP/3 does. Section 6 starts at G1. G10
through G16, G22, G23, G26, G27, and the "Do not implement" list
are not coding turns. G17 through G21, G24, and G25 are in this
tree with the limits on those rows.
