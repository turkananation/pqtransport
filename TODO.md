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

100-continue, upgrade, and HTTP/1.0 are out of this list.

## 5. Extensions

- [x] E1. Extended CONNECT (RFC 8441, RFC 9220). `:protocol` is a
  token (RFC 9110 tchar) and only on CONNECT. Extended CONNECT also
  sends `:scheme`, `:path`, and `:authority`. Classic CONNECT stays
  `:method` and `:authority`. The server sends
  SETTINGS_ENABLE_CONNECT_PROTOCOL=1 and rejects a later 0. The
  client does not send that setting. RFC 9220 is quiche 0.30.0
  both ways: CONNECT with `:protocol websocket`, `:scheme https`,
  `:path /pq`, `:authority localhost`, and a 200. The ML-DSA-65
  certificate is checked. RFC 8441 is still in-memory. The curl
  in this tree has no nghttp2.
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
  capsules, so that protocol is not claimed. CONNECT-UDP (RFC 9298)
  and CONNECT-IP (RFC 9484) are implemented on top of it. Context
  ID 0 only. No foreign MASQUE peer has completed, so neither is
  claimed. Draft DNS/PREF64 capsules and CONNECT-ETHERNET are not
  implemented.
- [x] E3. PRIORITY_UPDATE (RFC 9218), not the old PRIORITY frame.
  HTTP/2 type 0x10 on stream 0. A prioritized stream id of 0, a
  reserved bit, or a payload shorter than 4 octets is an error.
  HTTP/3 types 0xF0700 (request stream id) and 0xF0701 (push id)
  are legal only on the client control stream. On a request stream
  they are H3_FRAME_UNEXPECTED. Push ids are H3_ID_ERROR because
  push is off. The server sends SETTINGS_NO_RFC7540_PRIORITIES=1.
  The old PRIORITY frame is ignored. HTTP/3 is quiche 0.30.0 both
  ways. quiche sends `u=1,i`. This stack sends `u=1, i` and quiche
  returns that field value. HTTP/2 PRIORITY_UPDATE is still
  in-memory.
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
  PROTOCOL_VIOLATION. Extra paths have their own packet numbers.
  They do not have a separate PTO. No picoquic flight has completed,
  so multipath is not claimed. Single-path migration stays in
  section 1.

## Order

Section 0, then 1, then 2, then 3, then 4 and 5. HTTP/2 and HTTP/1
do not wait on QUIC. HTTP/3 does.
