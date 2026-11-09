# RFC completion TODO

Branch: `feat/quic-0rtt-slh`. One pull request. Five commits, one per
numbered section, pushed only after that section's tests are green.

The bar is the RFC text, a failing-closed test, and claim text that
does not call a slice a complete protocol. Issues 50 and 55 stay out
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
- [x] Q11. Anti-amplification: three times the bytes received until the
  client address is validated. The client Initial is large enough that
  an ML-DSA flight fits under that budget.
- [x] Q12. One QUIC key update. A second update before confirmation fails.
- [x] Q13. PATH_CHALLENGE is answered on the same path. Migration waits
  for a matching PATH_RESPONSE.
- [x] Q14. ECN counts are parsed. This stack does not claim the mark is
  visible on a memory datagram.
- [x] Q15. The resumption ticket remembers the server flow-control limits.
  writeEarly refuses bytes past them.
- [x] Q16. Tests for each frame, a coalesced datagram, Retry, key update,
  and path challenge. The existing suite still passes.

## 2. HTTP/2 (RFC 9113, RFC 7541)

- [ ] H2-1. Connection and stream windows. WINDOW_UPDATE is applied.
  DATA is not written past the window. Received DATA is answered
  before the peer stalls at 65535. Overflow is FLOW_CONTROL_ERROR.
- [ ] H2-2. Enforce MAX_CONCURRENT_STREAMS, MAX_FRAME_SIZE,
  MAX_HEADER_LIST_SIZE, and INITIAL_WINDOW_SIZE.
- [ ] H2-3. Stream states: idle, open, half-closed, closed.
- [ ] H2-4. close() sends GOAWAY. A stream error sends RST_STREAM.
- [ ] H2-5. A second HEADERS block with END_STREAM is trailers.
- [ ] H2-6. CONTINUATION follows HEADERS on the same stream with no
  other frames between them.
- [ ] H2-7. Tests: body larger than 65535, window overflow, trailer,
  GOAWAY. Push stays off. PRIORITY stays ignored.

## 3. HTTP/3 (RFC 9114, RFC 9204)

Starts after section 1. The session speaks the QUIC from that section.

- [ ] H3-1. Control stream: SETTINGS first. GOAWAY, MAX_PUSH_ID, and
  CANCEL_PUSH are legal afterwards and are acted on. They are errors
  on a request stream.
- [ ] H3-2. QPACK encoder and decoder streams carry the codec bytes.
  Dynamic table follows the peer limits. A blocked section waits.
- [ ] H3-3. Trailers are one HEADERS block after DATA.
- [ ] H3-4. A request can be cancelled with RESET_STREAM and STOP_SENDING.
- [ ] H3-5. One control, one encoder, one decoder stream. A second is an
  error. Unknown stream types and unknown request frames are ignored.
- [ ] H3-6. Tests: SETTINGS, GOAWAY, dynamic table, trailer, cancel.

## 4. HTTP/1.1 (RFC 9110, RFC 9112)

- [ ] H1-1. Decode and send chunked transfer coding, including trailers.
- [ ] H1-2. decodeHttp1Request. Reason phrases match the status.
- [ ] H1-3. A response split across TLS records is one message.
- [ ] H1-4. Content-Length must match. Both Content-Length and chunked
  is a failure. Obsolete line folding is a failure.
- [ ] H1-5. Honor Connection: close. Kept-alive responses are sequential.
- [ ] H1-6. Tests for chunked, split records, length mismatch, close.

100-continue, upgrade, and HTTP/1.0 are out of this list.

## 5. Extensions

- [ ] E1. Extended CONNECT (RFC 8441): `:protocol` on HTTP/2 and HTTP/3.
- [ ] E2. QUIC DATAGRAM (RFC 9221) and HTTP/3 datagrams (RFC 9297).
- [ ] E3. PRIORITY_UPDATE (RFC 9218). Not the old PRIORITY frame.
- [ ] E4. Server push stays off. ENABLE_PUSH=0. An unsolicited push is
  a protocol error.
- [ ] E5. Multipath (RFC 9369) is not implemented. `initial_max_path_id`
  is rejected. Single-path migration stays in section 1.

## Order

Section 0, then 1, then 2, then 3, then 4 and 5. HTTP/2 and HTTP/1
do not wait on QUIC. HTTP/3 does.
