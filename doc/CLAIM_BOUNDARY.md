# Claim Boundary

Last updated: 2026-09-17

pqtransport sits **above** pqforge, which sits **above** pqcrypto. This
layer may not invent a stronger claim than the primitive layer has. A
later role (Client Integration) may not upgrade a claim made here.

Sister evidence:

- [`pqcrypto`](https://github.com/turkananation/pqcrypto) — FIPS 203/204/205 primitives and KAT ledger
- [`pqforge`](https://github.com/turkananation/pqforge) — hybrid KEX, AEAD, HKDF, signatures
- Skill: `.grok/skills/pqtransport-distinguished-engineer/references/00-evidence-boundary.md`

## Package floor (verify live before a pub.dev cut)

| Package | Floor | Role |
| --- | --- | --- |
| pqcrypto | 0.4.1 (via pqforge, not a direct dep) | FIPS 203/204/205 primitives, KATs |
| pqforge | **0.4.8** | Hybrid KEX, AEAD (incl. dart2js ChaCha), ChaCha20 keystream for QUIC HP, HKDF, signatures |
| swissarmyknife | **0.1.0** | StateMachine, Result, Cache, CircuitBreaker, Throttler |
| pqtransport | 0.2.0 | Protocol layer |

SDK: **`>=3.12.0 <4.0.0`**. The original blueprint said `>=3.8.0`; both
foundational packages publish `sdk: ^3.12.0`. Do not lower the floor.

## Allowed wording

- "FIPS 203-aligned ML-KEM via package:pqforge / package:pqcrypto with
  checked-in KAT evidence in pqcrypto."
- "FIPS 204-aligned ML-DSA, byte-exact on pqcrypto's checked-in KAT corpus."
- "FIPS 205-aligned SLH-DSA for all 12 parameter sets in pqcrypto 0.4.x"
  (available through pqforge; **not** the default interactive handshake
  signature in pqtransport).
- "TLS 1.3 hybrid groups X25519MLKEM768, SecP256r1MLKEM768, and
  SecP384r1MLKEM1024 as specified by RFC 10024, with unit-tested share
  concatenation." Live KEX in 0.1.0 is **all three RFC 10024 groups**.
  SecP384r1MLKEM1024 requires `PqForgeProfile.maximum`.
- "Pure-Dart transport. No dart:ffi. Cryptography exclusively from pqforge."
- "Best-effort zeroization in Dart."
- "Best-effort side-channel posture in Dart (VM / dart2js / dart2wasm
  cannot guarantee constant-time execution)."
- Handshake interop with OpenSSL 3.5.9 on X25519MLKEM768,
  SecP256r1MLKEM768, and SecP384r1MLKEM1024 in `tool/interop/openssl`.
  raw-pk (2026-10-20): `-enable_server_rpk`, one ML-DSA-65
  SubjectPublicKeyInfo. X.509 (2026-11-01), both directions. Client to
  `s_server`: ML-DSA-65 leaf, chain length 1, caller CA, DNS
  `localhost`. Server: `openssl s_client -verify_return_error` against
  `PqTlsSocket`, ML-DSA-65 on all three groups (chain length 1, and
  chain length 2 on X25519MLKEM768) plus one P-256 leaf
  (`0x0403`) on X25519MLKEM768. KEX stays the hybrid group.
  P-384 uses `PqForgeProfile.maximum`. BoringSSL 0.20261020.0 runs
  `X509_verify_cert` on the OpenSSL leaf, and is a TLS peer on
  X25519MLKEM768 and `TLS_AES_256_GCM_SHA384`, both directions
  (2026-11-01): ML-DSA-65 chain length 1, one P-256 leaf, and ML-DSA-65
  raw public key. The BoringSSL client pins that raw public key. Not
  SecP256r1MLKEM768. Not SecP384r1MLKEM1024. Classical and pure
  ML-KEM-1024, both directions, ML-DSA-65 chain length 1, suite
  `0x1302` (2026-11-01): X25519 (`0x001D`), secp256r1 (`0x0017`),
  secp384r1 (`0x0018`), and MLKEM1024 (`0x0202`), against OpenSSL 3.5.9
  and BoringSSL 0.20261020.0. The default offer is still the hybrid
  share, then X25519. The hybrid is selected when the peer offers it.
  `s_server -groups x25519:secp256r1` finishes on X25519 with no retry.
  A peer that allows only P-256, P-384, or MLKEM1024 gets
  HelloRetryRequest. BoringSSL's HelloRetryRequest carries no cookie;
  that decodes. Not MLKEM512. Not MLKEM768. Not X448. Not TLS 1.2.
  The hybrid raw-pk, P-256 leaf, and chain-length-2 flights are not
  repeated on these four groups. curl linked to this OpenSSL
  completes one X25519MLKEM768 HTTP/1.1 GET with `--cacert` against
  `s_server`, one against `PqTlsSocket`, and one chunked GET against
  `PqHttpServer` (body `pq-h1`). The same curl process then reads
  `/pq` and `/next` on one connection, and opens a second connection
  when the first response is `Connection: close`. `PqHttpClient`
  reads a 2048-octet body from `s_server -max_send_frag 512`. That
  ServerHello is fragmented and reassembled (RFC 8446 §5.1). Not a
  browser. Not WebPKI.
  Not `curl --http3`.

ADR-0014 is implemented for a caller-supplied chain of 1 to 8. There
is no AIA fetch, no system trust store, and no browser flight. A
browser-shaped ClientHello (the certificate-type extension omitted)
is what the X.509 mode sends. A live Chrome handshake is not claimed.

ECH (RFC 9849) is self-interop, and one BoringSSL 0.20261020.0
flight (2026-11-01). The suite is DHKEM(X25519, HKDF-SHA256),
HKDF-SHA256, and AES-128-GCM, via `PqHpke` (pqforge 0.4.10). Both
directions, group X25519MLKEM768, suite `TLS_AES_256_GCM_SHA384`,
ML-DSA-65 chain length 1. The inner name is `localhost`. The public
name is `public.example`. A client given an `EchConfig` fails closed:
`ech_required`, no ClientHelloOuter continuation, and no cleartext
second hello. HelloRetryRequest under ECH is rejected the same way.
A server given an `EchServerConfig` does not resume the outer hello.
A BoringSSL server without the ECH key gets that alert and no second
ClientHello. Not an OpenSSL flight. Not DNS. Not GREASE. Not a browser.

## Forbidden wording

Do not write the invariant-script banned phrases (see
`scripts/check_invariants.sh` in the Distinguished Engineer skill).
Positive claims of module validation, a CMVP listing, hard
constant-time execution, or hard memory erasure are forbidden.

Use instead:

| Do not claim | Use instead |
| --- | --- |
| Module validation under FIPS 140 | "not a FIPS 140 module" |
| A CMVP listing | "no CMVP listing; not claimed" |
| Hard constant-time execution | "best-effort side-channel posture in Dart" |
| Hard memory erasure | "best-effort zeroization" |
| Interoperable with OpenSSL | The sentence above: OpenSSL 3.5.9, the three RFC 10024 groups, plus X25519, secp256r1, secp384r1, and MLKEM1024 as named there. BoringSSL 0.20261020.0 is the hybrid plus those same four groups, as named there. curl is the HTTP/1.1 client against `s_server`, `PqTlsSocket`, and `PqHttpServer` (chunked, keep-alive, `Connection: close`). `PqHttpClient` reassembles `s_server -max_send_frag 512`. Nothing wider. Not `curl --http3`. |

Also forbidden in meaning, even if the substring differs:

- "certified", "FIPS 140 module" as a positive claim.
- "Production-ready post-quantum TLS" in the OpenSSL sense.
- RFC-byte-exact TLS 1.3 interoperability with OpenSSL beyond the
  three hybrid groups, the four fallback groups, and the auth modes in
  the sentence above. BoringSSL is a TLS peer for X25519MLKEM768 and
  those four groups, as named above. Not SecP256r1MLKEM768. Not
  SecP384r1MLKEM1024. A browser handshake is not claimed. WebPKI is
  not claimed.
- Putting IANA `0x1302` on a SHA-256 schedule (that lie is closed: the
  `0x1302` path is SHA-384).
- Web UDP / mDNS / raw QUIC when the target is a browser.

## RFC claim map

| Need | Cite | 0.1.0 honesty |
| --- | --- | --- |
| TLS 1.3 record + handshake + key schedule | RFC 8446 | Schedule structure yes; hellos RFC 8446-shaped; `0x1302` is SHA-384; `0x1303` is SHA-256+ChaCha |
| Hybrid KEX framework in TLS 1.3 | RFC 9954 | Concat is group-dependent; X25519 name order is **not** followed |
| X25519MLKEM768 / SecP256r1MLKEM768 / SecP384r1MLKEM1024 | RFC 10024 | Codecs **and live KEX** for all three |
| PQ/T terminology | RFC 9794 | Hybrid, not PQ-only |
| ML-KEM / ML-DSA / SLH-DSA | FIPS 203 / 204 / 205 | Via pqforge → pqcrypto |
| QUIC | RFC 9000, 9001, 9002 | Self-interop, plus OpenSSL 3.5.9 QUIC handshakes in both directions. Loss detection (§6), PTO, and NewReno (§7, Appendix B) via `QuicLossRecovery`. Flow control (§4) and CONNECTION_CLOSE / drain (§10.2). Transport parameters are exchanged (RFC 9000 §18, RFC 9001 extension 57). A missing or duplicate required connection ID is a connection error. `max_idle_timeout` is sent when the caller set a local idle timeout. Handshake packets use the TLS handshake traffic secrets. ClientHello and ServerHello stay in Initial. EncryptedExtensions through Finished use Handshake protection. NewSessionTicket stays in 1-RTT. The server sends HANDSHAKE_DONE once. The client confirms the handshake on that frame. Coalesced datagrams are accepted. A short header packet is last. Retry is not coalesced. ACK_ECN counts are parsed and are not treated as a mark on a memory datagram. PATH_CHALLENGE is answered with PATH_RESPONSE. One key update is confirmed by an acknowledgement. A second update before that fails. A UDP datagram stays at or below 1200 bytes until the path is known. A client Initial datagram is padded to 1200 bytes. The server discards an Initial carried in a smaller datagram. Until a Handshake packet arrives, the server sends at most three times the bytes it has received. Retry integrity, Version Negotiation, and stateless reset are implemented. Retry is not forced on every handshake. Multipath is not implemented. ChaCha20 header protection is the RFC 9001 §5.4.4 mask (pqforge 0.4.8). 0-RTT is self-interop: a long header in the Application Data packet number space, shared with 1-RTT (RFC 9000 §12.3), not a fourth space. That space's PTO stays disarmed until the handshake is confirmed (RFC 9002 §6.2.1). Early data is replayable. The ticket is single-use and stores the server flow-control limits. `writeEarly` refuses bytes past them. A replay completes the handshake and accepts no early data. Rejected early data is not resent as 1-RTT. ECH together with 0-RTT is refused. The NewSessionTicket `early_data` maximum is `0xffffffff` (RFC 9001 §4.6.1). OpenSSL 3.5.9 `s_client -quic` completes a QUICv1 handshake and verifies an ML-DSA-65 localhost certificate (X25519MLKEM768, ALPN `h3`). `PqQuicConn.client` completes against OpenSSL `demos/quic/server`: Retry, the same ClientHello resent, ALPN `ossltest`, ML-DSA-65 leaf minted by that OpenSSL for DNS `localhost` and checked. quiche 0.30.0 (`fa0e480`), linked to BoringSSL 0.20261020.0, completes a QUICv1 handshake both ways: X25519MLKEM768 only, `TLS_AES_256_GCM_SHA384`, ALPN `h3`, ML-DSA-65, and the quiche client checks the peer certificate. A datagram that carries an Initial may end in trailing zeros (fixed bit clear); those bytes are discarded, which is how that quiche build pads to 1200. Not `curl --http3`. `max_datagram_frame_size` is 65535. DATAGRAM frames (RFC 9221) are ack-eliciting and are not retransmitted. quiche 0.30.0 both ways receives one and does not receive a second that was never sent. `initial_max_path_id` (RFC 10069) is not sent, so multipath is not negotiated and is not claimed. The HTTP/3 GET is the next row. The encrypted UDP handshake is an Initial long header. The client datagram is at least 1200 bytes. A peer opens it with `QuicInitialCodec` from the destination connection ID. Data packets are 1-RTT short headers opened by `QuicPacketCodec`. 0-RTT packets are long headers opened by `QuicZeroRttCodec`. |
| HTTP/2 | RFC 9113, RFC 7541, RFC 7301 | Self-interop on `PqTlsSocket` ALPN `h2`. Connection and stream windows. DATA is not written past the window, and received DATA is answered with WINDOW_UPDATE before a peer stalls at 65535. A window that would pass 2^31-1 is FLOW_CONTROL_ERROR. SETTINGS_MAX_CONCURRENT_STREAMS, SETTINGS_MAX_FRAME_SIZE, SETTINGS_MAX_HEADER_LIST_SIZE, and SETTINGS_INITIAL_WINDOW_SIZE are enforced. Stream states are idle, open, half-closed, and closed. `close` sends GOAWAY. A stream error sends RST_STREAM. A second HEADERS block with END_STREAM is trailers. CONTINUATION stays on the same stream. Push is off. The client sends ENABLE_PUSH=0. The server does not send that setting. Extended CONNECT (RFC 8441) and PRIORITY_UPDATE (RFC 9218) are in-memory. HTTP/3 extended CONNECT and PRIORITY_UPDATE are the quiche flights. The old PRIORITY frame is ignored. Not a complete RFC 9113 stack. Not nghttp2. |
| HTTP/3 | RFC 9114, RFC 9204 | quiche 0.30.0 (`fa0e480`), linked to BoringSSL 0.20261020.0, completes one HTTP/3 GET both ways on ALPN `h3`: X25519MLKEM768, `TLS_AES_256_GCM_SHA384`, ML-DSA-65. The quiche client checks the peer certificate and receives body `pq-h3` for `GET /pq` with header `x-pq: interop`. `PqHttp3Session` against the quiche server receives body `quiche-h3`. QPACK capacity stays 0 because that quiche build rejects a dynamic-table reference. Grease stays on. The in-memory suite still covers one control stream, SETTINGS first, GOAWAY, MAX_PUSH_ID, CANCEL_PUSH, one encoder stream, one decoder stream, trailers, and request cancel. SETTINGS_H3_DATAGRAM=1 is sent only when the peer's `max_datagram_frame_size` is non-zero. The same quiche peer, both ways, completes extended CONNECT (`:protocol websocket`), PRIORITY_UPDATE (`u=1,i` from quiche and `u=1, i` from this stack), and an HTTP datagram (`qd-quiche`, `qd-pq`). A second QUIC DATAGRAM is not sent; quiche does not receive it after loss detection. The Capsule Protocol parses a DATAGRAM capsule and skips an unknown type. quiche does not parse capsules, so that is not claimed. Unknown control-stream frame types are ignored (RFC 9114 §9). Push is off. Not a complete RFC 9114 stack. Not nghttp3. Not `curl --http3`. |
| DNS / EDNS0 / SVCB / DoH / DoT / mDNS / DNSSEC | RFC 1034, 1035, 2181, 2308, 3597, 3225, 4033, 4034, 4035, 5011, 5155, 5702, 6605, 6672, 6891, 7873, 8080, 8198, 9156, 9276, 9460, 8484, 7858, 6762/6763 | Wire plus production DoH and DoT. The stub sets DO and CD, matches the response id, retries truncation over TCP, and retries BADCOOKIE once. The iterative resolver starts from caller-supplied root hints, follows referrals and glue, minimizes qnames, and returns secure, insecure, or bogus. CNAME and DNAME are followed. NSEC and NSEC3 proofs are cached and answer later names in the span. NSEC3 hash algorithm 1 is `PqBytes.sha1`. The iteration field is 0 through 65535. The resolver ceiling defaults to 0. The AD bit is not validation. Algorithms 5, 7, 8, 10, 13, 14, and 15. RSA moduli 1024, 2048, 3072, and 4096. A trust anchor may be a DS set. Algorithm 16 (Ed448) verifies with an empty context. Not an authoritative server. mDNS cache keys are the DNS canonical name. Live `curl --http3` is not claimed. |
| X25519 | RFC 7748 | Via pqforge. Also a whole TLS group (`0x001D`) when the peer does not take the hybrid. |

RFC 10024 note (normative): the group name `X25519MLKEM768` does **not**
follow RFC 9954 §3.2 naming order. Shares and shared secrets are
**ML-KEM then X25519**. Do not "correct" this to match the name.

## Primitive profile (do not invert)

Default enterprise profile is **hybrid**:

| Primitive | Set | Size |
| --- | --- | --- |
| Classical KEX | X25519 (or P-256 / P-384 when that group is selected) | 32-byte ss (P-256 x-coordinate); 48-byte ss (P-384 x-coordinate) |
| Lattice KEM | ML-KEM-768 (balanced) | pk=1184, ct=1088, sk=2400, ss=32 |
| Lattice KEM (maximum / P-384 group) | ML-KEM-1024 | pk=1568, ct=1568, sk=3168, ss=32 |
| Identity signature | ML-DSA-65 | pk=1952, sk=4032, sig=3309 |
| Session key (app UDP) | HKDF-SHA-256 output | 32 bytes |

SLH-DSA is **not** the default interactive handshake signature.
mDNS may carry an optional second TXT field, `pqslh=`, signed with
SLH-DSA-SHA2-128f only (`signTxtArchival` / `verifyTxtArchival`).
The default announce path stays ML-DSA-65 (`signTxt` / `pqsig=`).
The other eleven FIPS 205 sets are not used on this path. TLS
CertificateVerify is not SLH-DSA. A mutated TXT fails closed.

Public keys must be authenticated. ML-KEM alone is not authenticated
transport — TLS certificates / ML-DSA-bound mDNS records / an
out-of-band key id are the authentication story.

## Drift rule

If pub.dev versions, IANA codepoints, or RFC text disagree with a number
in `lib/src/core/lengths.dart` or this folder, **stop**, fetch the live
document, update lengths + docs together, then continue. Silent drift is
a defect.
