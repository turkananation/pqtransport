---
title: Peers
description: What OpenSSL, BoringSSL, quiche, curl, nghttp2, and nghttp3 have actually completed against pqtransport 0.2.0.
---

These are the peers CI runs. None of them is a browser, and none of
them is WebPKI. Reproduce a row from the repository root. The first
run builds the peer. Later runs reuse `.build/`.

| Peer | What finished | Run |
| --- | --- | --- |
| OpenSSL 3.5.9 | TLS both directions on X25519MLKEM768, SecP256r1MLKEM768, and SecP384r1MLKEM1024, plus the classical reverse rows. Raw public key and an ML-DSA-65 X.509 chain of 1, plus one chain of 2. QUIC both ways: `s_client -quic` and `demos/quic/server`. Those QUIC flights are handshakes, not HTTP/3. `s_server -max_send_frag 512` serves a 2048-octet HTTP/1.1 body. `PqHttpClient` reassembles it. ServerHello on that flight is fragmented and buffered until complete. | `bash tool/interop/openssl/run.sh` |
| curl, linked to that OpenSSL | HTTP/1.1 with `--cacert`. One GET against `s_server`, one against `PqTlsSocket`, and against `PqHttpServer` a chunked body `pq-h1`, two responses on one connection, and a new connection after `Connection: close`. | The same script. |
| BoringSSL 0.20261020.0 | TLS client, server, and classical reverse. X25519MLKEM768 both directions. Also X25519, secp256r1, secp384r1, and ML-KEM-1024. Not the two NIST hybrid groups. One ECH flight, both directions. A wrong CA is rejected. Not QUIC: this `bssl` has no QUIC transport. | `bash tool/interop/boringssl/run.sh` |
| quiche 0.30.0, linked to that BoringSSL | QUICv1 handshake both ways, and one HTTP/3 GET both ways. X25519MLKEM768, `TLS_AES_256_GCM_SHA384`, ALPN `h3`, ML-DSA-65. The quiche client checks the certificate. Bodies `pq-h3` and `quiche-h3`. Not `curl --http3`. | `bash tool/interop/quiche/run.sh` |
| nghttp2, through curl | Cleartext HTTP/2 DoH POST and GET. RFC 9113 preface, SETTINGS, HEADERS, DATA, and this package's HPACK. | `bash tool/interop/nghttp2-curl/run.sh` |
| nghttp3 1.11.0 | One QPACK field section, both directions, including the DoH static-table request. | `bash tool/interop/nghttp3-qpack/run.sh` |

All of them:

```bash
bash tool/interop/run_all.sh
```

## What a peer row is not

The nghttp2 row is cleartext. curl's TLS is classical, and this
handshake is not. Production DoH over our TLS is `DohClient.h2` or
`DohClient.h3` after ALPN, which the [Cookbook](cookbook) shows.

BoringSSL does not complete SecP256r1MLKEM768 or SecP384r1MLKEM1024.
ECH has no OpenSSL flight. There is no `curl --http3`. OpenSSL 3.5.9
`s_client -quic` does complete a QUICv1 handshake and verifies an
ML-DSA-65 localhost certificate. The reverse also completes:
`PqQuicConn.client` against OpenSSL `demos/quic/server`, ALPN
`ossltest`, after Retry, with that certificate checked. quiche
0.30.0, linked to BoringSSL 0.20261020.0, completes a QUICv1
handshake both ways and one HTTP/3 GET both ways on
X25519MLKEM768 with an ML-DSA-65 certificate checked. The OpenSSL
QUIC flights are not HTTP/3. QUIC 0-RTT is sent to this stack only:
a long header beside the Initial and the 1-RTT short header. A
third-party HTTP/3 client has not completed that path. Early data is
replayable. Extended CONNECT, PRIORITY_UPDATE, and HTTP datagrams
are the quiche 0.30.0 flights, both ways. masque-go v0.6.0
completed CONNECT-UDP, and connect-ip-go v0.6.0 completed
CONNECT-IP, in both directions, with the ML-DSA-65 leaf checked
by the side that did not mint it. The payloads are QUIC DATAGRAMs.
The address and route capsules were parsed in both directions.
The masque-go reverse response did not include `capsule-protocol`.
curl 8.23.0 with nghttp2 1.66.0 completed one HTTP/2 GET. Its
`wss://` request is HTTP/1.1 Upgrade, not extended CONNECT.
libnghttp2 1.66.0 did complete extended CONNECT. Multipath
(RFC 10069) is off unless `initialMaxPathId` is set. picoquic
1.1.54.0 was run and refused the ML-DSA-65 certificate. It is
not claimed.

## Groups the TLS peers selected

Hybrid concatenation is group-dependent. X25519MLKEM768 puts ML-KEM
first. The NIST groups put the ECDHE share first. P-384 needs
`PqForgeProfile.maximum`. The default ClientHello still offers the
hybrid first, then X25519. A peer that offers only X25519, P-256,
P-384, or ML-KEM-1024 gets HelloRetryRequest.

Auth on the OpenSSL and BoringSSL flights is ML-DSA-65. The default
offer is an RFC 7250 raw public key. X.509 is opt-in:
`certificateTypes: [TlsCertificateType.x509]`, chain of 1 to 8, caller
anchors. A signature without that check is not authentication.
`peerAuthenticated` stays false until CertificateVerify succeeds.

## Dart servers

`serveShelf` replaces `shelf_io.serve` plus a `SecurityContext`.
`PqRelicAdapter` replaces Relic's `IOAdapter`. The calls are in the
[Cookbook](cookbook#servers). Serverpod's API server and insights
server still construct a `SecurityContext` inside Serverpod. Passing
this package's adapter to a Relic web server you build yourself is
the path that exists. Inventing a `SecurityContext` that holds an
ML-DSA handshake does not.

`PqRelicAdapter` does not detach the TLS record stream and does not
speak WebSocket. HTTP/3 on that adapter is the same `PqHttpServer`
session the quiche row above talks to, not a second stack.
