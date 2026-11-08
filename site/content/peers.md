---
title: Peers
description: What OpenSSL, BoringSSL, curl, nghttp2, and nghttp3 have actually completed against pqtransport 0.2.0.
---

These are the peers CI runs. None of them is a browser, and none of
them is WebPKI. Reproduce a row from the repository root. The first
run builds the peer. Later runs reuse `.build/`.

| Peer | What finished | Run |
| --- | --- | --- |
| OpenSSL 3.5.9 | X25519MLKEM768, SecP256r1MLKEM768, SecP384r1MLKEM1024, both directions. Raw public key and an ML-DSA-65 X.509 chain of 1, plus one chain of 2. Also X25519, secp256r1, secp384r1, and ML-KEM-1024. | `bash tool/interop/openssl/run.sh` |
| curl, linked to that OpenSSL | Two HTTP/1.1 GETs with `--cacert`. One against `s_server`, one against `PqTlsSocket`. | The same script. |
| BoringSSL 0.20261020.0 | X25519MLKEM768 both directions. Also X25519, secp256r1, secp384r1, and ML-KEM-1024. Not the two NIST hybrid groups. One ECH flight, both directions. A wrong CA is rejected. | `bash tool/interop/boringssl/run.sh` |
| nghttp2, through curl | Cleartext HTTP/2 DoH POST and GET. RFC 9113 preface, SETTINGS, HEADERS, DATA, and this package's HPACK. | `bash tool/interop/nghttp2-curl/run.sh` |
| nghttp3 1.11.0 | One QPACK field section, both directions, including the DoH static-table request. | `bash tool/interop/nghttp3-qpack/run.sh` |

All five:

```bash
bash tool/interop/run_all.sh
```

## What a peer row is not

The nghttp2 row is cleartext. curl's TLS is classical, and this
handshake is not. Production DoH over our TLS is `DohClient.h2` or
`DohClient.h3` after ALPN, which the [Cookbook](cookbook) shows.

BoringSSL does not complete SecP256r1MLKEM768 or SecP384r1MLKEM1024.
ECH has no OpenSSL flight. There is no `curl --http3`. QUIC 0-RTT
is sent to this stack only: a long header beside the Initial and
the 1-RTT short header. A third-party HTTP/3 client has not completed
that path. Early data is replayable.

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
