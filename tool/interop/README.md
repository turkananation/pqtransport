# Peer interop

These tools talk to other people's stacks. They are not part of the
published library and they do not use `dart:ffi`.

| Tool | Peer | What is proven |
| --- | --- | --- |
| [nghttp2-curl](nghttp2-curl/README.md) | curl linked to libnghttp2 | Live HTTP/2 prior-knowledge DoH POST and GET. Our HPACK, HTTP/2 frames, and RFC 8484 body. |
| [nghttp3-qpack](nghttp3-qpack/README.md) | libnghttp3 1.11.0 | QPACK field section, both directions, static table, encoder stream ingested when present. |
| [openssl](openssl/README.md) | OpenSSL 3.5.9, curl linked to that OpenSSL | Three RFC 10024 groups, raw-pk and X.509 both directions. BoringSSL verifies the OpenSSL leaf. curl does two HTTPS GETs. Not a browser. |
| [boringssl](boringssl/README.md) | BoringSSL 0.20261020.0 | X25519MLKEM768 and `TLS_AES_256_GCM_SHA384` only, both directions. ML-DSA-65 chain length 1, one P-256 leaf, ML-DSA-65 raw public key. Not the other two RFC 10024 groups. Not a browser. |

Run all:

```bash
bash tool/interop/run_all.sh
```

CI job `nghttp2/curl and nghttp3 QPACK` runs that script on every pull
request. A failure there is a wire mismatch, not a skipped test.

## What these tools do not prove

Live `curl --http3` is not in this set. The curl on Debian 12 / the
GitHub `ubuntu-latest` image is HTTP/2 only (`nghttp2/…`, no HTTP/3).
A curl that does speak HTTP/3 still completes QUIC with classical
TLS 1.3. This package's QUIC handshake is hybrid ML-KEM + ML-DSA
(RFC 9001 over our TLS). That handshake is LIM-01 until a recorded
peer fixture exists. Do not add a classical TLS fallback to make
`curl --http3` go green.

HTTP/3 framing on our side is covered by `PqHttp3Session` self-interop
in `test/http/http3_test.dart`. The nghttp3 tool covers the QPACK
bytes that curl's HTTP/3 stack would decode.
