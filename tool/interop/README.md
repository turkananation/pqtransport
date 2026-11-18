# Peer interop

These tools talk to other people's stacks. They are not part of the
published library and they do not use `dart:ffi`.

| Tool | Peer | What is proven |
| --- | --- | --- |
| [nghttp2-curl](nghttp2-curl/README.md) | curl linked to libnghttp2 | Live HTTP/2 prior-knowledge DoH POST and GET. Our HPACK, HTTP/2 frames, and RFC 8484 body. |
| [nghttp3-qpack](nghttp3-qpack/README.md) | libnghttp3 1.11.0 | QPACK field section, both directions, static table, encoder stream ingested when present. |
| [openssl](openssl/README.md) | OpenSSL 3.5.9, curl linked to that OpenSSL | Three RFC 10024 groups, raw-pk and X.509 both directions. BoringSSL verifies the OpenSSL leaf. curl does HTTP/1.1 GETs, including a reused connection, `Connection: close`, and `deflate` (zlib, checked by CPython) against `PqHttpServer`. `PqHttpClient` reassembles `s_server -max_send_frag 512`. Not a browser. Not `curl --compressed`. |
| [boringssl](boringssl/README.md) | BoringSSL 0.20261020.0 | X25519MLKEM768 and `TLS_AES_256_GCM_SHA384` only, both directions. ML-DSA-65 chain length 1, one P-256 leaf, ML-DSA-65 raw public key. Not the other two RFC 10024 groups. Not QUIC. Not a browser. |
| [quiche](quiche/run.sh) | quiche 0.30.0 (`fa0e480`), linked to that BoringSSL | QUICv1 handshake both ways, and one HTTP/3 GET both ways. X25519MLKEM768, `TLS_AES_256_GCM_SHA384`, ALPN `h3`, ML-DSA-65 checked. Bodies `pq-h3` and `quiche-h3`. Not `curl --http3`. |
| [masque](masque/README.md) | masque-go v0.6.0 and connect-ip-go v0.6.0 | CONNECT-UDP and CONNECT-IP, both directions. ML-DSA-65 checked by the side that did not mint the leaf. The UDP proxy sets `Capsule-Protocol: ?1` before masque-go flushes. |
| [picoquic](picoquic/README.md) | picoquic 1.1.54.0, tag `v2026.11.16.f557eab`, OpenSSL 3.5.9 | The demo runs, single-path and with `-M`. It does not offer ML-DSA-65. This server sends `unsupported_certificate`. `Enable multipath: Refused`, one client port. Not a completed handshake. |
| [noq](noq/README.md) | noq 1.5.0 (`bb1c63ee`), rustls 0.23.46, aws-lc-rs | QUICv1 handshake and path 1. ML-DSA-65 checked by rustls. X25519MLKEM768 after HelloRetryRequest. ALPN `h3`. `initial_max_path_id` 1. Not every RFC 10069 frame. Not a separate per-path PTO. |

Run all:

```bash
bash tool/interop/run_all.sh
```

CI job `OpenSSL, BoringSSL, and quiche peers` runs that script on every pull
request. A failure there is a wire mismatch, not a skipped test.

## What these tools do not prove

Live `curl --http3` is not in this set. The curl built here is 8.23.0
with nghttp2 and OpenSSL 3.5.9. Its `--version` features include
HTTP2 and do not include HTTP3. picoquic is in this set. The flight
exits 0 only when 1.1.54.0 refuses ML-DSA-65 and does not open a
second path. That refusal is not the multipath claim. The multipath
peer is noq 1.5.0 (`bb1c63ee`): rustls 0.23.46 on aws-lc-rs checks
the ML-DSA-65 chain, the group is X25519MLKEM768 after
HelloRetryRequest, and path 1 is established. A path id above 0 has
its own PTO in memory. That timer was not part of the noq flight.
Not every RFC 10069 frame.

HTTP/3 against quiche is one GET in each direction
(`tool/interop/quiche/run.sh`), plus extended CONNECT, PRIORITY_UPDATE,
and one HTTP datagram with that same peer. That is not a complete
RFC 9114 stack. The nghttp3 tool covers the QPACK bytes. curl
`wss://` is still HTTP/1.1 Upgrade. picoquic runs here and does not
complete the handshake.
