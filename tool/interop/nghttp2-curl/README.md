# nghttp2 / curl — cleartext HTTP/2 DoH

Live DNS-over-HTTPS against the HTTP/2 stack inside curl, which is
libnghttp2. No fixtures checked in. Each run builds a DNS query with
this package, serves it with this package's HTTP/2 and HPACK codecs,
and checks the bytes curl writes back.

## What curl actually does

`curl --http2-prior-knowledge` opens a TCP connection and speaks
RFC 9113 immediately (the `PRI * HTTP/2.0` preface, SETTINGS,
HEADERS, DATA). That path is nghttp2. The script refuses to start
if `curl --version` does not contain `nghttp2/`.

TLS is not on this path. Our `PqTlsSocket` handshake is hybrid
post-quantum. curl speaks classical TLS. Prior knowledge is the
honest interop: the bytes after the handshake, which is what
nghttp2 owns. Production DoH over our own TLS is
`DohClient.h2` / `DohClient.h3` in `test/dns/doh_dot_test.dart`.

## Run

From the repository root, with `dart` and `curl` on `PATH`:

```bash
bash tool/interop/nghttp2-curl/run.sh
```

The script:

1. Writes a query for `curl.example.` (id `0x4411`) and the expected
   answer (A `9.9.9.9`, TTL 15) via `doh_fixture.dart`.
2. Starts `h2c_doh_server.dart`, which binds `127.0.0.1:0` and prints
   `ready <port>`.
3. `curl --http2-prior-knowledge` POST `application/dns-message` to
   `/dns-query`.
4. The same curl GET `?dns=` unpadded base64url (RFC 8484).
5. Compares both bodies to the answer fixture and requires
   `content-type: application/dns-message`.

Exit 0 prints `nghttp2/curl DoH POST and GET ok`. Any other exit is a
failure. Server stderr is printed when curl fails.

`PQ_H2C_TRACE=1` makes the server log each HTTP/2 frame type, flags,
stream id, and payload length. Use that when a frame is rejected.

## Server behaviour

`h2c_doh_server.dart` is a one-connection-at-a-time peer, not a
product:

- Checks the 24-byte connection preface.
- Sends a SETTINGS frame and ACKs the peer's SETTINGS.
- ACKs PING. Ignores WINDOW_UPDATE, PRIORITY, and unknown frames.
- Strips HEADERS padding and the optional priority block before HPACK.
- Accepts POST (body) and GET (`dns` query) through `dohQueryFromRequest`.
- Answers with `dohResponse` (status 200, `cache-control: max-age=0`).
- Drains the socket before `close`. Closing with unread bytes makes
  Linux reset the connection, which curl reports as error 56.

Default is two requests (the POST and the GET). Pass a count as the
only argument to serve more.

## Not covered

- TLS, ALPN, or certificates. See the DoT / DoH self-interop tests.
- HTTP/3. See [../nghttp3-qpack/README.md](../nghttp3-qpack/README.md).
- Loss, flow-control stalls, or concurrent streams. One request per
  connection is enough to prove the frame and HPACK bytes.
