# nghttp3 — QPACK field sections

Round trip of one HTTP/3 field section with libnghttp3 **1.11.0**
(the QPACK implementation used by ngtcp2 and by curl's HTTP/3 builds).

There is no `dart:ffi`. `build.sh` downloads the pinned release,
configures it, and links `qpack_iov.c` against `libnghttp3.so`.
Build output lives in `.build/` and is gitignored.

## What is exchanged

A static-table DoH request, dynamic table capacity 0:

| Name | Value |
| --- | --- |
| `:method` | `POST` |
| `:scheme` | `https` |
| `:authority` | `dns.example` |
| `:path` | `/dns-query` |
| `content-type` | `application/dns-message` |
| `accept` | `application/dns-message` |

Two directions, both required:

1. `QpackCodec.encodeFieldSection` (this package) → `qpack_iov decode`
   (nghttp3). Header lines must match.
2. `qpack_iov encode` (nghttp3) → `QpackCodec.ingestEncoderStream` then
   `decodeFieldSection`. Header lines must match.

`qpack_iov` writes the encoder stream to its own file. Capacity 0
makes that file empty today. The Dart side still ingests it, so a
future nghttp3 that emits a capacity instruction is not dropped on
the floor.

nghttp3's stderr must contain `nghttp3 1.11.0`. That is the library
version, not a string we invent.

## Run

From the repository root. Needs `dart`, `gcc`, `make`, `curl`, and
`tar` (to fetch the release).

```bash
bash tool/interop/nghttp3-qpack/run.sh
```

The first run builds nghttp3. Later runs reuse `.build/bin/qpack_iov`
when the binary and the shared library are both present. Delete
`.build/` to force a rebuild.

`qpack_iov` itself:

```text
qpack_iov decode <section.bin>
qpack_iov encode <headers.txt> <section.bin> <encoder.bin>
```

`headers.txt` is `name<TAB>value` lines, the same shape nghttp3's own
`examples/qpack` tool prints.

## Why this is not `curl --http3`

HTTP/3 has no cleartext prior-knowledge mode. curl's HTTP/3 path is
QUIC plus classical TLS 1.3 (ngtcp2 or quiche). Our QUIC handshake is
hybrid ML-KEM + ML-DSA inside CRYPTO frames. Those two handshakes do
not complete. Shipping a classical TLS just so curl's QUIC stack can
connect would be a different protocol, and it is rejected (LIM-01).

QPACK is the piece nghttp3 owns and the piece our HTTP/3 session
puts in HEADERS frames. This tool checks that piece against the
library. Live HTTP/3 GET/POST over `PqQuicConn` is
`test/http/http3_test.dart`.

## Failure

`ERR_QPACK_FATAL`, `blocked`, or a `cmp` mismatch means the field
section bytes disagree. Do not weaken the compare. Rebuild with a
clean `.build/` before blaming a stale `qpack_iov`.
