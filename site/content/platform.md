---
title: Platform Support
description: VM, Flutter, and web support for pqtransport. Verified by barrels, not prose.
---

pqtransport targets Dart SDK `>=3.12.0 <4.0.0`. Cryptography is
pure-Dart via pqforge (no `dart:ffi` in this package). Which
**transports** work depends on the barrel and the host.

## Barrels

| Import | Platforms | Provides |
| --- | --- | --- |
| `package:pqtransport/pqtransport.dart` | VM, Flutter, web | TLS, HTTP/1.1–2, DNSSEC, DoH codecs, hybrid, memory sockets, QUIC packet protection |
| `package:pqtransport/pqtransport_io.dart` | Dart VM, Flutter mobile/desktop | Plus `IoDatagramChannel`, `IoTcpSocket`, `IoTcpServer` |

## Matrix

| Capability | VM | Flutter | Web |
| --- | --- | --- | --- |
| In-memory TLS | Yes | Yes | Yes |
| ChaCha20-Poly1305 (`0x1303`) | Yes | Yes | Yes (pqforge 0.4.5 Dart engine). AES-GCM `0x1302` is the default. |
| HTTP/1.1 over that TLS | Yes | Yes | Yes |
| HTTP/2 over that TLS (ALPN `h2`) | Yes | Yes | Yes |
| DNS codec / cache / breaker | Yes | Yes | Yes |
| Encrypted UDP (memory) | Yes | Yes | Yes |
| Encrypted UDP (real NIC) | Yes | Yes | **No** |
| mDNS on a real LAN | Yes (`joinMulticast`) | Yes | **No** |
| DNSSEC validate / iterative resolve | Yes | Yes | Yes. The network send is the caller's |
| QUIC / HTTP/3 | Self-interop on `PqQuicConn`. QPACK field sections also round-trip with nghttp3 1.11.0 | Self-interop | No raw UDP |
| OpenSSL 3.5.9 / BoringSSL 0.20261020.0 | The [Peers](peers) job | Same code | Not a browser |
| `SecureSocket` on PQ path | Not used | Not used | Not used |

Browsers do not expose generic UDP, multicast, or a raw QUIC socket.
Web callers supply a `PqTransportSocket` over whatever byte pipe they
have (WebSocket, a VM sidecar, `MemoryByteSocket` in tests) and run
`PqTlsSocket` on that pipe.
