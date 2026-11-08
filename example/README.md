# Examples

In-memory, no network. Run from the package root after `dart pub get`.

```bash
dart run example/pq_tls_client.dart
dart run example/tls13.dart
dart run example/http1.dart
dart run example/http2.dart
dart run example/http3.dart
dart run example/doh.dart
dart run example/dot.dart
dart run example/dns_stub.dart
dart run example/encrypted_udp_peer.dart
dart run example/mdns_discovery.dart
dart run example/dns_validate.dart
```

| File | What it shows |
| --- | --- |
| `pq_tls_client.dart` | Compact TLS 1.3 hybrid handshake and exporter, without a socket |
| `tls13.dart` | `PqTlsSocket`: SNI, ALPN `http/1.1`, CertificateVerify, exporter, one application record |
| `http1.dart` | `roundTrip` HTTP/1.1 GET |
| `http2.dart` | `roundTripH2` on ALPN `h2` |
| `http3.dart` | `PqQuicConn.pair` and `roundTripH3` on ALPN `h3` |
| `doh.dart` | DoH POST and GET, then `PqDnsResolver` |
| `dot.dart` | DoT on ALPN `dot`, 2-byte length prefix |
| `dns_stub.dart` | `lookup` stops at a CNAME. `resolve` follows it. TC is retried over TCP. No DNSSEC |
| `encrypted_udp_peer.dart` | Encrypted UDP session over `MemoryDatagramNetwork` |
| `mdns_discovery.dart` | Probe + announce; joins mDNS groups on the memory network |
| `dns_validate.dart` | Ed25519 DNSSEC: one RRset, a DNSKEY anchor, a DS anchor, a flipped signature |
| `dns_live.dart` | Not run by CI. Asks a resolver, then `authenticateDns` from the IANA root DS set. Default resolver is 1.1.1.1 and the names are `yardenah.com`, `www.yardenah.com`, and `hardware.yardenah.com`. |

Live IO sockets: `import 'package:pqtransport/pqtransport_io.dart';`
