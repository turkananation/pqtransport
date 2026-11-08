# Examples

In-memory, no network. Run from the package root after `dart pub get`.

```bash
dart run example/pq_tls_client.dart
dart run example/encrypted_udp_peer.dart
dart run example/mdns_discovery.dart
dart run example/dns_validate.dart
```

| File | What it shows |
| --- | --- |
| `pq_tls_client.dart` | Compact TLS 1.3 hybrid handshake (X25519MLKEM768) and exporter |
| `encrypted_udp_peer.dart` | Encrypted UDP session over `MemoryDatagramNetwork` |
| `mdns_discovery.dart` | Probe + announce; joins mDNS groups on the memory network |
| `dns_validate.dart` | Ed25519 DNSSEC: one RRset, a DNSKEY anchor, a DS anchor, a flipped signature |
| `dns_live.dart` | Not run by the command above. Asks a resolver, then `authenticateDns` from the IANA root DS set. Default resolver is 1.1.1.1 and the names are `yardenah.com`, `www.yardenah.com`, and `hardware.yardenah.com`. |

Live IO sockets: `import 'package:pqtransport/pqtransport_io.dart';`
