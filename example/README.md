# Examples

In-memory, no network. Run from the package root after `dart pub get`.

```bash
dart run example/pq_tls_client.dart
dart run example/encrypted_udp_peer.dart
dart run example/mdns_discovery.dart
```

| File | What it shows |
|---|---|
| `pq_tls_client.dart` | Compact TLS 1.3 hybrid handshake (X25519MLKEM768) and exporter |
| `encrypted_udp_peer.dart` | Encrypted UDP session over `MemoryDatagramNetwork` |
| `mdns_discovery.dart` | Probe + announce; joins mDNS groups on the memory network |

Live IO sockets: `import 'package:pqtransport/pqtransport_io.dart';`
