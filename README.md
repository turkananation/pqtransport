# pqtransport

[![CI](https://github.com/turkananation/pqtransport/actions/workflows/ci.yml/badge.svg)](https://github.com/turkananation/pqtransport/actions/workflows/ci.yml)
[![CodeQL](https://github.com/turkananation/pqtransport/actions/workflows/codeql.yml/badge.svg)](https://github.com/turkananation/pqtransport/actions/workflows/codeql.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Dart SDK](https://img.shields.io/badge/SDK-%3E%3D3.12.0-0175C2.svg)](https://dart.dev)
[![pub package](https://img.shields.io/pub/v/pqtransport.svg)](https://pub.dev/packages/pqtransport)

Pure-Dart post-quantum transport: UDP, TLS 1.3 hybrid key exchange
(RFC 10024), DNS/DoH/DoT, mDNS, QUIC, and HTTP/1.1–3.

Cryptography is exclusively [`package:pqforge`](https://pub.dev/packages/pqforge).
Infrastructure is exclusively [`package:swissarmyknife`](https://pub.dev/packages/swissarmyknife).
There is no `dart:ffi` and no platform TLS (`SecureSocket`) on the PQ path.

This is **not** a FIPS 140 module. Side-channel resistance and
zeroization in Dart are best-effort. ML-KEM/ML-DSA evidence lives in
`package:pqcrypto` (via pqforge).

Documentation (architecture, features, bugs, tracker, roadmap):
[`doc/INDEX.md`](doc/INDEX.md).
Site: [turkananation.github.io/pqtransport](https://turkananation.github.io/pqtransport/).

## Hybrid groups (RFC 10024)

| Group | Codepoint | Client | Server | Shared secret | Order |
|---|---|---|---|---|---|
| X25519MLKEM768 | 0x11EC | 1216 | 1120 | 64 | **ML-KEM then X25519** |
| SecP256r1MLKEM768 | 0x11EB | 1249 | 1153 | 64 | ECDHE then ML-KEM |
| SecP384r1MLKEM1024 | 0x11ED | 1665 | 1665 | 80 | ECDHE then ML-KEM |

Live handshake (KEM + X25519 + ML-DSA-65 + AES-256-GCM records) is implemented
for **X25519MLKEM768**. The NIST-curve groups have byte-exact share codecs;
pqforge does not yet export P-256/P-384 ECDH, so those handshakes fail closed
rather than silently dropping to classical.

TLS record protection uses AES-256-GCM via pqforge and an HKDF-SHA-256
schedule (pqforge does not export HKDF-SHA-384, so IANA `TLS_AES_256_GCM_SHA384`
is not claimed). Concatenation is RFC 10024-aligned and unit-tested — this
release does **not** claim OpenSSL interop.

## Install

```yaml
dependencies:
  pqtransport: ^0.1.0
  pqforge: ^0.4.3
  swissarmyknife: ^0.1.0
```

```dart
import 'package:pqtransport/pqtransport.dart';
```

IO datagrams / multicast: `import 'package:pqtransport/pqtransport_io.dart';`

## Consume

In-memory TLS 1.3 hybrid handshake (the same path the tests use):

```dart
final crypto = PqTransportCrypto();
final identity = PqTlsServerIdentity.generate(crypto);
final (a, b) = MemoryByteSocket.pair();
final client = PqTlsSocket.client(a, crypto: crypto);
final server = PqTlsSocket.server(b, crypto: crypto, identity: identity);
await Future.wait([server.handshake(), client.handshake()]);
final key = client.exporter('app', Uint8List(0), 32);
```

Encrypted UDP session:

```dart
final net = MemoryDatagramNetwork();
final kem = crypto.kemKeyGen();
final salt = crypto.randomBytes(16);
final a = PqEncryptedUdpSocket(
  raw: PqUdpSocket(channel: net.bind(epA), throttleWindow: Duration.zero),
  crypto: crypto,
);
final flight = await a.initiate(
  peerKemPublicKey: kem.publicKey,
  deploymentSalt: salt,
);
```

## Tests

```bash
dart test
bash tool/check_invariants.sh .
```

`dart analyze` is clean. **93 tests**, **90.5% line coverage** of `lib/`.
Gates: hybrid concat (all three groups), AEAD round-trip, replay-before-open,
TLS state machines, live X25519MLKEM768 handshake, HTTP/1.1 GET over
`PqTlsSocket`, DNS circuit-breaker + TTL cache, mDNS probe/announce/browse,
ML-DSA-65 TXT, QUIC CRYPTO frames carrying the 1216-byte share, `dart:io` UDP.

## Documentation

Canonical root: [`doc/INDEX.md`](doc/INDEX.md).

| Document | Purpose |
|---|---|
| [doc/ACHIEVEMENTS.md](doc/ACHIEVEMENTS.md) | What 0.1.0 shipped, with evidence |
| [doc/ARCHITECTURE.md](doc/ARCHITECTURE.md) | Layout, concat, TLS/UDP data flow |
| [doc/FEATURES.md](doc/FEATURES.md) | Done / partial / fail-closed / not started |
| [doc/API.md](doc/API.md) | Public types and consume examples |
| [doc/BUGS.md](doc/BUGS.md) | OPEN / BLK / LIM / FIX |
| [doc/TRACKER.md](doc/TRACKER.md) | Canonical tracker |
| [doc/ROADMAP.md](doc/ROADMAP.md) | 0.2 → 0.5, order is not optional |
| [doc/PQFORGE_EXPORTS.md](doc/PQFORGE_EXPORTS.md) | APIs pqforge must grow |
| [doc/CLAIM_BOUNDARY.md](doc/CLAIM_BOUNDARY.md) | Allowed vs forbidden wording |

## Sister packages

| Package | Role |
|---|---|
| [pqcrypto](https://github.com/turkananation/pqcrypto) | ML-KEM / ML-DSA / SLH-DSA primitives and KATs |
| [pqforge](https://github.com/turkananation/pqforge) | Hybrid crypto workflows this package consumes |
| [swissarmyknife](https://github.com/turkananation/swissarmyknife) | `Result`, `StateMachine`, `CircuitBreaker`, `Cache` |

## License

MIT. See [LICENSE](LICENSE).
