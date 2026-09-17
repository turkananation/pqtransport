---
title: Getting Started
description: Add pqtransport to a Dart or Flutter project and run the in-memory hybrid handshake the tests use.
---

## Install

```yaml
dependencies:
  pqtransport: ^0.1.0
  pqforge: ^0.4.3
  swissarmyknife: ^0.1.0
```

```bash
dart pub get
```

## Import

Web-safe barrel (no `dart:io`, no `dart:ffi`):

```dart
import 'package:pqtransport/pqtransport.dart';
```

VM / mobile / desktop datagrams:

```dart
import 'package:pqtransport/pqtransport_io.dart';
```

## First handshake

The same loop the tests use. No OS sockets, no `SecureSocket`.

```dart
final crypto = PqTransportCrypto();
final identity = PqTlsServerIdentity.generate(crypto);
final (a, b) = MemoryByteSocket.pair();
final client = PqTlsSocket.client(a, crypto: crypto);
final server = PqTlsSocket.server(b, crypto: crypto, identity: identity);
await Future.wait([server.handshake(), client.handshake()]);
final key = client.exporter('app', Uint8List(0), 32);
```

## Encrypted UDP

```dart
final net = MemoryDatagramNetwork();
final kem = crypto.kemKeyGen();
final salt = crypto.randomBytes(16);
final a = PqEncryptedUdpSocket(
  raw: PqUdpSocket(channel: net.bind(epA), throttleWindow: Duration.zero),
  crypto: crypto,
);
```

## Good defaults

- Length-filter every share with `requireLength` before crypto.
- Treat `Result<T, PqTransportError>` as the parse/handshake contract.
  Do not `throw` on a truncated record or a bad Finished MAC.
- Fail closed if a NIST-curve group is requested — pqforge 0.4.3 has no
  P-256 / P-384 ECDH.
- Do not put IANA `0x1302` on the wire. The schedule is SHA-256.
- Import `pqtransport_io.dart` only where you need a real NIC.

## Next

- [Architecture](architecture) — barrels, data flow, concat formulas.
- [Hybrid Groups](hybrid) — why order is group-dependent.
- [Cookbook](cookbook) — common patterns.
- [Claim Boundary](claim-boundary) — wording that is allowed.
