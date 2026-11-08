---
title: Getting Started
description: Add pqtransport to a Dart or Flutter project and run the in-memory hybrid handshake the tests use.
---

## Install

```yaml
dependencies:
  pqtransport: ^0.2.0
  pqforge: ^0.4.13
  swissarmyknife: ^0.1.0
```

```bash
dart pub get
dart run example/tls13.dart
dart run example/http1.dart
dart run example/http2.dart
dart run example/http3.dart
dart run example/doh.dart
dart run example/dot.dart
dart run example/dns_stub.dart
dart run example/dns_validate.dart
dart run example/encrypted_udp_peer.dart
dart run example/mdns_discovery.dart
```

Each file is one protocol, in memory, and prints one line. `dns_stub.dart` does not check signatures. `dns_validate.dart` does. `example/dns_live.dart` is the network one: it asks 1.1.1.1 and then checks `yardenah.com` from the IANA root DS set. The comment at the top of each file says which call not to use.

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
final aEp = const PqEndpoint('127.0.0.1', 4242);
final bEp = const PqEndpoint('127.0.0.1', 4243);
final a = PqEncryptedUdpSocket(
  raw: PqUdpSocket(channel: net.bind(aEp), throttleWindow: Duration.zero),
  crypto: crypto,
);
final b = PqEncryptedUdpSocket(
  raw: PqUdpSocket(channel: net.bind(bEp), throttleWindow: Duration.zero),
  crypto: crypto,
);
final kem = crypto.kemKeyGen();
final salt = crypto.randomBytes(16);
final flight = (await a.initiate(
  peerKemPublicKey: kem.publicKey,
  deploymentSalt: salt,
)).valueOrNull!;
final reply = (await b.accept(
  kemSecretKey: kem.secretKey,
  initiatorFlight: flight,
  deploymentSalt: salt,
)).valueOrNull!;
await a.completeInitiate(responderClassicalPublic: reply);
await a.send(Uint8List.fromList('hello'.codeUnits), bEp);
```

The other protocols, including the server half of HTTP and DoH, are
the [Cookbook](cookbook).

## Good defaults

- Length-filter every share with `requireLength` before crypto.
- Treat `Result<T, PqTransportError>` as the parse/handshake contract.
  Do not `throw` on a truncated record or a bad Finished MAC.
- NIST-curve groups are live via pqforge 0.4.5. SecP384r1MLKEM1024
  requires `PqForgeProfile.maximum`. Profile/group mismatches fail closed
  (`requireGroup`) — they do not silently drop the classical share.
- Default cipher is IANA `0x1302` (SHA-384 AES-GCM). `0x1303` is offered
  and completes on dart2js (pqforge 0.4.5).
  Do not put `0x1302` on a SHA-256 schedule.
- Import `pqtransport_io.dart` only where you need a real NIC.

## Next

- [Architecture](architecture) — barrels, data flow, concat formulas.
- [Hybrid Groups](hybrid) — why order is group-dependent.
- [Cookbook](cookbook) — common patterns.
- [Claim Boundary](claim-boundary) — wording that is allowed.
