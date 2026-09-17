# API

Last updated: 2026-09-17

Frozen v0.1.0 names. Adding a symbol to the web barrel requires a test that
imports only `package:pqtransport/pqtransport.dart`.

## Install

```yaml
dependencies:
  pqtransport: ^0.1.0
  pqforge: ^0.4.3
  swissarmyknife: ^0.1.0
```

```dart
import 'package:pqtransport/pqtransport.dart';
// VM / mobile / desktop datagrams:
import 'package:pqtransport/pqtransport_io.dart';
```

## Core

| Type | Role |
|---|---|
| `HybridGroup` | `x25519MlKem768`, `secP256r1MlKem768`, `secP384r1MlKem1024` |
| `encodeClientShare` / `decodeClientShare` | RFC 10024 client key_share |
| `encodeServerShare` / `decodeServerShare` | RFC 10024 server key_share |
| `combineSharedSecret` | Group-order concatenation of component secrets |
| `requireLength` / `requireMinLength` | Length filter |
| `PqTransportError` / `PqTransportErrorCode` | Failures without secret bytes |
| `PqTransportCrypto` | Facade over pqforge (KEM, X25519, ML-DSA, HKDF, AES-GCM) |
| `Transcript` | Running SHA-256 handshake transcript |
| `zeroize` / `withSecrets` | Best-effort wipe |
| Length constants | `x25519MlKem768ClientShareBytes` (1216), etc. |

## Sockets

| Type | Role |
|---|---|
| `PqTransportSocket` | Bytes in / bytes out |
| `MemoryByteSocket.pair()` | In-memory duplex; buffers until a listener attaches |
| `PqEndpoint` / `PqDatagramChannel` / `PqDatagramIn` | Addressed datagrams |
| `MemoryDatagramNetwork` | In-memory network; multicast flood on 224.0.0.251 / ff02::fb |
| `IoDatagramChannel.bind` | `dart:io` UDP (IO barrel only) |

## UDP

| Type | Role |
|---|---|
| `PqUdpSocket` | Raw send + Throttler |
| `PqDatagram` / `PqDatagramCodec` | AEAD envelope |
| `peekDatagramSequence` | Cheap replay check |
| `ReplayWindow` | Sliding anti-replay |
| `PqEncryptedUdpSocket` | Hybrid session then AEAD datagrams |
| `udpStateMachine` | Reliability states |

## TLS

| Type | Role |
|---|---|
| `PqTlsClient` / `PqTlsServer` / `PqTlsSocket` | Handshake + records |
| `PqTlsServerIdentity` | ML-DSA-65 key pair |
| `TlsState` / `TlsEvent` / `tlsClientMachine` / `tlsServerMachine` | Machines |
| `TlsKeySchedule` | HKDF-SHA-256 schedule + exporter |
| `TlsRecordLayer` | Epoch-aware AES-256-GCM |
| `ClientHello` / `ServerHello` | Compact (not RFC 8446) codecs |

### In-memory handshake

```dart
final crypto = PqTransportCrypto();
final identity = PqTlsServerIdentity.generate(crypto);
final (a, b) = MemoryByteSocket.pair();
final client = PqTlsSocket.client(a, crypto: crypto);
final server = PqTlsSocket.server(b, crypto: crypto, identity: identity);
await Future.wait([server.handshake(), client.handshake()]);
final key = client.exporter('app', Uint8List(0), 32);
```

## DNS / mDNS / HTTP / QUIC

| Type | Role |
|---|---|
| `PqDnsClient` / `PqDnsResolver` | Lookup + cache + breaker |
| `DohExchange` / `DotExchange` | Thin adapters |
| `DnsMessage` + `DnsA` … `DnsNs` | Records |
| `encodeDnsMessage` / `decodeDnsMessage` | Wire |
| `PqMdnsClient` / `PqMdnsServer` | Probe/announce/browse |
| `signTxt` / `verifyTxt` | ML-DSA-65 TXT |
| `PqHttpClient` / `PqHttpRequest` / `PqHttpResponse` | HTTP/1.1 over TLS |
| `Http3Frame` | HTTP/3 frame codec |
| `QuicPacketCodec` / `QuicCryptoFrame` / `QuicFlowControl` | QUIC sketch |

## Errors

`Result<T, PqTransportError>` for expected protocol failures. Do not `throw`
on a truncated record or a bad Finished MAC. Unexpected machine events
transition to `failed` and wrap `Result.failure`.
