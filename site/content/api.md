---
title: API Guide
description: Frozen v0.1.0 public types for pqtransport. Web barrel vs IO barrel.
---

Frozen v0.1.0 names. Adding a symbol to the web barrel requires a test
that imports only `package:pqtransport/pqtransport.dart`.

## Install

```yaml
dependencies:
  pqtransport: ^0.1.0
  pqforge: ^0.4.5
  swissarmyknife: ^0.1.0
```

```dart
import 'package:pqtransport/pqtransport.dart';
// VM / mobile / desktop datagrams:
import 'package:pqtransport/pqtransport_io.dart';
```

## Core

| Type | Role |
| --- | --- |
| `HybridGroup` | `x25519MlKem768`, `secP256r1MlKem768`, `secP384r1MlKem1024` |
| `encodeClientShare` / `decodeClientShare` | RFC 10024 client key_share |
| `encodeServerShare` / `decodeServerShare` | RFC 10024 server key_share |
| `combineSharedSecret` | Group-order concatenation of component secrets |
| `requireLength` / `requireMinLength` | Length filter |
| `PqTransportError` / `PqTransportErrorCode` | Failures without secret bytes |
| `PqTransportCrypto` | Facade over pqforge |
| `Transcript` | Running SHA-256 or SHA-384 handshake transcript |
| `zeroize` / `withSecrets` | Best-effort wipe |

## Sockets

| Type | Role |
| --- | --- |
| `PqTransportSocket` | Bytes in / bytes out |
| `MemoryByteSocket.pair()` | In-memory duplex; buffers until a listener attaches |
| `MemoryDatagramNetwork` | In-memory network; multicast only to joined sockets on 224.0.0.251 / ff02::fb |
| `IoDatagramChannel.bind` | `dart:io` UDP (IO barrel only); `joinMulticast` for LAN mDNS |

## UDP / TLS

| Type | Role |
| --- | --- |
| `PqUdpSocket` / `PqDatagramCodec` / `ReplayWindow` | Datagram AEAD + replay |
| `peekDatagramSequence` | Cheap replay check **before** AEAD |
| `PqEncryptedUdpSocket` | Hybrid session then AEAD datagrams |
| `PqTlsClient` / `PqTlsServer` / `PqTlsSocket` | Handshake + records |
| `PqTlsServerIdentity` | ML-DSA-65 key pair |
| `TlsCipherSuite` | IANA `0x1302` / `0x1303` |
| `TlsKeySchedule` | Suite-bound HKDF-SHA-384 (`0x1302`) or SHA-256 (`0x1303`) + exporter |
| `TlsRecordLayer` | Epoch-aware AES-256-GCM or ChaCha20-Poly1305 |

## DNS / mDNS / HTTP / QUIC

| Type | Role |
| --- | --- |
| `PqDnsClient` / `PqDnsResolver` | Lookup + cache + breaker |
| `DohClient` / `DotClient` | RFC 8484 DoH (ALPN `h2`/`h3`, `{?dns}`) and RFC 7858 DoT (ALPN `dot`) |
| `PqMdnsClient` / `PqMdnsServer` | Probe / announce / browse |
| `signTxt` / `verifyTxt` | ML-DSA-65 TXT |
| `PqHttpClient` | HTTP/1.1 and HTTP/2 over TLS; HTTP/3 over `PqQuicConn` |
| `PqHttp2Session` / `HpackCodec` | RFC 9113 + RFC 7541 |
| `PqHttp3Session` / `QpackCodec` | RFC 9114 + RFC 9204 |
| `PqQuicConn` / `QuicStreamFrame` | TLS-in-QUIC + 1-RTT STREAM |
| `QuicPacketCodec` / `QuicCryptoFrame` | QUIC Initial / 1-RTT |

## Errors

`Result<T, PqTransportError>` for expected protocol failures. Unexpected
machine events transition to `failed` and wrap `Result.failure`.
