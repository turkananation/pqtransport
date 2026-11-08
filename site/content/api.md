---
title: API Guide
description: Public types in pqtransport 0.2.0. Web barrel and IO barrel.
---

Adding a symbol to the web barrel requires a test that imports only
`package:pqtransport/pqtransport.dart`.

## Install

```yaml
dependencies:
  pqtransport: ^0.2.0
  pqforge: ^0.4.13
  swissarmyknife: ^0.1.0
```

```dart
import 'package:pqtransport/pqtransport.dart';
// VM / mobile / desktop datagrams and TCP:
import 'package:pqtransport/pqtransport_io.dart';
```

## Named groups

`TlsNamedGroup` is the group on the wire. `HybridGroup` is only the
three RFC 10024 values.

| Value | Code | Secret |
| --- | --- | --- |
| `x25519MlKem768` | `0x11EC` | ML-KEM-768 then X25519 |
| `secP256r1MlKem768` | `0x11EB` | P-256 then ML-KEM-768 |
| `secP384r1MlKem1024` | `0x11ED` | P-384 then ML-KEM-1024. `PqForgeProfile.maximum` |
| `x25519` | `0x001D` | X25519 only |
| `secp256r1` | `0x0017` | P-256 only |
| `secp384r1` | `0x0018` | P-384 only |
| `mlKem1024` | `0x0202` | ML-KEM-1024 only |

The default ClientHello still offers the hybrid first, then X25519.
`tlsClassicalFallbackGroups` is the four non-hybrid groups. A peer
that offers only one of those gets HelloRetryRequest.

## DNSSEC

`PqDnsClient.lookup` does not check signatures. The stub query sets
RD, DO, and CD. `authenticateDns` checks one name. Pass `lookup`,
not `resolve`. CNAME hops are validated inside `authenticateDns`.

| Type | Role |
| --- | --- |
| `DnsTrustAnchor.dnskey` | One trusted DNSKEY |
| `DnsTrustAnchor.ds` | One trusted DS |
| `DnsTrustAnchor.dsSet` | More than one DS. The root has two KSKs |
| `authenticateDns` | One name. Returns `DnsAuthData` or `DnsAuthDenial` |
| `verifyDnssecRrset` | One RRset, already fetched |
| `DnsIterativeResolver` | Walks `DnsHint`s. Returns `DnsResolution` |
| `DnsSecurity` | `secure`, `insecure`, `bogus` |
| `DnsHint` | A root server the caller can already reach |
| `DnsSend` | One query to one nameserver. The message already has CD, DO, and a cookie |

Algorithms 5, 7, 8, 10, 13, 14, 15, and 16. RSA is PKCS#1 v1.5,
moduli 1024, 2048, 3072, and 4096. Ed448 uses an empty context.
NSEC3 is hash algorithm 1. The iterative resolver's extra-iteration
ceiling defaults to 0. The AD bit is not read.

```dart
final anchor = DnsTrustAnchor.dsSet(zone: '.', ds: rootDs);
final auth = await authenticateDns(
  name: 'yardenah.com',
  type: DnsType.a,
  anchor: anchor,
  lookup: dns.lookup,
  now: DateTime.now().toUtc(),
);
```

`example/dns_validate.dart` signs a zone in memory.
`example/dns_live.dart` asks a resolver, then checks from the IANA
root DS set. There is no authoritative server in this package.

## Core

| Type | Role |
| --- | --- |
| `encodeClientShare` / `decodeClientShare` | RFC 10024 client key_share |
| `encodeServerShare` / `decodeServerShare` | RFC 10024 server key_share |
| `combineSharedSecret` | Group-order concatenation |
| `requireLength` / `requireMinLength` | Length filter |
| `PqTransportError` / `PqTransportErrorCode` | Failures without secret bytes |
| `PqTransportCrypto` | Facade over pqforge |
| `Transcript` | SHA-256 or SHA-384 handshake transcript |
| `zeroize` / `withSecrets` | Best-effort wipe |

## Sockets

| Type | Role |
| --- | --- |
| `PqTransportSocket` | Bytes in / bytes out |
| `MemoryByteSocket.pair()` | In-memory duplex |
| `MemoryDatagramNetwork` | Multicast only to joined sockets |
| `IoDatagramChannel.bind` | `dart:io` UDP. IO barrel only |
| `IoTcpSocket` / `IoTcpServer` | `dart:io` TCP. IO barrel only |

## TLS

| Type | Role |
| --- | --- |
| `PqTlsClient` / `PqTlsServer` / `PqTlsSocket` | Handshake and records |
| `PqTlsServerIdentity.generate` | ML-DSA-65 raw public key |
| `PqTlsServerIdentity.x509` | Opt-in chain, 1 to 8, caller anchors |
| `peerAuthenticated` | True only after CertificateVerify |
| `EchConfig` / `EchServerConfig` | RFC 9849. One BoringSSL flight |
| `TlsCipherSuite` | `0x1302` AES-256-GCM, `0x1303` ChaCha20-Poly1305 |
| `TlsKeySchedule` | HKDF-SHA-384 or HKDF-SHA-256, plus the exporter |

`allowUnauthenticated` skips the check and leaves `peerAuthenticated`
false. That is not authentication.

## UDP / HTTP / QUIC

| Type | Role |
| --- | --- |
| `PqEncryptedUdpSocket` | Hybrid session, then QUIC 1-RTT. Loss recovery is RFC 9002 |
| `DohClient` / `DotClient` | RFC 8484 and RFC 7858 |
| `PqMdnsClient` / `PqMdnsServer` | Probe, announce, browse |
| `PqHttpClient` | HTTP/1.1 and HTTP/2 over TLS. HTTP/3 over `PqQuicConn` |
| `PqHttp2Session` / `HpackCodec` | RFC 9113 and RFC 7541 |
| `PqHttp3Session` / `QpackCodec` | RFC 9114 and RFC 9204 |
| `PqQuicConn` | TLS-in-QUIC and 1-RTT STREAM |

## Errors

`Result<T, PqTransportError>` for a bad record, a bad signature, or a
bogus zone. Do not throw those. A state-machine event that is not
legal moves the machine to `failed`.
