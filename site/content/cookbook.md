---
title: Cookbook
description: Common pqtransport patterns for Dart application code.
---

## In-memory TLS

```dart
final crypto = PqTransportCrypto();
final identity = PqTlsServerIdentity.generate(crypto);
final (a, b) = MemoryByteSocket.pair();
final client = PqTlsSocket.client(a, crypto: crypto);
final server = PqTlsSocket.server(b, crypto: crypto, identity: identity);
await Future.wait([server.handshake(), client.handshake()]);
```

## HTTP/1.1 GET over that socket

```dart
final http = PqHttpClient(socket: client);
final res = await http.roundTripH1(PqHttpRequest.get('/health'));
```

## Length-filter a share

```dart
final share = requireLength(raw, x25519MlKem768ClientShareBytes);
final parsed = decodeClientShare(HybridGroup.x25519MlKem768, share);
```

## DNS with breaker and cache

```dart
final client = PqDnsClient(
  exchange: memoryExchange,
  cache: Cache<String, DnsMessage>(ttl: const Duration(seconds: 30)),
);
final answer = await client.lookup('example.test', DnsType.a);
```

## Signed mDNS TXT

```dart
final txt = signTxt(crypto, identity, 'pqtransport=1');
final ok = verifyTxt(crypto, identity.publicKey, txt);
```

## Fail closed on NIST groups

```dart
final r = PqTlsClient(
  crypto: crypto,
  group: HybridGroup.secP256r1MlKem768,
).startHandshake();
// Result.failure until pqforge exports P-256 ECDH.
```
