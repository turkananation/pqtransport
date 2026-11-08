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

## HTTP

`PqHttpClient` does not take a socket in its constructor. Pass the
finished socket to the call. `roundTrip` follows ALPN. A silent drop
from `h2` or `h3` to HTTP/1.1 fails unless `allowDowngrade` is set.
HTTP/3 is `roundTripH3` on a finished `PqQuicConn` whose ALPN is `h3`.

```dart
final http = PqHttpClient();
final res = await http.roundTripH1(
  tls: client,
  request: PqHttpRequest(
    method: 'GET',
    uri: Uri.parse('https://localhost/health'),
  ),
);
```

ALPN `h2` is the same request through `roundTripH2`. ALPN `h3` is
`roundTripH3(conn: quic, request: request)`.

## DoH and DoT

DoH is RFC 8484. The template is a POST URI, or the same URI with a
trailing `{?dns}` for GET. `DohClient.h2` needs a `PqTlsSocket` whose
ALPN is `h2`. `DohClient.h3` needs a `PqQuicConn` whose ALPN is `h3`.

```dart
final template = DohUriTemplate.parse(
  'https://dns.example/dns-query{?dns}',
).valueOrNull!;
final doh = DohClient.h2(tls, template: template);
final answer = await doh.query(query);
```

DoT is `DotClient(tls)` after a handshake that selected ALPN `dot`.
The bytes after a handshake, checked against curl's libnghttp2, are
on [Peers](peers). That check is cleartext HTTP/2. curl's TLS is not
this handshake.

## Programs in this repository

```bash
dart run example/pq_tls_client.dart
dart run example/encrypted_udp_peer.dart
dart run example/mdns_discovery.dart
dart run example/dns_validate.dart
dart run example/dns_live.dart
```

`dns_live.dart` is the only one that uses the network. It asks
1.1.1.1, then checks `yardenah.com` from the IANA root DS set. Pass
another resolver address as the argument. `encrypted_udp_peer.dart`
is the QUIC Initial session on `MemoryDatagramNetwork`.
`mdns_discovery.dart` probes and announces on that same network.

## Length-filter a share

```dart
final share = requireLength(raw, x25519MlKem768ClientShareBytes);
final parsed = decodeClientShare(HybridGroup.x25519MlKem768, share);
```

## DNS stub, then DNSSEC

`lookup` does not check signatures. The query sets RD, DO, and CD.
`authenticateDns` does check them. Pass `lookup`, not `resolve`:
CNAME hops are validated inside `authenticateDns`. The AD bit is not
read. A full signed zone is `example/dns_validate.dart`. A query of
`yardenah.com` through 1.1.1.1 is `example/dns_live.dart`.

```dart
import 'package:pqtransport/pqtransport.dart';
import 'package:swissarmyknife/swissarmyknife.dart';

final dns = PqDnsClient(exchange: udp, tcp: tcp);
final stub = await dns.lookup('example.com', DnsType.a);

final auth = await authenticateDns(
  name: 'www.example.com',
  type: DnsType.a,
  anchor: DnsTrustAnchor.dsSet(zone: '.', ds: rootDs),
  lookup: dns.lookup,
  now: DateTime.now().toUtc(),
);
switch (auth.valueOrNull) {
  case DnsAuthData(:final records):
    // Signed records. The chain reached [anchor].
    break;
  case DnsAuthDenial(:final nameError):
    // Secure NXDOMAIN when nameError is set, otherwise secure NODATA.
    break;
  case null:
    // auth.errorOrNull. Not secure, and not a proven insecure zone.
    break;
}
```

`DnsTrustAnchor.dnskey` pins one key. `DnsTrustAnchor.ds` pins one DS.
`DnsTrustAnchor.dsSet` is the root, which publishes two KSKs. Pinning
only one of them makes the other KSK look bogus.

`DnsIterativeResolver` is the walker. Give it root hints and the same
anchor. It returns `DnsSecurity.secure`, `insecure`, or `bogus`.
Queries to authoritative servers do not set RD. The NSEC3 iteration
ceiling defaults to 0.

```dart
final walker = DnsIterativeResolver(
  hints: [DnsHint('a.root-servers.net.', [aRoot])],
  anchor: DnsTrustAnchor.dsSet(zone: '.', ds: rootDs),
  send: queryAuthoritative,
);
final walked = await walker.lookup('example.com', DnsType.a);
```

## Signed mDNS TXT

```dart
final txt = signTxt(crypto, identity, 'pqtransport=1');
final ok = verifyTxt(crypto, identity.publicKey, txt);
```

## Live NIST group

```dart
final crypto = PqTransportCrypto();
final r = PqTlsClient(
  crypto: crypto,
  group: HybridGroup.secP256r1MlKem768,
).startHandshake();
// Live via pqforge. SecP384r1MLKEM1024 needs PqForgeProfile.maximum.
```

## Profile / group mismatch still fails closed

```dart
final crypto = PqTransportCrypto(profile: PqForgeProfile.maximum);
final r = await PqTlsClient(
  crypto: crypto,
  group: HybridGroup.x25519MlKem768,
).startHandshake();
// Result.failure — maximum is ML-KEM-1024; X25519MLKEM768 needs 768.
```
