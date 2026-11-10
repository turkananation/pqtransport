---
title: Cookbook
description: One complete call for each pqtransport protocol.
---

Each block is the call the matching program in `example/` runs. Paste
it after `import 'package:pqtransport/pqtransport.dart';` and
`import 'package:swissarmyknife/swissarmyknife.dart';`.

## TLS 1.3

`serverName` is SNI. A raw public key does not check that name.
`peerAuthenticated` is true only after CertificateVerify.
`onlyShares` forces one group. X.509 is
`certificateTypes: [TlsCertificateType.x509]` plus caller anchors.

```dart
final crypto = PqTransportCrypto();
final identity = PqTlsServerIdentity.generate(crypto);
final (a, b) = MemoryByteSocket.pair();
final client = PqTlsSocket.client(
  a,
  crypto: crypto,
  serverName: 'app.example',
  alpnProtocols: const [httpAlpnH1],
);
final server = PqTlsSocket.server(
  b,
  crypto: crypto,
  identity: identity,
  alpnProtocols: const [httpAlpnH1],
);
final hs = await Future.wait([server.handshake(), client.handshake()]);
final sent = await client.send(Uint8List.fromList('ping'.codeUnits));
final got = await server.applicationData.first;
final key = client.exporter('app', Uint8List(0), 32);
```

`hs` must succeed, `client.peerAuthenticated` is true, and
`client.negotiatedGroup` is `TlsNamedGroup.x25519MlKem768`. The
program is `example/tls13.dart`.

## HTTP/1.1

Listen on the server before the client writes. `roundTrip` follows
ALPN. A silent drop from `h2` or `h3` fails unless `allowDowngrade`
is set.

```dart
server.applicationData.listen((raw) async {
  await server.send(
    encodeHttp1Response(
      PqHttpResponse(
        status: 200,
        headers: const {'content-type': 'text/plain'},
        body: Uint8List.fromList('pq-ok'.codeUnits),
        version: HttpVersion.h1,
      ),
    ),
  );
});
await Future.wait([server.handshake(), client.handshake()]);
final res = await PqHttpClient().roundTrip(
  tls: client,
  request: PqHttpRequest(
    method: 'GET',
    uri: Uri.parse('https://app.example/health'),
  ),
);
```

The handshake uses `alpnProtocols: const [httpAlpnH1]`. The program
is `example/http1.dart`.

## HTTP/2

Start `accept` before `roundTripH2`. ALPN must be `h2`.

```dart
final client = PqTlsSocket.client(
  a,
  crypto: crypto,
  alpnProtocols: const [httpAlpnH2],
);
final server = PqTlsSocket.server(
  b,
  crypto: crypto,
  identity: identity,
  alpnProtocols: const [httpAlpnH2],
);
await Future.wait([server.handshake(), client.handshake()]);
final h2 = PqHttp2Session.server(server);
final serving = () async {
  final accepted = await h2.accept(timeout: const Duration(seconds: 20));
  final (id, _) = accepted.valueOrNull!;
  return h2.respond(
    id,
    PqHttpResponse(
      status: 200,
      headers: const {'content-type': 'text/plain'},
      body: Uint8List.fromList('h2-ok'.codeUnits),
      version: HttpVersion.h2,
    ),
  );
}();
final res = await PqHttpClient(prefer: HttpVersion.h2).roundTripH2(
  tls: client,
  request: PqHttpRequest(
    method: 'GET',
    uri: Uri.parse('https://app.example/health'),
  ),
);
await serving;
```

The program is `example/http2.dart`.

## HTTP/3

`PqQuicConn.pair` links the two ends in memory. A real socket uses
`PqQuicConn.client` and sends the datagram from `deliver`.
`roundTripH3` refuses any ALPN other than `h3`.

```dart
final (client, server) = PqQuicConn.pair(alpnProtocols: const [httpAlpnH3]);
await Future.wait([client.handshake(), server.handshake()]);
final h3 = PqHttp3Session.server(server);
final serving = () async {
  final accepted = await h3.accept();
  final (id, _) = accepted.valueOrNull!;
  return h3.respond(
    id,
    PqHttpResponse(
      status: 200,
      headers: const {'content-type': 'text/plain'},
      body: Uint8List.fromList('pq-h3'.codeUnits),
      version: HttpVersion.h3,
    ),
  );
}();
final res = await PqHttpClient(prefer: HttpVersion.h3).roundTripH3(
  conn: client,
  request: PqHttpRequest(
    method: 'GET',
    uri: Uri.parse('https://app.example/health'),
  ),
);
await serving;
```

The program is `example/http3.dart`. This is not `curl --http3`.

## DNS stub

`exchange` and `tcp` return the raw message. `lookup` returns that
one answer. `resolve` follows CNAME. Neither checks a signature. A
truncated UDP answer is retried once over `tcp`.

```dart
final dns = PqDnsClient(
  exchange: (query) async => reply(query, truncated: false),
  tcp: (query) async => reply(query, truncated: false),
);
final one = await dns.lookup('alias.example.', DnsType.a);
final chased = await dns.resolve('alias.example.', DnsType.a);
```

`one` stops at the CNAME. `chased` is the A record at the target.
`reply` echoes `id` and the question, and sets `dnsFlagTc` when
`truncated` is true. The program is `example/dns_stub.dart`.

## DNSSEC

Pass `lookup`, not `resolve`. CNAME hops are checked inside
`authenticateDns`. The AD bit is not read.

```dart
final anchor = DnsTrustAnchor.dnskey(zone: 'example.com.', dnskey: key);
final auth = await authenticateDns(
  name: 'www.example.com.',
  type: DnsType.a,
  anchor: anchor,
  lookup: lookup,
  now: DateTime.utc(2026, 6, 1),
);
```

`key` is a `DnsDnskey` with `flags: dnssecZoneKeyFlag`,
`protocol: dnssecProtocol`, and `algorithm: dnssecAlgorithmEd25519`.
A DS anchor is `DnsTrustAnchor.ds`. The root publishes two KSKs, so
pin both:

```dart
final root = DnsTrustAnchor.dsSet(
  zone: '.',
  ds: [
    DnsDs(
      name: '.',
      keyTag: 20326,
      algorithm: dnssecAlgorithmRsaSha256,
      digestType: dnssecDigestSha256,
      digest: digest20326,
    ),
    DnsDs(
      name: '.',
      keyTag: 38696,
      algorithm: dnssecAlgorithmRsaSha256,
      digestType: dnssecDigestSha256,
      digest: digest38696,
    ),
  ],
);
```

Those two digests are the digest-type-2 records in the IANA root
anchors. The signed zone is `example/dns_validate.dart`. The live
query of `yardenah.com` is `example/dns_live.dart`.

`auth.valueOrNull` is `DnsAuthData` when the chain verified, or
`DnsAuthDenial` for a secure NXDOMAIN or NODATA. Anything else is
`auth.errorOrNull`.

## Iterative resolver

Queries to authoritative servers do not set RD. The sender retries a
truncated answer over TCP. The NSEC3 iteration ceiling defaults to 0.

```dart
final walker = DnsIterativeResolver(
  hints: [
    DnsHint(
      'a.root-servers.net.',
      [Uint8List.fromList(const [198, 41, 0, 4])],
    ),
  ],
  anchor: root,
  send: (query, nameserver, addresses) async {
    final wire = encodeDnsMessage(query).valueOrNull!;
    final raw = await ask(addresses, wire);
    return decodeDnsMessage(raw);
  },
);
final walked = await walker.lookup('example.com.', DnsType.a);
```

`walked.valueOrNull!.security` is `DnsSecurity.secure`, `insecure`,
or `bogus`.

## DoH

The handshake selects ALPN `h2`. The template may end in `{?dns}`.
Any other `{` fails. `exchange` is what `PqDnsResolver` calls.
`lookup` still does not validate. HTTP/3 is `DohClient.h3` on a
`PqQuicConn` whose ALPN is `h3`.

```dart
final template = DohUriTemplate.parse(
  'https://dns.example/dns-query{?dns}',
).valueOrNull!;
final http = PqHttpClient(prefer: HttpVersion.h2);
final post = DohClient.h2(client, template: template, http: http);
final get = DohClient.h2(
  client,
  template: template,
  http: http,
  useGet: true,
);
final query = encodeDnsMessage(
  DnsMessage(
    id: 0x0d07,
    questions: [DnsQuestion(name: 'www.example.', type: DnsType.a)],
  ),
).valueOrNull!;
final posted = await post.query(query);
final gotten = await get.query(query);
final looked = await PqDnsResolver(
  doh: post.exchange,
).lookup('www.example.', DnsType.a);
```

The server reads the request with `dohQueryFromRequest` and answers
with `dohResponse`. The program is `example/doh.dart`.

## DoT

ALPN must be `dot`. The DNS message has a 2-byte length prefix.

```dart
final client = PqTlsSocket.client(
  a,
  crypto: crypto,
  alpnProtocols: const [dnsAlpnDot],
);
final server = PqTlsSocket.server(
  b,
  crypto: crypto,
  identity: identity,
  alpnProtocols: const [dnsAlpnDot],
);
final serving = () async {
  final reader = DnsTcpReader();
  await for (final chunk in server.applicationData) {
    reader.add(chunk);
    final q = reader.next();
    if (q == null) continue;
    return server.send(encodeDnsTcp(answer));
  }
}();
await Future.wait([server.handshake(), client.handshake()]);
final got = await DotClient(client).query(query);
await serving;
```

`query` is `encodeDnsMessage(...)`. The program is `example/dot.dart`.

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

The program is `example/encrypted_udp_peer.dart`.

## mDNS

```dart
final net = MemoryDatagramNetwork();
final server = PqMdnsServer(
  channel: net.bind(const PqEndpoint('10.0.0.1', mdnsPort)),
);
await server.beginProbe('printer._pq._tcp.local.');
server.completeProbe(collision: false);
server.completeProbe(collision: false);
await server.announce(
  DnsA(
    name: 'printer._pq._tcp.local.',
    address: Uint8List.fromList(const [10, 0, 0, 1]),
  ),
);
```

A signed TXT is named arguments, not a positional call:

```dart
final identity = PqTlsServerIdentity.generate(crypto);
final txt = signTxt(
  crypto: crypto,
  secretKey: identity.secretKey,
  name: 'printer._pq._tcp.local.',
  body: const ['pqtransport=1'],
);
final ok = verifyTxt(
  crypto: crypto,
  publicKey: identity.publicKey,
  txt: txt.valueOrNull!,
);
```

The program is `example/mdns_discovery.dart`. A real LAN joins
`224.0.0.251` with `joinMdnsGroups` on `IoDatagramChannel`.

## Length-filter a share

```dart
final share = requireLength(raw, x25519MlKem768ClientShareBytes);
final parsed = decodeClientShare(HybridGroup.x25519MlKem768, share);
```

## Live NIST group

```dart
final crypto = PqTransportCrypto();
final r = PqTlsClient(
  crypto: crypto,
  group: HybridGroup.secP256r1MlKem768,
).startHandshake();
```

SecP384r1MLKEM1024 needs `PqForgeProfile.maximum`.

## Profile / group mismatch still fails closed

```dart
final crypto = PqTransportCrypto(profile: PqForgeProfile.maximum);
final r = await PqTlsClient(
  crypto: crypto,
  group: HybridGroup.x25519MlKem768,
).startHandshake();
```

`r` is a failure. Maximum is ML-KEM-1024. X25519MLKEM768 needs 768.

## Servers

Shelf and Relic do not take a `dart:io` `SecurityContext` on this
path. The handshake is pqtransport. Serverpod's API server and
insights server still build that context inside Serverpod. This
package does not pretend a `SecurityContext` can hold an ML-DSA
certificate. Serverpod's web server is Relic. If you construct that
web server yourself, pass `PqRelicAdapter` instead of `IOAdapter`.

```dart
import 'package:pqtransport/shelf.dart';
import 'package:shelf/shelf.dart';

final shelf = await serveShelf(
  (request) => Response.ok('shelf-ok ${request.requestedUri.path}'),
  InternetAddress.loopbackIPv4,
  0,
  identity: identity,
);
```

```dart
import 'package:pqtransport/relic.dart';
import 'package:relic_core/relic_core.dart';

final adapter = await PqRelicAdapter.bind(
  InternetAddress.loopbackIPv4,
  0,
  identity: identity,
);
final relic = RelicServer(() => adapter);
await relic.mountAndStart(
  (request) =>
      Response.ok(body: Body.fromString('relic-ok ${request.url.path}')),
);
```

`identity` is a `PqTlsServerIdentity`. ALPN offers `h2` and
`http/1.1`. Pass `quic: true` to also accept HTTP/3 on the same
port. Neither adapter detaches the TLS stream, and neither speaks
WebSocket. The tests are `test/io/framework_test.dart`.

Foreign servers are the [Peers](peers) page. OpenSSL 3.5.9 is the
TLS peer, including `s_server -max_send_frag 512`, which splits both
ServerHello and a 2048-octet HTTP/1.1 body. curl linked to that
OpenSSL is the HTTP/1.1 client against `PqHttpServer` (chunked body,
one connection for two responses, a new connection after
`Connection: close`). quiche 0.30.0 is the HTTP/3 peer for one GET
both ways. That is not `curl --http3` and not a complete RFC 9114
stack. Extended CONNECT, PRIORITY_UPDATE, and HTTP datagrams are
the quiche flights. The Capsule Protocol, CONNECT-UDP, and
CONNECT-IP are implemented and have no foreign peer.
