---
title: Reference
description: Every public call in pqtransport 0.2.0. Constructors and fields are the ones in the library.
---

The web-safe import is `package:pqtransport/pqtransport.dart`.
`Result` is `package:swissarmyknife/swissarmyknife.dart`.
`dart:io` types are `package:pqtransport/pqtransport_io.dart`, and
that import does not compile for the web.

## Sockets

`MemoryByteSocket.pair()` returns two linked byte pipes. TLS and HTTP
samples use that. A real TCP socket is the IO barrel:

```dart
import 'package:pqtransport/pqtransport_io.dart';

final tcp = await IoTcpSocket.connect('app.example', 443);
final server = await IoTcpServer.bind(InternetAddress.anyIPv4, 443);
final accepted = await server.connections.first;
```

`IoTcpSocket.from` wraps a `Socket` you already accepted.
`IoTcpSocket.send` writes and flushes. `close` closes the `Socket`.
`PqTlsSocket` reassembles records. This class does not.

```dart
final udp = await IoDatagramChannel.bind(
  InternetAddress.anyIPv4,
  0,
  reuseAddress: true,
  reusePort: false,
  multicastLoopback: true,
);
```

`reusePort: true` is for binding `mdnsPort` (5353). `joinMulticast`
refuses a host that is not multicast, and refuses an address family
that does not match the socket. Joining `224.0.0.251` or `ff02::fb`
sets multicast hops to 255. `leaveMulticast` drops the group.
`send` uses `PqEndpoint(host, port)`.

`MemoryDatagramNetwork` delivers a multicast datagram only to sockets
that joined that group.

`readMlDsaIdentityPem(publicPath, privatePath)` reads two files and
calls `PqTlsServerIdentity.parsePem`. An `ENCRYPTED PRIVATE KEY` is
refused. A missing file is `decodeFailure`.

## TLS client

`PqTlsSocket.client` takes the same arguments as `PqTlsClient` and
owns the record layer.

| Argument | Default | What it does |
| --- | --- | --- |
| `group` | `HybridGroup.x25519MlKem768` | The first key share |
| `offeredGroups` | `[group]` | `supported_groups`, hybrid first |
| `offeredCipherSuites` | `0x1302`, then `0x1303` | AES-256-GCM SHA-384, then ChaCha20-Poly1305 SHA-256 |
| `alpnProtocols` | `['http/1.1']` | RFC 7301 |
| `allowUnauthenticated` | `false` | Skips the peer signature. `peerAuthenticated` stays false. Finished is still checked |
| `certificateTypes` | `[rawPublicKey]` | `[x509]` omits `server_certificate_type`. Wire values are 2 and 0 |
| `trustAnchors` | empty | DER certificates. Empty uses the pin, or fails closed |
| `trustedSpki` | null | One self-signed SubjectPublicKeyInfo. Not a trust store |
| `verifyPeer` | null | Called only after the signature and the path or pin succeeded. A failure is `certificate_unknown`. It cannot authorize a bad signature |
| `now` | `DateTime.now.toUtc` | Certificate validity clock |
| `serverName` | null on the socket, `'localhost'` on the hello when omitted | SNI. For X.509 it is also the DNS SAN check. Null skips the SAN check |
| `signatureSchemes` | null | Null is ML-DSA for a raw offer, and the schemes pqforge verifies when X.509 is offered |
| `onlyShares` | null | Null sends `group`, then X25519. A non-null list is the whole offer. The hybrid is not added back |
| `ech` | null | An `EchConfig`. Rejection fails closed. There is no cleartext retry |

After `handshake()`:

- `isComplete`
- `peerAuthenticated`, true only when this socket checked CertificateVerify. A server socket is false. This stack does not authenticate the client
- `alpn`, the protocol from EncryptedExtensions, or null
- `negotiatedGroup`
- `applicationData`
- `send`
- `exporter(label, context, length)`
- `close`, which sends a warning `close_notify` and then closes the inner socket. Without it OpenSSL reports an unexpected EOF

Force one group:

```dart
final client = PqTlsClient(
  crypto: crypto,
  onlyShares: const [TlsNamedGroup.x25519],
);
```

The seven groups are `x25519`, `secp256r1`, `secp384r1`, `mlKem1024`,
`x25519MlKem768`, `secP256r1MlKem768`, and `secP384r1MlKem1024`.
`clientShareBytes` and `serverShareBytes` are the lengths.
`tlsClassicalFallbackGroups` is X25519, P-256, P-384, and ML-KEM-1024.
A peer that offered a hybrid is not moved onto that list.

SecP384r1MLKEM1024 needs `PqTransportCrypto(profile: PqForgeProfile.maximum)`.
A profile that does not contain the group fails in `requireGroup`.

## TLS server

```dart
PqTlsServer(
  crypto: crypto,
  group: HybridGroup.x25519MlKem768,
  identity: identity,
  alpnProtocols: const [httpAlpnH1],
  ech: echServer,
);
```

`PqTlsSocket.server` takes `crypto`, `identity`, `group`,
`alpnProtocols`, and `ech`.

## Certificates

The default identity is an ML-DSA-65 raw public key:

```dart
final identity = PqTlsServerIdentity.generate(crypto);
```

`parse` takes RFC 9881 public key bytes and an RFC 5958 private key.
`parsePem` takes RFC 7468 text. `publicKeyPem` and `privateKeyPem`
write those forms.

X.509 is opt-in. The chain is leaf first, 1 to 8. `sign` covers the
CertificateVerify content, not the certificate TBS. `certificateDnsName`
must be a DNS SAN on the leaf. These leaf algorithms have a
CertificateVerify scheme: ML-DSA-65, ML-DSA-87, ECDSA P-256 SHA-256,
ECDSA P-384 SHA-384, Ed25519, RSA-PSS SHA-256, SHA-384, and SHA-512.
Anything else throws.

The mint below is pqforge. The TLS identity is this package.

```dart
final raw = PqTlsServerIdentity.generate(crypto);
final leafKey = PqX509MlDsaKey(PqX509Algorithm.mlDsa65, raw.publicKey);
final leafDer = PqX509.mintLeaf(
  subject: PqX509Name.commonName('localhost'),
  publicKey: leafKey,
  algorithm: PqX509Algorithm.mlDsa65,
  sign: (tbs) => crypto.mlDsaSign(secretKey: raw.secretKey, message: tbs),
  notBefore: notBefore,
  notAfter: notAfter,
  serial: Uint8List.fromList([1]),
  subjectAltNames: const [PqX509DnsName('localhost')],
);
final identity = PqTlsServerIdentity.x509(
  leafKey: leafKey,
  sign: (content) =>
      crypto.mlDsaSign(secretKey: raw.secretKey, message: content),
  chain: [leafDer],
  certificateDnsName: 'localhost',
);
```

A chain of two puts the leaf first and the CA second. The CA is
`PqX509.mint` with `ca: true` and `keyCertSign: true`. The client
then sets `certificateTypes: [TlsCertificateType.x509]` and
`trustAnchors: [caDer]`, or `trustedSpki` for one self-signed leaf.
`serverName` checks the DNS SAN. `authenticateX509` checks the path.
CertificateVerify is a separate check.

## ECH

One suite: DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-128-GCM.
No other KEM. No cleartext retry.

```dart
final ech = await EchServerConfig.generate(
  crypto,
  publicName: 'public.example',
  configId: 1,
  maximumNameLength: 64,
);
final client = PqTlsClient(
  crypto: crypto,
  serverName: 'secret.example',
  ech: ech.config,
);
final server = PqTlsServer(crypto: crypto, identity: identity, ech: ech);
```

`publicKey` is 32 bytes. `configId` and `maximumNameLength` are one
byte. `publicName` is 1 to 255 UTF-8 bytes. `maximumNameLength`
defaults to the public name's length and is raised to that length if
you pass less. Padding uses `maximumNameLength`, not the name.
`EchConfig.parse` keeps extra HPKE suites in `wire` and requires
HKDF-SHA256 plus AES-128-GCM to be one of them. `encodeList` is the
ECHConfigList. A client that offered ECH and is rejected gets
`PqTransportError.echRequired`.

## Encrypted UDP

```dart
final socket = PqEncryptedUdpSocket(
  raw: PqUdpSocket(channel: channel, throttleWindow: Duration.zero),
  crypto: crypto,
  group: HybridGroup.x25519MlKem768,
);
```

`initiate` takes the peer ML-KEM public key and a `deploymentSalt`.
The public key is length-checked and then checked as an
encapsulation key. The flight is a QUIC Initial, padded to 1200
bytes. `accept` takes `kemSecretKey`, `initiatorFlight`, and the same
salt. `completeInitiate` takes `responderClassicalPublic`. `send`
takes plaintext and a `PqEndpoint`. `incoming` is the decrypted
datagrams. `isEstablished` is true after the session key exists.
`wasThrottled` is the send-path throttler. `driveLossDetection`
runs the RFC 9002 timer. `lossRecovery` is that recovery object.

## QUIC

`PqQuicConn.pair` links two connections in memory. A real path is
`PqQuicConn.client` or `PqQuicConn.server`. `deliver` is where you
send the datagram. `ingestDatagram` is where you put one you
received.

```dart
final client = PqQuicConn.client(
  crypto: crypto,
  group: HybridGroup.x25519MlKem768,
  alpnProtocols: const [httpAlpnH3],
  deliver: (packet) => udp.send(packet, peer),
);
await client.handshake();
final id = client.openBidi();
await client.writeStream(id, bytes, fin: true);
final got = server.readStream(id);
```

`openUni` opens a unidirectional stream. `streamFin` reports the
peer FIN. `resetStream(id, errorCode)` sends RESET_STREAM.
`flushControl` sends MAX_DATA and MAX_STREAM_DATA queued by
`readStream`. `driveLossRecovery` runs the loss timer.
`close(errorCode: quicErrorNoError, application: true)` sends
CONNECTION_CLOSE and then discards inbound packets until three times
the current PTO. `isComplete` is the TLS handshake. `alpn` is the
selected protocol. `isDraining` and `isClosed` are the connection
state. There is no 0-RTT send.

## HTTP

`PqHttpRequest` is `method`, `uri`, `headers`, and `body`.
`PqHttpResponse` is `status`, `headers`, `body`, and `version`.

`PqHttpClient(prefer: HttpVersion.h1, allowDowngrade: false)`.
`roundTrip` follows ALPN on a finished `PqTlsSocket`. ALPN `h3`
fails and tells you to call `roundTripH3`. A silent drop from `h2`
or `h3` to HTTP/1.1 fails unless `allowDowngrade` is true.

`roundTripH1` writes `encodeHttp1Request` and reads one
`applicationData` event. `encodeHttp1Response` is the server side.
`decodeHttp1Response` parses it.

`roundTripH2` requires ALPN `h2`. The server is
`PqHttp2Session.server(tls)`, then `accept`, then `respond`.
`PqHttp2Session.client` is what `roundTripH2` builds.

`roundTripH3` requires a finished `PqQuicConn` whose ALPN is `h3`.
The server is `PqHttp3Session.server(conn)`, then `accept`, then
`respond`.

`HpackCodec` and `QpackCodec` are the header codecs those sessions
use. The nghttp2 and nghttp3 jobs round-trip those bytes. They are
not a second HTTP client.

## DNS records

Every record takes `name` and an optional `ttl` (300 unless noted).

| Type | Fields |
| --- | --- |
| `DnsA` | `address`, 4 bytes |
| `DnsAaaa` | `address`, 16 bytes |
| `DnsCname` | `canonical` |
| `DnsDname` | `target` |
| `DnsMx` | `preference`, `exchange` |
| `DnsTxt` | `strings` |
| `DnsSrv` | `priority`, `weight`, `port`, `target` |
| `DnsCaa` | `flags`, `tag`, `value` |
| `DnsSvcb` | `priority`, `target`, `params` as `Map<int, Uint8List>` |
| `DnsHttps` | same fields as `DnsSvcb` |
| `DnsPtr` | `pointer` |
| `DnsNs` | `nameserver` |
| `DnsOpt` | `udpPayload`, `extendedRcode`, `version`, `flags`, `options`. Name is `.` |
| `DnsDnskey` | `flags`, `protocol`, `algorithm`, `publicKey` (not a SPKI) |
| `DnsDs` | `keyTag`, `algorithm`, `digestType`, `digest` |
| `DnsRrsig` | `typeCovered`, `algorithm`, `labels`, `originalTtl`, `expiration`, `inception`, `keyTag`, `signer`, `signature` |
| `DnsSoa` | `mname`, `rname`, `serial`, `refresh`, `retry`, `expire`, `minimum` |
| `DnsNsec` | `next`, `types` bitmap |
| `DnsNsec3` | `hashAlgorithm`, `flags`, `iterations`, `salt`, `next` hash, `types` |
| `DnsNsec3param` | `hashAlgorithm`, `flags`, `iterations`, `salt` |
| `DnsOpaque` | `typeCode`, `rdata`. The codec does not interpret `rdata` |

`encodeDnsMessage` and `decodeDnsMessage` are the UDP message.
`encodeDnsTcp` prefixes a 2-byte length. `DnsTcpReader.add` then
`next` reassembles it. A zero length is an error.

`DnsQuestion` is `name` and `type`. `DnsMessage` is `id`, `flags`,
`questions`, `answers`, `authority`, `additional`. `rcode` is the low
4 bits, plus the OPT extended rcode. `minTtl` is the smallest TTL in
the message.

## DNS clients

`PqDnsClient(exchange:, tcp:, failureThreshold: 2)`. `exchange` and
`tcp` are `Future<Uint8List> Function(Uint8List)`. `lookup` sets RD,
DO, and CD, matches the id and the question, retries `TC` over `tcp`,
and retries `BADCOOKIE` once. It caches by name and type. `resolve`
follows CNAME, up to 8 hops, and does not validate. `authenticateDns`
wants `lookup`.

`PqDnsResolver(doh:, dot:, udp:)` tries those in that order. Each one
that you pass has its own breaker. Omit one to skip it.

`DohUriTemplate.parse` accepts a URI, or that URI plus a trailing
`{?dns}`. Any other `{` fails. `DohClient.h2` needs ALPN `h2`.
`DohClient.h3` needs a `PqQuicConn` with ALPN `h3`. `useGet: true`
sends the GET form. `query` takes the raw DNS message. `exchange` is
the function you pass to `PqDnsResolver`. The server reads
`dohQueryFromRequest` and writes `dohResponse`.

`DotClient(tls)` requires ALPN `dot`. `query` writes `encodeDnsTcp`.
`close` stops the reader.

`DnsIterativeResolver` takes `hints`, `anchor`, and `send`. `send`
receives the query, the nameserver name, and its addresses. The
query has CD, DO, and a cookie. It does not have RD. Truncation is
the sender's TCP retry. `maxQueries` defaults to 32.
`maxNsec3Iterations` defaults to 0. `lookup` returns a
`DnsResolution` whose `security` is `secure`, `insecure`, or `bogus`.

`DnsTrustAnchor.dnskey` pins one key. `DnsTrustAnchor.ds` pins one
DS. `DnsTrustAnchor.dsSet` pins more than one. The root has two.
`DnsAuthData.records` is a verified RRset. `DnsAuthDenial.nameError`
is secure NXDOMAIN. Otherwise it is secure NODATA.

## mDNS

`PqMdnsServer` probes, then announces. Two `completeProbe(collision: false)`
calls are the successful probe. `announce` takes one `DnsRecord`.

`PqMdnsClient.browse` joins `224.0.0.251` and `ff02::fb` through
`joinMdnsGroups`. One family succeeding is enough. An IPv4 socket
cannot join `ff02::fb`. Each answer is stored in `seen` and fired on
`bus` as `MdnsServiceEvent(name, record)`. `stop` cancels the
listener.

```dart
final client = PqMdnsClient(channel: channel);
await client.browse();
final found = await client.bus.on<MdnsServiceEvent>().first;
```

`signTxt` takes `crypto`, `secretKey`, `name`, and `body`. It appends
`pqsig=` and returns a `DnsTxt`. `verifyTxt` takes `crypto`,
`publicKey`, and that `DnsTxt`. The signature is ML-DSA-65.

## Errors

`PqTransportError` has `code`, `message`, and an optional TLS
`alert`. The message does not contain secret bytes.

| Code | Factory |
| --- | --- |
| `illegalParameter` | `illegalParameter(label, actual, expected)`, or `illegalKemKey` |
| `decodeFailure` | `decodeFailure` |
| `unexpectedMessage` | `unexpectedMessage` |
| `handshakeFailure` | `handshakeFailure`, and `noApplicationProtocol` |
| `internalError` | `internalError` |
| `decryptError` | `decryptError` |
| `badCertificate` | `badCertificate` |
| `unsupportedCertificate` | `unsupportedCertificate` |
| `certificateUnknown` | `certificateUnknown` |
| `circuitOpen` | `circuitOpen` |
| `replay` | `replay` |
| `throttled` | `throttled` |
| `closed` | `closed` |
| `flowControl` | `flowControl` |
| `unsupported` | `unsupported` |
| `echRequired` | `echRequired` |

`illegalParameter`, the certificate codes, `decryptError`,
`handshakeFailure`, `decodeFailure`, `unexpectedMessage`, and
`internalError` carry a TLS alert. `circuitOpen`, `replay`,
`throttled`, `closed`, `flowControl`, and `unsupported` do not.
`echRequired` carries the ECH required alert.

A length check uses `requireLength(bytes, expected, PqLengthLabel)`.
The label is a name such as `mlKem768PublicKey` or `x25519Share`.
The bytes are not in the error.
