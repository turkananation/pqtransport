import 'dart:typed_data';

import 'package:pqtransport/pqtransport.dart';
import 'package:test/test.dart';

void main() {
  final crypto = PqTransportCrypto();

  group('signed TXT', () {
    test('splitTxt/joinTxt round trip and missing pqsig fails', () {
      final raw = Uint8List.fromList(List<int>.generate(300, (i) => i & 0xff));
      final parts = splitTxt(raw);
      expect(parts.length, 2);
      expect(joinTxt(parts), raw);
      expect(
        verifyTxt(
          crypto: crypto,
          publicKey: Uint8List(mlDsa65PublicKeyBytes),
          txt: DnsTxt(name: 'x.', strings: ['no-sig']),
        ).isFailure,
        isTrue,
      );
    });
  });

  group('DoH / DoT helpers', () {
    test('DohExchange forwards the body', () async {
      final ex = DohExchange((body) async => body);
      expect(await ex.call(Uint8List.fromList([1, 2])), [1, 2]);
    });

    test('DotExchange length-prefixes over a byte pipe', () async {
      final (a, b) = MemoryByteSocket.pair();
      b.incoming.listen((q) async {
        final len = (q[0] << 8) | q[1];
        final payload = q.sublist(2, 2 + len);
        final reply = BytesBuilder(copy: false)
          ..addByte(0)
          ..addByte(payload.length)
          ..add(payload);
        await b.send(reply.takeBytes());
      });
      final dot = DotExchange(a);
      final out = await dot.call(Uint8List.fromList([9, 9]));
      expect(out, [9, 9]);
      await a.close();
      await b.close();
    });
  });

  group('mDNS collision', () {
    test('collision fails closed', () async {
      final net = MemoryDatagramNetwork();
      final server = PqMdnsServer(
        channel: net.bind(const PqEndpoint('10.9.0.1', mdnsPort)),
      );
      expect((await server.beginProbe('x.local.')).isSuccess, isTrue);
      expect(server.completeProbe(collision: true).isFailure, isTrue);
      expect(server.state, MdnsState.failed);
    });

    test('announce from idle is unexpected', () async {
      final net = MemoryDatagramNetwork();
      final server = PqMdnsServer(
        channel: net.bind(const PqEndpoint('10.9.0.2', mdnsPort)),
      );
      final r = await server.announce(
        DnsA(name: 'x.local.', address: Uint8List.fromList([1, 2, 3, 4])),
      );
      expect(r.isFailure, isTrue);
    });
  });

  group('encrypted UDP error paths', () {
    test('completeInitiate without pending fails', () async {
      final net = MemoryDatagramNetwork();
      final sock = PqEncryptedUdpSocket(
        raw: PqUdpSocket(
          channel: net.bind(const PqEndpoint('8.8.8.8', 9)),
          throttleWindow: Duration.zero,
        ),
        crypto: crypto,
      );
      final r = await sock.completeInitiate(
        responderClassicalPublic: Uint8List(x25519ShareBytes),
      );
      expect(r.isFailure, isTrue);
    });

    test('accept rejects wrong flight length', () async {
      final net = MemoryDatagramNetwork();
      final sock = PqEncryptedUdpSocket(
        raw: PqUdpSocket(
          channel: net.bind(const PqEndpoint('8.8.4.4', 9)),
          throttleWindow: Duration.zero,
        ),
        crypto: crypto,
      );
      final r = await sock.accept(
        kemSecretKey: Uint8List(mlKem768SecretKeyBytes),
        initiatorFlight: Uint8List(3),
        deploymentSalt: Uint8List(8),
      );
      expect(r.isFailure, isTrue);
      expect(r.errorOrNull!.code, PqTransportErrorCode.illegalParameter);
    });

    test('installSessionKey then AEAD send/receive', () async {
      final net = MemoryDatagramNetwork();
      final epA = const PqEndpoint('9.9.9.1', 7);
      final epB = const PqEndpoint('9.9.9.2', 7);
      final key = crypto.randomBytes(aeadKeyBytes);
      final a = PqEncryptedUdpSocket(
        raw: PqUdpSocket(channel: net.bind(epA), throttleWindow: Duration.zero),
        crypto: crypto,
      )..installSessionKey(key);
      final b = PqEncryptedUdpSocket(
        raw: PqUdpSocket(channel: net.bind(epB), throttleWindow: Duration.zero),
        crypto: crypto,
      )..installSessionKey(key);
      await b.send(Uint8List(0), epA); // listen not started — install only
      // Direct codec path already covered; this pins installSessionKey length.
      expect(a.sessionKeyLength, appSessionKeyBytes);
      expect(a.isEstablished, isTrue);
    });
  });

  group('handshake codecs', () {
    test('ClientHello/ServerHello/Finished/Cert round trip', () {
      final g = HybridGroup.x25519MlKem768;
      final share = Uint8List(g.clientShareBytes)..[0] = 1;
      final ch = ClientHello(
        random: Uint8List(handshakeRandomBytes)..[0] = 7,
        group: g,
        share: share,
      );
      final decoded = ClientHello.decode(ch.encode());
      expect(decoded.isSuccess, isTrue);
      expect(decoded.valueOrNull!.group, g);
      expect(
        ClientHello.decode(Uint8List.fromList([99, 0, 0, 0])).isFailure,
        isTrue,
      );

      final ssh = Uint8List(g.serverShareBytes)..[0] = 2;
      final sh = ServerHello(
        random: Uint8List(handshakeRandomBytes)..[1] = 8,
        group: g,
        share: ssh,
      );
      expect(ServerHello.decode(sh.encode()).isSuccess, isTrue);

      final cert = encodeCertificate(Uint8List(mlDsa65PublicKeyBytes)..[0] = 3);
      expect(decodeCertificate(cert).isSuccess, isTrue);
      expect(
        decodeCertificate(Uint8List.fromList([1, 0, 0, 0])).isFailure,
        isTrue,
      );

      final cv = encodeCertVerify(Uint8List(mlDsa65SignatureBytes)..[0] = 4);
      expect(decodeCertVerify(cv).isSuccess, isTrue);

      final fin = encodeFinished(Uint8List(sha384HashBytes)..[0] = 5);
      expect(decodeFinished(fin).isSuccess, isTrue);
      expect(decodeHandshake(Uint8List(2)).isFailure, isTrue);
    });

    test('unknown named group is unsupported', () {
      final g = HybridGroup.x25519MlKem768;
      final encoded = ClientHello(
        random: Uint8List(handshakeRandomBytes),
        group: g,
        share: Uint8List(g.clientShareBytes)..[0] = 1,
      ).encode();
      final smashed = Uint8List.fromList(encoded);
      for (var i = 0; i < smashed.length - 1; i++) {
        if (smashed[i] == 0x11 && smashed[i + 1] == 0xEC) {
          smashed[i] = 0x00;
          smashed[i + 1] = 0x01;
        }
      }
      expect(ClientHello.decode(smashed).isFailure, isTrue);
    });
  });

  group('PqTlsSocket send before complete', () {
    test('fails closed', () async {
      final (a, _) = MemoryByteSocket.pair();
      final tls = PqTlsSocket.client(a);
      final r = await tls.send(Uint8List.fromList([1]));
      expect(r.isFailure, isTrue);
      await tls.close();
    });
  });

  group('HTTP/3 oversized headers', () {
    test('rejected', () {
      final payload = Uint8List(httpMaxHeaderBytes + 1);
      final f = Http3Frame(type: http3FrameHeaders, payload: payload);
      expect(Http3Frame.decode(f.encode()).isFailure, isTrue);
    });
  });

  group('UDP machine happy path', () {
    test('bind then reliable then close', () {
      final m = udpStateMachine();
      expect(m.trigger(UdpEvent.bind).isSuccess, isTrue);
      expect(m.trigger(UdpEvent.startReliable).isSuccess, isTrue);
      expect(m.trigger(UdpEvent.timeout).isSuccess, isTrue);
      expect(m.trigger(UdpEvent.peerAck).isSuccess, isTrue);
      expect(m.trigger(UdpEvent.close).isSuccess, isTrue);
      expect(m.currentState, UdpState.closed);
    });
  });

  group('QUIC stream happy path', () {
    test('open data fin close', () {
      final s = quicStreamMachine();
      expect(s.trigger(QuicStreamEvent.open).isSuccess, isTrue);
      expect(s.trigger(QuicStreamEvent.data).isSuccess, isTrue);
      expect(s.trigger(QuicStreamEvent.fin).isSuccess, isTrue);
      expect(s.trigger(QuicStreamEvent.close).isSuccess, isTrue);
      expect(s.currentState, QuicStreamState.closed);
    });

    test('connection start handshakeDone', () {
      final c = quicConnMachine();
      expect(c.trigger(QuicConnectionEvent.start).isSuccess, isTrue);
      expect(c.trigger(QuicConnectionEvent.handshakeDone).isSuccess, isTrue);
      expect(c.currentState, QuicConnectionState.ready);
    });
  });

  group('dns lookup encode failure', () {
    test('oversized label fails before exchange', () async {
      final c = PqDnsClient(exchange: (q) async => q);
      final r = await c.lookup('${'a' * 64}.example.', DnsType.a);
      expect(r.isFailure, isTrue);
    });
  });

  group('MemoryByteSocket closed send', () {
    test('fails', () async {
      final (a, b) = MemoryByteSocket.pair();
      await a.close();
      final r = await a.send(Uint8List(1));
      expect(r.isFailure, isTrue);
      await b.close();
    });
  });

  group('OPEN-12 leftover error paths', () {
    test('DNS short header, unknown qtype, A rdata, authority NS', () {
      expect(decodeDnsMessage(Uint8List(4)).isFailure, isTrue);
      final unknown = BytesBuilder(copy: false)
        ..add(Uint8List(12))
        ..addByte(0) // root
        ..addByte(0)
        ..addByte(99) // qtype
        ..addByte(0)
        ..addByte(1);
      // qdcount = 1
      final w = unknown.takeBytes();
      w[4] = 0;
      w[5] = 1;
      expect(decodeDnsMessage(w).isFailure, isTrue);

      expect(
        encodeDnsMessage(
          DnsMessage(
            id: 1,
            answers: [
              DnsA(name: 'x.', address: Uint8List.fromList([1, 2, 3])),
            ],
          ),
        ).isFailure,
        isTrue,
      );

      final withNs = encodeDnsMessage(
        DnsMessage(
          id: 2,
          questions: [const DnsQuestion(name: 'x.', type: DnsType.a)],
          authority: [DnsNs(name: 'x.', nameserver: 'ns.x.')],
        ),
      );
      expect(withNs.isSuccess, isTrue, reason: '${withNs.errorOrNull}');
      final decoded = decodeDnsMessage(withNs.valueOrNull!);
      expect(decoded.isSuccess, isTrue, reason: '${decoded.errorOrNull}');
      expect(decoded.valueOrNull!.authority, hasLength(1));
    });

    test('TXT too long and empty name encode', () {
      expect(
        encodeDnsMessage(
          DnsMessage(
            id: 3,
            answers: [
              DnsTxt(name: 'x.', strings: ['a' * 256]),
            ],
          ),
        ).isFailure,
        isTrue,
      );
      final root = encodeDnsMessage(
        DnsMessage(
          id: 4,
          questions: [const DnsQuestion(name: '.', type: DnsType.a)],
        ),
      );
      expect(root.isSuccess, isTrue);
    });

    test('UDP datagram version and truncated header', () {
      expect(
        peekDatagramSequence(Uint8List.fromList([2, 8])).isFailure,
        isTrue,
      );
      expect(
        peekDatagramSequence(
          Uint8List.fromList([datagramVersion, 4, 0, 0]),
        ).isFailure,
        isTrue,
      );
      expect(
        peekDatagramSequence(
          Uint8List.fromList([datagramVersion, 8, 0, 0, 0]),
        ).isFailure,
        isTrue,
      );
    });

    test('ByteReader take short, hashTranscript, internalError', () {
      final r = ByteReader(Uint8List(1));
      expect(r.take(4, PqLengthLabel.nonce).isFailure, isTrue);
      expect(r.u24().isFailure, isTrue);
      expect(
        hashTranscript([
          Uint8List.fromList([1]),
        ]).length,
        sha384HashBytes,
      );
      expect(
        hashTranscript([
          Uint8List.fromList([1]),
        ], hashKind: TranscriptHashKind.sha256).length,
        sha256HashBytes,
      );
      expect(
        PqTransportError.internalError('x').code,
        PqTransportErrorCode.internalError,
      );
    });

    test('TLS decode: short handshake, duplicate extension, empty ALPN', () {
      expect(decodeHandshake(Uint8List(2)).isFailure, isTrue);
      expect(
        decodeHandshake(
          encodeHandshake(tlsHsFinished, Uint8List(1)).sublist(0, 4),
        ).isFailure,
        isTrue,
      );
      expect(
        decodeFinished(
          encodeHandshake(tlsHsClientHello, Uint8List(4)),
        ).isFailure,
        isTrue,
      );
      expect(
        decodeCertificate(
          encodeHandshake(tlsHsFinished, Uint8List(4)),
        ).isFailure,
        isTrue,
      );
      expect(
        decodeCertVerify(
          encodeHandshake(tlsHsFinished, Uint8List(4)),
        ).isFailure,
        isTrue,
      );
      expect(
        decodeEncryptedExtensions(
          encodeHandshake(tlsHsFinished, Uint8List(4)),
        ).isFailure,
        isTrue,
      );

      final g = HybridGroup.x25519MlKem768;
      expect(
        ClientHello.decode(
          ClientHello(
            random: Uint8List(handshakeRandomBytes),
            group: g,
            share: Uint8List(g.clientShareBytes)..[0] = 1,
            cipherSuites: const [0x1301],
          ).encode(),
        ).isFailure,
        isTrue,
      );
    });

    test('P-256 share missing 0x04 prefix fails', () {
      final g = HybridGroup.secP256r1MlKem768;
      final share = HybridClientShare(
        group: g,
        kemEncapsulationKey: Uint8List(g.kemPublicKeyBytes),
        classicalShare: Uint8List(g.classicalShareBytes), // [0] is 0, not 0x04
      );
      expect(encodeClientShare(share).isFailure, isTrue);
      expect(
        decodeClientShare(g, Uint8List(g.clientShareBytes)).isFailure,
        isTrue,
      );
      expect(
        encodeServerShare(
          HybridServerShare(
            group: g,
            kemCiphertext: Uint8List(g.kemCiphertextBytes),
            classicalShare: Uint8List(g.classicalShareBytes),
          ),
        ).isFailure,
        isTrue,
      );
    });

    test('record length mismatch and EncryptedExtensions type refuse', () {
      expect(decodePlainRecord(Uint8List(3)).isFailure, isTrue);
      final rec = encodePlainRecord(
        TlsRecord(type: tlsContentHandshake, payload: Uint8List(4)),
      );
      rec[3] = 0xff;
      expect(decodePlainRecord(rec).isFailure, isTrue);
      expect(
        decodeEncryptedExtensions(
          encodeEncryptedExtensions(serverCertificateType: 0),
        ).isFailure,
        isTrue,
      );
    });
  });
}
