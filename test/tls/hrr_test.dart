import 'dart:typed_data';

import 'package:pqtransport/pqtransport.dart';
import 'package:test/test.dart';

void main() {
  final crypto = PqTransportCrypto();
  final x25519 = HybridGroup.x25519MlKem768;
  final p256 = HybridGroup.secP256r1MlKem768;

  test('HRR random is SHA-256("HelloRetryRequest")', () {
    expect(
      crypto.sha256(Uint8List.fromList('HelloRetryRequest'.codeUnits)),
      Uint8List.fromList(tlsHelloRetryRequestRandom),
    );
    expect(
      isHelloRetryRequestRandom(Uint8List.fromList(tlsHelloRetryRequestRandom)),
      isTrue,
    );
    expect(isHelloRetryRequestRandom(Uint8List(handshakeRandomBytes)), isFalse);
  });

  test('HelloRetryRequest encodes selected_group + cookie, not a share', () {
    final cookie = Uint8List(tlsCookieBytes)..[0] = 9;
    final hrr = ServerHello.helloRetryRequest(
      selectedGroup: p256,
      cookie: cookie,
    );
    expect(hrr.isHelloRetryRequest, isTrue);
    expect(hrr.share, isEmpty);
    final encoded = hrr.encode();
    final decoded = ServerHello.decode(encoded);
    expect(decoded.isSuccess, isTrue, reason: '${decoded.errorOrNull}');
    final out = decoded.valueOrNull!;
    expect(out.isHelloRetryRequest, isTrue);
    expect(out.group, p256);
    expect(out.share, isEmpty);
    expect(out.cookie, cookie);
    expect(out.cipherSuite, tlsCipherAes256GcmSha256Private);

    final body = decodeHandshake(encoded).valueOrNull!.$2;
    expect(readUint16(body, 0), tlsLegacyVersion);
    expect(
      body.sublist(2, 2 + handshakeRandomBytes),
      Uint8List.fromList(tlsHelloRetryRequestRandom),
    );
  });

  test('HRR without cookie is decode_failure', () {
    final hrr = ServerHello.helloRetryRequest(
      selectedGroup: x25519,
      cookie: Uint8List(tlsCookieBytes)..[0] = 1,
    );
    final hs = hrr.encode();
    // Drop the cookie extension: rebuild as SH-shaped HRR random + NamedGroup
    // share with no cookie by decoding and re-encoding is hard; smash the
    // extension type 44 (cookie) to 45 so parse misses it.
    final smashed = Uint8List.fromList(hs);
    var flipped = false;
    for (var i = 0; i < smashed.length - 1; i++) {
      if (smashed[i] == 0 && smashed[i + 1] == tlsExtCookie) {
        smashed[i + 1] = tlsExtCookie + 1;
        flipped = true;
        break;
      }
    }
    expect(flipped, isTrue);
    final r = ServerHello.decode(smashed);
    expect(r.isFailure, isTrue);
    expect(r.errorOrNull!.code, PqTransportErrorCode.decodeFailure);
  });

  test('real ServerHello encode omits cookie and is not HRR', () {
    final sh = ServerHello(
      random: Uint8List(handshakeRandomBytes)..[1] = 3,
      group: x25519,
      share: Uint8List(x25519.serverShareBytes)..[0] = 2,
      cookie: Uint8List(tlsCookieBytes)..[0] = 1,
    );
    expect(sh.isHelloRetryRequest, isFalse);
    final decoded = ServerHello.decode(sh.encode());
    expect(decoded.isSuccess, isTrue, reason: '${decoded.errorOrNull}');
    expect(decoded.valueOrNull!.isHelloRetryRequest, isFalse);
    expect(decoded.valueOrNull!.cookie, isNull);
  });

  test('ClientHello cookie round-trips (OPEN-05 echo)', () {
    final cookie = Uint8List(tlsCookieBytes)..[3] = 7;
    final ch = ClientHello(
      random: Uint8List(handshakeRandomBytes)..[0] = 4,
      group: x25519,
      share: Uint8List(x25519.clientShareBytes)..[0] = 1,
      supportedGroups: [x25519.codepoint, p256.codepoint],
      cookie: cookie,
    );
    final decoded = ClientHello.decode(ch.encode());
    expect(decoded.isSuccess, isTrue, reason: '${decoded.errorOrNull}');
    expect(decoded.valueOrNull!.cookie, cookie);
    expect(decoded.valueOrNull!.offeredGroupCodepoints, [
      x25519.codepoint,
      p256.codepoint,
    ]);
  });

  test('RFC 8446 message_hash replaces ClientHello1 in the transcript', () {
    final ch = ClientHello(
      random: Uint8List(handshakeRandomBytes)..[0] = 1,
      group: x25519,
      share: Uint8List(x25519.clientShareBytes)..[0] = 1,
    ).encode();
    final hrr = ServerHello.helloRetryRequest(
      selectedGroup: p256,
      cookie: Uint8List(tlsCookieBytes)..[0] = 2,
    ).encode();
    final t = Transcript();
    t.add(ch);
    rewriteTranscriptForHelloRetry(
      transcript: t,
      clientHello1: ch,
      helloRetryRequest: hrr,
      sha256: crypto.sha256,
    );
    expect(t.bytes[0], tlsHsMessageHash);
    expect(readUint24(t.bytes, 1), transcriptHashBytes);
    expect(
      t.bytes.sublist(
        tlsHandshakeHeaderBytes,
        tlsHandshakeHeaderBytes + transcriptHashBytes,
      ),
      crypto.sha256(ch),
    );
    expect(t.bytes.sublist(tlsHandshakeHeaderBytes + transcriptHashBytes), hrr);
  });

  test(
    'live HRR: client offers X25519+P-256, server selects P-256, exporters match',
    () async {
      final identity = PqTlsServerIdentity.generate(crypto);
      final client = PqTlsClient(
        crypto: crypto,
        group: x25519,
        offeredGroups: [x25519, p256],
      );
      final server = PqTlsServer(
        crypto: crypto,
        identity: identity,
        group: p256,
      );

      final ch1 = await client.startHandshake();
      expect(ch1.isSuccess, isTrue, reason: '${ch1.errorOrNull}');

      final hrrFlight = await server.ingest(ch1.valueOrNull!);
      expect(hrrFlight.isSuccess, isTrue, reason: '${hrrFlight.errorOrNull}');
      expect(hrrFlight.valueOrNull!, hasLength(1));
      expect(server.helloRetryCount, 1);
      expect(server.state, TlsState.waitClientHello);

      final hrrRec = decodePlainRecord(hrrFlight.valueOrNull![0]);
      final hrr = ServerHello.decode(hrrRec.valueOrNull!.payload);
      expect(hrr.valueOrNull!.isHelloRetryRequest, isTrue);
      expect(hrr.valueOrNull!.group, p256);
      expect(hrr.valueOrNull!.cookie, isNotNull);

      final ch2 = await client.ingest(hrrFlight.valueOrNull![0]);
      expect(ch2.isSuccess, isTrue, reason: '${ch2.errorOrNull}');
      expect(ch2.valueOrNull!, hasLength(1));
      expect(client.helloRetryCount, 1);
      expect(client.state, TlsState.clientHelloSent);
      final ch2Body = ClientHello.decode(
        decodePlainRecord(ch2.valueOrNull![0]).valueOrNull!.payload,
      );
      expect(ch2Body.valueOrNull!.group, p256);
      expect(ch2Body.valueOrNull!.cookie, hrr.valueOrNull!.cookie);

      final shFlight = await server.ingest(ch2.valueOrNull![0]);
      expect(shFlight.isSuccess, isTrue, reason: '${shFlight.errorOrNull}');
      expect(shFlight.valueOrNull!, hasLength(2));
      expect(
        ServerHello.decode(
          decodePlainRecord(shFlight.valueOrNull![0]).valueOrNull!.payload,
        ).valueOrNull!.isHelloRetryRequest,
        isFalse,
      );

      final afterSh = await client.ingest(shFlight.valueOrNull![0]);
      expect(afterSh.isSuccess, isTrue, reason: '${afterSh.errorOrNull}');
      final afterHs = await client.ingest(shFlight.valueOrNull![1]);
      expect(afterHs.isSuccess, isTrue, reason: '${afterHs.errorOrNull}');
      expect(afterHs.valueOrNull!, hasLength(1));
      expect(client.isComplete, isTrue);

      final done = await server.ingest(afterHs.valueOrNull![0]);
      expect(done.isSuccess, isTrue, reason: '${done.errorOrNull}');
      expect(server.isComplete, isTrue);

      final ctx = Uint8List.fromList([1, 2, 3]);
      expect(client.exporter('hrr', ctx, 32), server.exporter('hrr', ctx, 32));
    },
    timeout: const Timeout(Duration(seconds: 45)),
  );

  test('same-group handshake does not emit HRR', () async {
    final client = PqTlsClient(crypto: crypto);
    final server = PqTlsServer(crypto: crypto);
    final ch = (await client.startHandshake()).valueOrNull!;
    final flight = await server.ingest(ch);
    expect(flight.isSuccess, isTrue, reason: '${flight.errorOrNull}');
    expect(flight.valueOrNull!, hasLength(2));
    expect(server.helloRetryCount, 0);
    final sh = ServerHello.decode(
      decodePlainRecord(flight.valueOrNull![0]).valueOrNull!.payload,
    );
    expect(sh.valueOrNull!.isHelloRetryRequest, isFalse);
  }, timeout: const Timeout(Duration(seconds: 30)));

  test('second wire HRR fails closed (GATE-11)', () async {
    final client = PqTlsClient(
      crypto: crypto,
      group: x25519,
      offeredGroups: [x25519, p256],
    );
    await client.startHandshake();
    final hrr = encodePlainRecord(
      TlsRecord(
        type: tlsContentHandshake,
        payload: ServerHello.helloRetryRequest(
          selectedGroup: p256,
          cookie: Uint8List(tlsCookieBytes)..[0] = 1,
        ).encode(),
      ),
    );
    expect((await client.ingest(hrr)).isSuccess, isTrue);
    final second = await client.ingest(hrr);
    expect(second.isFailure, isTrue);
    expect(client.state, TlsState.failed);
  }, timeout: const Timeout(Duration(seconds: 30)));

  test('CH2 with cookie but original group is second hello retry', () async {
    final server = PqTlsServer(crypto: crypto, group: p256);
    final client = PqTlsClient(
      crypto: crypto,
      group: x25519,
      offeredGroups: [x25519, p256],
    );
    final ch1 = (await client.startHandshake()).valueOrNull!;
    final hrrFlight = (await server.ingest(ch1)).valueOrNull!;
    final cookie = ServerHello.decode(
      decodePlainRecord(hrrFlight[0]).valueOrNull!.payload,
    ).valueOrNull!.cookie!;
    final fake = ClientHello(
      random: Uint8List(handshakeRandomBytes),
      group: x25519,
      share: Uint8List(x25519.clientShareBytes)..[0] = 1,
      supportedGroups: [x25519.codepoint, p256.codepoint],
      cookie: cookie,
    );
    final r = await server.ingest(
      encodePlainRecord(
        TlsRecord(type: tlsContentHandshake, payload: fake.encode()),
      ),
    );
    expect(r.isFailure, isTrue);
    expect(r.errorOrNull!.message, contains('second hello retry'));
    expect(server.state, TlsState.failed);
  }, timeout: const Timeout(Duration(seconds: 30)));

  test('CH2 cookie mismatch fails closed', () async {
    final server = PqTlsServer(crypto: crypto, group: p256);
    final client = PqTlsClient(
      crypto: crypto,
      group: x25519,
      offeredGroups: [x25519, p256],
    );
    final ch1 = (await client.startHandshake()).valueOrNull!;
    await server.ingest(ch1);
    final fake = ClientHello(
      random: Uint8List(handshakeRandomBytes),
      group: p256,
      share: Uint8List(p256.clientShareBytes)..[0] = uncompressedPointPrefix,
      supportedGroups: [x25519.codepoint, p256.codepoint],
      cookie: Uint8List(tlsCookieBytes)..[0] = 0xff,
    );
    final r = await server.ingest(
      encodePlainRecord(
        TlsRecord(type: tlsContentHandshake, payload: fake.encode()),
      ),
    );
    expect(r.isFailure, isTrue);
    expect(r.errorOrNull!.message, contains('cookie mismatch'));
  }, timeout: const Timeout(Duration(seconds: 30)));

  test('group not offered is mismatch, not HRR', () async {
    final server = PqTlsServer(crypto: crypto, group: p256);
    final client = PqTlsClient(crypto: crypto, group: x25519);
    final ch = (await client.startHandshake()).valueOrNull!;
    final r = await server.ingest(ch);
    expect(r.isFailure, isTrue);
    expect(r.errorOrNull!.message, contains('group mismatch'));
    expect(server.helloRetryCount, 0);
  }, timeout: const Timeout(Duration(seconds: 30)));

  test('PqTlsSocket completes an HRR handshake', () async {
    final identity = PqTlsServerIdentity.generate(crypto);
    final (clientSock, serverSock) = MemoryByteSocket.pair();
    final client = PqTlsSocket.client(
      clientSock,
      crypto: crypto,
      group: x25519,
      offeredGroups: [x25519, p256],
    );
    final server = PqTlsSocket.server(
      serverSock,
      crypto: crypto,
      identity: identity,
      group: p256,
    );
    final hs = await Future.wait([server.handshake(), client.handshake()]);
    expect(hs[0].isSuccess, isTrue, reason: '${hs[0].errorOrNull}');
    expect(hs[1].isSuccess, isTrue, reason: '${hs[1].errorOrNull}');
    expect(client.isComplete, isTrue);
    expect(server.isComplete, isTrue);
    final ctx = Uint8List.fromList([4, 5]);
    expect(client.exporter('sock', ctx, 16), server.exporter('sock', ctx, 16));
    await client.close();
    await server.close();
  }, timeout: const Timeout(Duration(seconds: 45)));
}
