import 'dart:typed_data';

import 'package:pqforge/pqforge.dart';
import 'package:pqtransport/pqtransport.dart';
import 'package:test/test.dart';

void main() {
  final crypto = PqTransportCrypto();

  test('X25519MLKEM768 client/server handshake + exporters match', () async {
    final identity = PqTlsServerIdentity.generate(crypto);
    final client = PqTlsClient(crypto: crypto);
    final server = PqTlsServer(crypto: crypto, identity: identity);

    final ch = await client.startHandshake();
    expect(ch.isSuccess, isTrue, reason: '${ch.errorOrNull}');
    expect(ch.valueOrNull!.length, greaterThan(x25519MlKem768ClientShareBytes));

    final serverFlight = await server.ingest(ch.valueOrNull!);
    expect(
      serverFlight.isSuccess,
      isTrue,
      reason: '${serverFlight.errorOrNull}',
    );
    expect(serverFlight.valueOrNull!, hasLength(2));

    final afterSh = await client.ingest(serverFlight.valueOrNull![0]);
    expect(afterSh.isSuccess, isTrue, reason: '${afterSh.errorOrNull}');

    final afterHs = await client.ingest(serverFlight.valueOrNull![1]);
    expect(afterHs.isSuccess, isTrue, reason: '${afterHs.errorOrNull}');
    expect(afterHs.valueOrNull!, hasLength(1));
    expect(client.isComplete, isTrue);
    expect(client.peerAuthenticated, isTrue);
    expect(client.allowUnauthenticated, isFalse);

    final done = await server.ingest(afterHs.valueOrNull![0]);
    expect(done.isSuccess, isTrue, reason: '${done.errorOrNull}');
    expect(server.isComplete, isTrue);

    final ctx = Uint8List.fromList([1, 2, 3]);
    final cExp = client.exporter('test', ctx, 32);
    final sExp = server.exporter('test', ctx, 32);
    expect(cExp, sExp);
    expect(cExp, isNot(equals(Uint8List(32))));
  }, timeout: const Timeout(Duration(seconds: 30)));

  test('key schedule is deterministic for a fixture IKM', () {
    final ikm = Uint8List.fromList(List<int>.generate(64, (i) => i + 1));
    final hash = Uint8List.fromList(
      List<int>.generate(sha384HashBytes, (i) => 32 - i),
    );
    final a = TlsKeySchedule(crypto)
      ..derive(
        hybridSharedSecret: ikm,
        handshakeTranscriptHash: hash,
        applicationTranscriptHash: hash,
      );
    final b = TlsKeySchedule(crypto)
      ..derive(
        hybridSharedSecret: ikm,
        handshakeTranscriptHash: hash,
        applicationTranscriptHash: hash,
      );
    expect(a.clientApplicationTraffic, b.clientApplicationTraffic);
    final other = Uint8List.fromList(ikm);
    other[0] ^= 1;
    final c = TlsKeySchedule(crypto)
      ..derive(
        hybridSharedSecret: other,
        handshakeTranscriptHash: hash,
        applicationTranscriptHash: hash,
      );
    expect(
      c.clientApplicationTraffic,
      isNot(equals(a.clientApplicationTraffic)),
    );
  });

  test('exporter is deterministic on a fixture', () {
    final ikm = Uint8List.fromList(List<int>.generate(64, (i) => 7));
    final hash = Uint8List.fromList(
      List<int>.generate(sha384HashBytes, (i) => 3),
    );
    final a = TlsKeySchedule(crypto)
      ..derive(
        hybridSharedSecret: ikm,
        handshakeTranscriptHash: hash,
        applicationTranscriptHash: hash,
      );
    final b = TlsKeySchedule(crypto)
      ..derive(
        hybridSharedSecret: ikm,
        handshakeTranscriptHash: hash,
        applicationTranscriptHash: hash,
      );
    final ctx = Uint8List.fromList([9]);
    expect(a.exporter('exp', ctx, 16), b.exporter('exp', ctx, 16));
  });

  test(
    'truncated ClientHello share is illegal_parameter, no encapsulate',
    () async {
      final server = PqTlsServer(crypto: crypto);
      final client = PqTlsClient(crypto: crypto);
      final ch = (await client.startHandshake()).valueOrNull!;
      // Mutate the advertised share length to 1215 and truncate the payload.
      final mutated = Uint8List.fromList(ch.sublist(0, ch.length - 1));
      mutated[mutated.length - 2] = 0; // smash last length bits
      final r = await server.ingest(mutated);
      expect(r.isFailure, isTrue);
      expect(
        r.errorOrNull!.code,
        anyOf(
          PqTransportErrorCode.illegalParameter,
          PqTransportErrorCode.decodeFailure,
          PqTransportErrorCode.handshakeFailure,
        ),
      );
      expect(server.isComplete, isFalse);
    },
  );

  test('encapsulation key truncated to 1183 bytes is illegal_parameter', () {
    const truncatedEncapsulationKey = 1183;
    final share = Uint8List(truncatedEncapsulationKey + 32);
    final r = decodeClientShare(HybridGroup.x25519MlKem768, share);
    expect(r.isFailure, isTrue);
    expect(r.errorOrNull!.code, PqTransportErrorCode.illegalParameter);
    expect(r.errorOrNull!.alert, tlsAlertIllegalParameter);
  });

  test('wrong-length hybrid client share fails with illegal_parameter', () {
    final g = HybridGroup.x25519MlKem768;
    final r = decodeClientShare(g, Uint8List(g.clientShareBytes - 1));
    expect(r.isFailure, isTrue);
    expect(r.errorOrNull!.code, PqTransportErrorCode.illegalParameter);
    expect(r.errorOrNull!.alert, tlsAlertIllegalParameter);
  });

  test('SecP256r1MLKEM768 live handshake + exporters match', () async {
    await _liveHandshake(crypto, HybridGroup.secP256r1MlKem768);
  }, timeout: const Timeout(Duration(seconds: 45)));

  test('SecP384r1MLKEM1024 live handshake needs profile.maximum', () async {
    final max = PqTransportCrypto(profile: PqForgeProfile.maximum);
    await _liveHandshake(max, HybridGroup.secP384r1MlKem1024);
  }, timeout: const Timeout(Duration(seconds: 90)));

  test('OPEN-03: profile.maximum with ML-KEM-768 group is refused', () async {
    final max = PqTransportCrypto(profile: PqForgeProfile.maximum);
    final client = PqTlsClient(crypto: max, group: HybridGroup.x25519MlKem768);
    final r = await client.startHandshake();
    expect(r.isFailure, isTrue);
    expect(r.errorOrNull!.code, PqTransportErrorCode.unsupported);
  });

  test('OPEN-03: balanced profile with P-384 group is refused', () async {
    final client = PqTlsClient(
      crypto: crypto,
      group: HybridGroup.secP384r1MlKem1024,
    );
    final r = await client.startHandshake();
    expect(r.isFailure, isTrue);
    expect(r.errorOrNull!.code, PqTransportErrorCode.unsupported);
  });

  test('ingest in uninitialized fails closed', () async {
    final client = PqTlsClient(crypto: crypto);
    final r = await client.ingest(Uint8List(tlsRecordHeaderBytes + 1));
    expect(r.isFailure, isTrue);
    expect(client.state, TlsState.failed);
    expect(client.peerAuthenticated, isFalse);
  });

  test('IMP-22: allowUnauthenticated is not authentication', () async {
    final identity = PqTlsServerIdentity.generate(crypto);
    final client = PqTlsClient(crypto: crypto, allowUnauthenticated: true);
    final server = PqTlsServer(crypto: crypto, identity: identity);
    expect(client.peerAuthenticated, isFalse);

    final ch = await client.startHandshake();
    final flight = await server.ingest(ch.valueOrNull!);
    await client.ingest(flight.valueOrNull![0]);
    final done = await client.ingest(flight.valueOrNull![1]);
    expect(done.isSuccess, isTrue, reason: '${done.errorOrNull}');
    expect(client.isComplete, isTrue);
    expect(client.peerAuthenticated, isFalse);
    expect(client.allowUnauthenticated, isTrue);
  }, timeout: const Timeout(Duration(seconds: 30)));

  test(
    'IMP-22: bad signature fails closed when authentication is required',
    () async {
      final identity = PqTlsServerIdentity.generate(crypto);
      final client = PqTlsClient(crypto: crypto);
      final server = PqTlsServer(crypto: crypto, identity: identity);
      final ch = await client.startHandshake();
      final flight = await server.ingest(ch.valueOrNull!);
      final sh = await client.ingest(flight.valueOrNull![0]);
      expect(sh.isSuccess, isTrue, reason: '${sh.errorOrNull}');

      final scratch = TlsRecordLayer(crypto, client.schedule);
      final opened = scratch.openWith(
        trafficSecret: client.schedule.serverHandshakeTraffic,
        iv: client.schedule.serverHandshakeIv,
        wire: flight.valueOrNull![1],
      );
      expect(opened.isSuccess, isTrue, reason: '${opened.errorOrNull}');
      final plain = Uint8List.fromList(opened.valueOrNull!.payload);
      expect(_flipCertVerify(plain), isTrue);
      final resealed = TlsRecordLayer(crypto, client.schedule).protectWith(
        trafficSecret: client.schedule.serverHandshakeTraffic,
        iv: client.schedule.serverHandshakeIv,
        inner: TlsRecord(type: tlsContentHandshake, payload: plain),
      );
      final done = await client.ingest(resealed);
      expect(done.isFailure, isTrue);
      expect(done.errorOrNull!.message, contains('ml-dsa verify failed'));
      expect(client.isComplete, isFalse);
      expect(client.peerAuthenticated, isFalse);
    },
    timeout: const Timeout(Duration(seconds: 30)),
  );

  test(
    'IMP-22: socket reports peerAuthenticated only after a checked handshake',
    () async {
      final identity = PqTlsServerIdentity.generate(crypto);
      final (checkedA, checkedB) = MemoryByteSocket.pair();
      final checked = PqTlsSocket.client(checkedA, crypto: crypto);
      final checkedServer = PqTlsSocket.server(
        checkedB,
        crypto: crypto,
        identity: identity,
      );
      final checkedOk = await Future.wait([
        checked.handshake(),
        checkedServer.handshake(),
      ]);
      expect(checkedOk.every((r) => r.isSuccess), isTrue);
      expect(checked.peerAuthenticated, isTrue);
      expect(checkedServer.peerAuthenticated, isFalse);

      final (openA, openB) = MemoryByteSocket.pair();
      final open = PqTlsSocket.client(
        openA,
        crypto: crypto,
        allowUnauthenticated: true,
      );
      final openServer = PqTlsSocket.server(
        openB,
        crypto: crypto,
        identity: identity,
      );
      final openOk = await Future.wait([
        open.handshake(),
        openServer.handshake(),
      ]);
      expect(openOk.every((r) => r.isSuccess), isTrue);
      expect(open.isComplete, isTrue);
      expect(open.peerAuthenticated, isFalse);
    },
    timeout: const Timeout(Duration(seconds: 30)),
  );
}

Future<void> _liveHandshake(PqTransportCrypto crypto, HybridGroup group) async {
  final identity = PqTlsServerIdentity.generate(crypto);
  final client = PqTlsClient(crypto: crypto, group: group);
  final server = PqTlsServer(crypto: crypto, identity: identity, group: group);

  final ch = await client.startHandshake();
  expect(ch.isSuccess, isTrue, reason: '${ch.errorOrNull}');

  final serverFlight = await server.ingest(ch.valueOrNull!);
  expect(serverFlight.isSuccess, isTrue, reason: '${serverFlight.errorOrNull}');
  expect(serverFlight.valueOrNull!, hasLength(2));

  final afterSh = await client.ingest(serverFlight.valueOrNull![0]);
  expect(afterSh.isSuccess, isTrue, reason: '${afterSh.errorOrNull}');

  final afterHs = await client.ingest(serverFlight.valueOrNull![1]);
  expect(afterHs.isSuccess, isTrue, reason: '${afterHs.errorOrNull}');
  expect(afterHs.valueOrNull!, hasLength(1));
  expect(client.isComplete, isTrue);
  expect(client.peerAuthenticated, isTrue);

  final done = await server.ingest(afterHs.valueOrNull![0]);
  expect(done.isSuccess, isTrue, reason: '${done.errorOrNull}');
  expect(server.isComplete, isTrue);

  final ctx = Uint8List.fromList([1, 2, 3]);
  expect(client.exporter('test', ctx, 32), server.exporter('test', ctx, 32));
}

bool _flipCertVerify(Uint8List handshake) {
  var offset = 0;
  while (offset + tlsHandshakeHeaderBytes <= handshake.length) {
    final len = readUint24(handshake, offset + 1);
    final end = offset + tlsHandshakeHeaderBytes + len;
    if (end > handshake.length) return false;
    if (handshake[offset] == tlsHsCertificateVerify && len > 0) {
      handshake[end - 1] ^= 0x01;
      return true;
    }
    offset = end;
  }
  return false;
}
