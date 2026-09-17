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
    final hash = Uint8List.fromList(List<int>.generate(32, (i) => 32 - i));
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
    final hash = Uint8List.fromList(List<int>.generate(32, (i) => 3));
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
  });
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

  final done = await server.ingest(afterHs.valueOrNull![0]);
  expect(done.isSuccess, isTrue, reason: '${done.errorOrNull}');
  expect(server.isComplete, isTrue);

  final ctx = Uint8List.fromList([1, 2, 3]);
  expect(client.exporter('test', ctx, 32), server.exporter('test', ctx, 32));
}
