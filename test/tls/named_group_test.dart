import 'dart:typed_data';

import 'package:pqtransport/pqtransport.dart';
import 'package:test/test.dart';

void main() {
  final crypto = PqTransportCrypto();

  test('default offer still selects the hybrid, not X25519', () async {
    final identity = PqTlsServerIdentity.generate(crypto);
    final client = PqTlsClient(crypto: crypto);
    final server = PqTlsServer(crypto: crypto, identity: identity);
    final hello = (await client.startHandshake()).valueOrNull!;
    final decoded = ClientHello.decode(
      unwrapHandshake(hello, quic: false).valueOrNull!,
    );
    expect(decoded.valueOrNull!.offeredKeyShares, hasLength(2));
    expect(
      decoded.valueOrNull!.offeredKeyShares.first.group,
      TlsNamedGroup.x25519MlKem768,
    );
    expect(
      decoded.valueOrNull!.offeredKeyShares.last.group,
      TlsNamedGroup.x25519,
    );
    expect(
      decoded.valueOrNull!.offeredGroupCodepoints.first,
      namedGroupX25519MlKem768,
    );
    final flight = await server.ingest(hello);
    expect(flight.isSuccess, isTrue, reason: '${flight.errorOrNull}');
    final sh = ServerHello.decode(
      unwrapHandshake(flight.valueOrNull!.first, quic: false).valueOrNull!,
    );
    expect(sh.valueOrNull!.group, TlsNamedGroup.x25519MlKem768);
    expect((await client.ingest(flight.valueOrNull![0])).isSuccess, isTrue);
    final fin = await client.ingest(flight.valueOrNull![1]);
    expect(fin.isSuccess, isTrue, reason: '${fin.errorOrNull}');
    expect((await server.ingest(fin.valueOrNull!.single)).isSuccess, isTrue);
    final ctx = Uint8List.fromList([3]);
    expect(
      client.exporter('hybrid', ctx, 16),
      server.exporter('hybrid', ctx, 16),
    );
  }, timeout: const Timeout(Duration(seconds: 30)));

  test('X25519-only handshake matches exporters', () async {
    await _named(crypto, const [TlsNamedGroup.x25519], TlsNamedGroup.x25519);
  }, timeout: const Timeout(Duration(seconds: 20)));

  test('P-256-only handshake matches exporters', () async {
    await _named(crypto, const [
      TlsNamedGroup.secp256r1,
    ], TlsNamedGroup.secp256r1);
  }, timeout: const Timeout(Duration(seconds: 20)));

  test('P-384-only handshake matches exporters', () async {
    await _named(crypto, const [
      TlsNamedGroup.secp384r1,
    ], TlsNamedGroup.secp384r1);
  }, timeout: const Timeout(Duration(seconds: 30)));

  test('MLKEM1024-only handshake matches exporters', () async {
    await _named(crypto, const [
      TlsNamedGroup.mlKem1024,
    ], TlsNamedGroup.mlKem1024);
  }, timeout: const Timeout(Duration(seconds: 60)));

  test('P-256 share without 0x04 is illegal_parameter', () {
    final hello = ClientHello(
      random: Uint8List(handshakeRandomBytes),
      group: TlsNamedGroup.secp256r1,
      share: Uint8List(secp256r1UncompressedBytes),
    );
    final decoded = ClientHello.decode(hello.encode());
    expect(decoded.isFailure, isTrue);
    expect(decoded.errorOrNull!.code, PqTransportErrorCode.illegalParameter);
  });

  test(
    'MLKEM1024 encapsulation key with a coefficient past q is rejected',
    () async {
      final share = Uint8List(mlKem1024PublicKeyBytes);
      // 12-bit coefficient 0x0FFF = 4095, and q is 3329.
      share[0] = 0xff;
      share[1] = 0x0f;
      final hello = ClientHello(
        random: Uint8List(handshakeRandomBytes),
        group: TlsNamedGroup.mlKem1024,
        share: share,
        supportedGroups: const [namedGroupMlKem1024],
      );
      final server = PqTlsServer(crypto: crypto);
      final flight = await server.ingest(
        wrapHandshake(hello.encode(), quic: false),
      );
      expect(flight.isFailure, isTrue);
      expect(flight.errorOrNull!.code, PqTransportErrorCode.illegalParameter);
      expect(server.isComplete, isFalse);
    },
  );
}

Future<void> _named(
  PqTransportCrypto crypto,
  List<TlsNamedGroup> shares,
  TlsNamedGroup selected,
) async {
  final identity = PqTlsServerIdentity.generate(crypto);
  final client = PqTlsClient(crypto: crypto, onlyShares: shares);
  final server = PqTlsServer(crypto: crypto, identity: identity);
  final hello = (await client.startHandshake()).valueOrNull!;
  final flight = await server.ingest(hello);
  expect(flight.isSuccess, isTrue, reason: '${flight.errorOrNull}');
  final sh = ServerHello.decode(
    unwrapHandshake(flight.valueOrNull!.first, quic: false).valueOrNull!,
  );
  expect(sh.valueOrNull!.group, selected);
  final afterSh = await client.ingest(flight.valueOrNull![0]);
  expect(afterSh.isSuccess, isTrue, reason: '${afterSh.errorOrNull}');
  final fin = await client.ingest(flight.valueOrNull![1]);
  expect(fin.isSuccess, isTrue, reason: '${fin.errorOrNull}');
  final done = await server.ingest(fin.valueOrNull!.single);
  expect(done.isSuccess, isTrue, reason: '${done.errorOrNull}');
  expect(client.isComplete, isTrue);
  expect(server.isComplete, isTrue);
  final ctx = Uint8List.fromList([1, 2]);
  expect(client.exporter('named', ctx, 24), server.exporter('named', ctx, 24));
}
