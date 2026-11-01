import 'dart:convert';
import 'dart:typed_data';

import 'package:pqtransport/pqtransport.dart';
import 'package:test/test.dart';

void main() {
  final crypto = PqTransportCrypto();

  test('ECH handshake hides the inner name and exporters match', () async {
    const innerName = 'secret.example';
    const publicName = 'public.example';
    final ech = await EchServerConfig.generate(
      crypto,
      publicName: publicName,
      maximumNameLength: 64,
    );
    final identity = PqTlsServerIdentity.generate(crypto);
    final client = PqTlsClient(
      crypto: crypto,
      serverName: innerName,
      ech: ech.config,
    );
    final server = PqTlsServer(crypto: crypto, identity: identity, ech: ech);

    final ch = await client.startHandshake();
    expect(ch.isSuccess, isTrue, reason: '${ch.errorOrNull}');
    final wire = ch.valueOrNull!;
    expect(latin1.decode(wire, allowInvalid: true), contains(publicName));
    expect(latin1.decode(wire, allowInvalid: true), isNot(contains(innerName)));

    final serverFlight = await server.ingest(wire);
    expect(
      serverFlight.isSuccess,
      isTrue,
      reason: '${serverFlight.errorOrNull}',
    );
    expect(server.acceptedServerName, innerName);

    final afterSh = await client.ingest(serverFlight.valueOrNull![0]);
    expect(afterSh.isSuccess, isTrue, reason: '${afterSh.errorOrNull}');
    final afterHs = await client.ingest(serverFlight.valueOrNull![1]);
    expect(afterHs.isSuccess, isTrue, reason: '${afterHs.errorOrNull}');
    expect(client.isComplete, isTrue);
    expect(client.peerAuthenticated, isTrue);

    final done = await server.ingest(afterHs.valueOrNull![0]);
    expect(done.isSuccess, isTrue, reason: '${done.errorOrNull}');
    expect(server.isComplete, isTrue);
    final ctx = Uint8List.fromList([9]);
    expect(client.exporter('ech', ctx, 32), server.exporter('ech', ctx, 32));
  }, timeout: const Timeout(Duration(seconds: 30)));

  test('ECH rejection does not continue in the clear', () async {
    final ech = await EchServerConfig.generate(
      crypto,
      publicName: 'public.example',
    );
    final identity = PqTlsServerIdentity.generate(crypto);
    final client = PqTlsClient(
      crypto: crypto,
      serverName: 'secret.example',
      ech: ech.config,
    );
    final server = PqTlsServer(crypto: crypto, identity: identity);

    final ch = await client.startHandshake();
    expect(ch.isSuccess, isTrue, reason: '${ch.errorOrNull}');
    final flight = await server.ingest(ch.valueOrNull!);
    expect(flight.isSuccess, isTrue, reason: '${flight.errorOrNull}');

    final rejected = await client.ingest(flight.valueOrNull![0]);
    expect(rejected.isFailure, isTrue);
    expect(rejected.errorOrNull!.alert, tlsAlertEchRequired);
    expect(client.state, TlsState.failed);
    expect(client.isComplete, isFalse);
    expect(client.peerAuthenticated, isFalse);
  }, timeout: const Timeout(Duration(seconds: 30)));

  test('a server with an ECH key does not accept the outer hello', () async {
    final ech = await EchServerConfig.generate(
      crypto,
      publicName: 'public.example',
    );
    final other = await EchServerConfig.generate(
      crypto,
      publicName: 'public.example',
      configId: 2,
    );
    final identity = PqTlsServerIdentity.generate(crypto);
    final client = PqTlsClient(
      crypto: crypto,
      serverName: 'secret.example',
      ech: other.config,
    );
    final server = PqTlsServer(crypto: crypto, identity: identity, ech: ech);

    final ch = await client.startHandshake();
    final flight = await server.ingest(ch.valueOrNull!);
    expect(flight.isFailure, isTrue);
    expect(flight.errorOrNull!.alert, tlsAlertDecryptError);
    expect(server.isComplete, isFalse);
    expect(server.acceptedServerName, isNull);
  }, timeout: const Timeout(Duration(seconds: 30)));
}
