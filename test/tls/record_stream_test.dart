import 'dart:async';
import 'dart:typed_data';

import 'package:pqtransport/pqtransport.dart';
import 'package:swissarmyknife/swissarmyknife.dart';
import 'package:test/test.dart';

void main() {
  test('a handshake split into single bytes still completes', () async {
    final crypto = PqTransportCrypto();
    final identity = PqTlsServerIdentity.generate(crypto);
    final (rawClient, rawServer) = MemoryByteSocket.pair();
    final client = PqTlsSocket.client(
      _OneByteSocket(rawClient),
      crypto: crypto,
    );
    final server = PqTlsSocket.server(
      _OneByteSocket(rawServer),
      crypto: crypto,
      identity: identity,
    );
    final hs = await Future.wait([server.handshake(), client.handshake()]);
    expect(hs[0].isSuccess, isTrue, reason: '${hs[0].errorOrNull}');
    expect(hs[1].isSuccess, isTrue, reason: '${hs[1].errorOrNull}');
    expect(client.peerAuthenticated, isTrue);
    await client.send(Uint8List.fromList([7]));
    final got = await server.applicationData.first.timeout(
      const Duration(seconds: 5),
    );
    expect(got, [7]);
    await client.close();
    await server.close();
  }, timeout: const Timeout(Duration(seconds: 40)));

  test('a record version other than 0x0303 fails closed', () async {
    final (rawClient, rawServer) = MemoryByteSocket.pair();
    final server = PqTlsSocket.server(rawServer);
    final pending = server.handshake();
    await rawClient.send(Uint8List.fromList([22, 0x03, 0x01, 0, 0]));
    final result = await pending;
    expect(result.isFailure, isTrue);
    await rawClient.close();
    await server.close();
  });
}

final class _OneByteSocket implements PqTransportSocket {
  _OneByteSocket(this._inner);

  final PqTransportSocket _inner;

  @override
  Stream<Uint8List> get incoming => _inner.incoming;

  @override
  bool get isClosed => _inner.isClosed;

  @override
  Future<void> close() => _inner.close();

  @override
  Future<Result<void, PqTransportError>> send(Uint8List bytes) async {
    for (final b in bytes) {
      final sent = await _inner.send(Uint8List.fromList([b]));
      if (sent.isFailure) return sent;
    }
    return const Result.success(null);
  }
}
