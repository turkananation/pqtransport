import 'dart:typed_data';

import 'package:pqtransport/pqtransport.dart';
import 'package:test/test.dart';

void main() {
  test('stream credit stalls, then completes after MAX_STREAM_DATA', () async {
    final linked = await _linked(maxStreamData: 4, maxData: 100, flowWindow: 4);
    final id = linked.client.openBidi();
    final wrote = await linked.client.writeStream(
      id,
      Uint8List.fromList([1, 2, 3, 4, 5, 6, 7, 8]),
    );
    expect(wrote.isSuccess, isTrue, reason: '${wrote.errorOrNull}');
    await _pump();
    expect(linked.server.readStream(id), [1, 2, 3, 4]);
    final flushed = await linked.server.flushControl();
    expect(flushed.isSuccess, isTrue, reason: '${flushed.errorOrNull}');
    await _pump();
    expect(linked.server.readStream(id), [5, 6, 7, 8]);
  });

  test(
    'connection credit stalls when the stream limit would allow it',
    () async {
      final linked = await _linked(
        maxStreamData: 100,
        maxData: 4,
        flowWindow: 4,
      );
      final id = linked.client.openBidi();
      final wrote = await linked.client.writeStream(
        id,
        Uint8List.fromList([1, 2, 3, 4, 5, 6, 7, 8]),
      );
      expect(wrote.isSuccess, isTrue, reason: '${wrote.errorOrNull}');
      await _pump();
      expect(linked.server.readStream(id), [1, 2, 3, 4]);
      final flushed = await linked.server.flushControl();
      expect(flushed.isSuccess, isTrue, reason: '${flushed.errorOrNull}');
      await _pump();
      expect(linked.server.readStream(id), [5, 6, 7, 8]);
    },
  );

  test('inbound STREAM past the receive limit closes the connection', () async {
    final linked = await _linked(maxStreamData: 20, serverRecvStream: 4);
    final id = linked.client.openBidi();
    final wrote = await linked.client.writeStream(
      id,
      Uint8List.fromList([1, 2, 3, 4, 5, 6, 7, 8]),
    );
    expect(wrote.isSuccess, isTrue, reason: '${wrote.errorOrNull}');
    await _pump();
    expect(linked.server.readStream(id), isEmpty);
    expect(linked.server.isDraining || linked.server.isClosed, isTrue);
    final more = await linked.server.writeStream(id, Uint8List.fromList([9]));
    expect(more.isFailure, isTrue);
    expect(more.errorOrNull!.code, PqTransportErrorCode.closed);
  });

  test('idle timeout closes and a later send fails', () async {
    final clock = QuicManualClock();
    final linked = await _linked(
      clock: clock,
      idleTimeout: const Duration(seconds: 5),
    );
    final id = linked.client.openBidi();
    clock.advance(const Duration(seconds: 5));
    final driven = await linked.client.driveLossRecovery();
    expect(driven.isFailure, isTrue);
    expect(driven.errorOrNull!.code, PqTransportErrorCode.closed);
    expect(linked.client.isClosed, isTrue);
    final wrote = await linked.client.writeStream(id, Uint8List.fromList([1]));
    expect(wrote.isFailure, isTrue);
    expect(linked.server.readStream(id), isEmpty);
  });

  test('CONNECTION_CLOSE from either role is terminal', () async {
    final clientClose = await _linked();
    final id = clientClose.client.openBidi();
    final closed = await clientClose.client.close();
    expect(closed.isSuccess, isTrue, reason: '${closed.errorOrNull}');
    await _pump();
    expect(
      clientClose.client.isDraining || clientClose.client.isClosed,
      isTrue,
    );
    expect(
      clientClose.server.isDraining || clientClose.server.isClosed,
      isTrue,
    );
    final again = await clientClose.client.close();
    expect(again.isFailure, isTrue);
    final wrote = await clientClose.client.writeStream(
      id,
      Uint8List.fromList([1, 2, 3]),
    );
    expect(wrote.isFailure, isTrue);
    expect(clientClose.server.readStream(id), isEmpty);
    final peerWrote = await clientClose.server.writeStream(
      id,
      Uint8List.fromList([4]),
    );
    expect(peerWrote.isFailure, isTrue);

    final serverClose = await _linked();
    final sid = serverClose.server.openBidi();
    final fromServer = await serverClose.server.close();
    expect(fromServer.isSuccess, isTrue, reason: '${fromServer.errorOrNull}');
    await _pump();
    expect(
      serverClose.client.isDraining || serverClose.client.isClosed,
      isTrue,
    );
    final clientWrote = await serverClose.client.writeStream(
      sid,
      Uint8List.fromList([1]),
    );
    expect(clientWrote.isFailure, isTrue);
    expect(serverClose.server.readStream(sid), isEmpty);
  });

  test('drain discards inbound packets, then the connection closes', () async {
    final clock = QuicManualClock();
    final linked = await _linked(clock: clock);
    final before = linked.fromClient;
    final closed = await linked.client.close();
    expect(closed.isSuccess, isTrue, reason: '${closed.errorOrNull}');
    await _pump();
    final afterClose = linked.fromClient;
    expect(afterClose, greaterThan(before));
    final discarded = await linked.client.ingestDatagram(Uint8List(32));
    expect(discarded.isSuccess, isTrue, reason: '${discarded.errorOrNull}');
    await _pump();
    expect(linked.fromClient, afterClose);
    clock.advance(const Duration(minutes: 5));
    final driven = await linked.client.driveLossRecovery();
    expect(driven.isFailure, isTrue);
    expect(linked.client.isClosed, isTrue);
  });

  test('RESET_STREAM is an error the peer can observe', () async {
    final linked = await _linked();
    final id = linked.client.openBidi();
    final seeded = await linked.client.writeStream(
      id,
      Uint8List.fromList([1, 2]),
    );
    expect(seeded.isSuccess, isTrue, reason: '${seeded.errorOrNull}');
    await _pump();
    final reset = await linked.client.resetStream(id, 17);
    expect(reset.isSuccess, isTrue, reason: '${reset.errorOrNull}');
    await _pump();
    expect(linked.server.streamResetCode(id), 17);
    expect(linked.client.streamResetCode(id), 17);
    final wrote = await linked.client.writeStream(id, Uint8List.fromList([3]));
    expect(wrote.isFailure, isTrue);
    expect(wrote.errorOrNull!.code, PqTransportErrorCode.closed);
  });
}

Future<void> _pump() async {
  for (var i = 0; i < 40; i++) {
    await Future<void>.delayed(Duration.zero);
  }
}

final class _Ends {
  _Ends(this.client, this.server, this._fromClient);
  final PqQuicConn client;
  final PqQuicConn server;
  final List<int> _fromClient;
  int get fromClient => _fromClient[0];
}

Future<_Ends> _linked({
  QuicClock? clock,
  int maxStreamData = quicMaxStreamDataDefault,
  int maxData = quicMaxDataDefault,
  int flowWindow = 0,
  int? serverRecvStream,
  Duration? idleTimeout,
}) async {
  final crypto = PqTransportCrypto();
  final identity = PqTlsServerIdentity.generate(crypto);
  final clientCid = crypto.randomBytes(quicShortDcidBytes);
  final serverCid = crypto.randomBytes(quicShortDcidBytes);
  late PqQuicConn client;
  late PqQuicConn server;
  final sent = <int>[0];
  client = PqQuicConn.client(
    crypto: crypto,
    localCid: clientCid,
    peerCid: serverCid,
    clock: clock,
    maxData: maxData,
    maxStreamData: maxStreamData,
    flowWindow: flowWindow,
    idleTimeout: idleTimeout,
    deliver: (packet) {
      if ((packet[0] & 0x80) == 0) sent[0]++;
      return server.ingestDatagram(packet);
    },
  );
  server = PqQuicConn.server(
    crypto: crypto,
    identity: identity,
    localCid: serverCid,
    peerCid: clientCid,
    clock: clock,
    maxData: maxData,
    maxStreamData: maxStreamData,
    recvMaxStreamData: serverRecvStream,
    flowWindow: flowWindow,
    idleTimeout: idleTimeout,
    deliver: (packet) => client.ingestDatagram(packet),
  );
  final hand = await client.handshake();
  expect(hand.isSuccess, isTrue, reason: '${hand.errorOrNull}');
  await _pump();
  return _Ends(client, server, sent);
}
