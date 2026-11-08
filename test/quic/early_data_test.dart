import 'dart:typed_data';

import 'package:pqtransport/pqtransport.dart';
import 'package:test/test.dart';

void main() {
  test('0-RTT early data is accepted once and rejected on replay', () async {
    final crypto = PqTransportCrypto();
    final store = QuicEarlyDataStore();
    final first = PqQuicConn.pair(crypto: crypto);
    final client = first.$1;
    final server = first.$2;
    expect((await client.handshake()).isSuccess, isTrue);
    expect((await server.handshake()).isSuccess, isTrue);
    final issued = await server.sendNewSessionTicket(store);
    expect(issued.isSuccess, isTrue, reason: '${issued.errorOrNull}');
    final ticket = client.receivedTicket;
    expect(ticket, isNotNull);
    expect(ticket!.identity, issued.valueOrNull!.identity);

    final early = Uint8List.fromList([1, 2, 3, 4]);
    final second = PqQuicConn.pair(
      crypto: crypto,
      ticket: ticket,
      earlyData: store,
    );
    expect(second.$1.writeEarly(early).isSuccess, isTrue);
    expect((await second.$1.handshake()).isSuccess, isTrue);
    expect((await second.$2.handshake()).isSuccess, isTrue);
    expect(second.$1.earlyDataAccepted, isTrue);
    expect(second.$2.earlyDataAccepted, isTrue);
    expect(second.$2.earlyData, hasLength(1));
    expect(second.$2.earlyData.single.data, early);
    expect(second.$1.connectionState, QuicConnectionState.ready);
    expect(second.$2.connectionState, QuicConnectionState.ready);
    expect(
      second.$2.streams.streams[0]!.machine.currentState,
      QuicStreamState.open,
    );

    final replay = PqQuicConn.pair(
      crypto: crypto,
      ticket: ticket,
      earlyData: store,
    );
    expect(replay.$1.writeEarly(early).isSuccess, isTrue);
    expect((await replay.$1.handshake()).isSuccess, isTrue);
    expect((await replay.$2.handshake()).isSuccess, isTrue);
    expect(replay.$1.earlyDataAccepted, isFalse);
    expect(replay.$2.earlyDataAccepted, isFalse);
    expect(replay.$2.earlyData, isEmpty);
  });
}
