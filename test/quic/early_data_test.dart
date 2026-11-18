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
    expect(
      second.$1.writeEarly(Uint8List.fromList([7, 8]), streamId: 4).isSuccess,
      isTrue,
    );
    expect((await second.$1.handshake()).isSuccess, isTrue);
    expect((await second.$2.handshake()).isSuccess, isTrue);
    expect(second.$1.earlyDataAccepted, isTrue);
    expect(second.$2.earlyDataAccepted, isTrue);
    expect(second.$2.earlyData, hasLength(2));
    expect(second.$2.earlyData[0].data, early);
    expect(second.$2.earlyData[1].data, [7, 8]);
    expect(
      (await second.$1.writeStream(0, Uint8List.fromList([9]))).isSuccess,
      isTrue,
    );
    await _pump();
    expect(second.$2.readStream(0), [1, 2, 3, 4, 9]);
    expect(second.$2.readStream(4), [7, 8]);
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
    await _pump();
    expect(replay.$2.readStream(0), early);
  });

  test('a ticket remembers flow control and drops connection ids', () {
    final crypto = const PqTransportCrypto();
    final local = crypto.randomBytes(8);
    final raw = quicEndpointParameters(
      server: true,
      localCid: local,
      maxData: 1000,
      maxStreamData: 200,
      statelessResetToken: crypto.randomBytes(quicStatelessResetTokenBytes),
    );
    final remembered = quicTicketTransportParameters(raw);
    expect(remembered.isSuccess, isTrue, reason: '${remembered.errorOrNull}');
    final ticket = QuicResumptionTicket(
      identity: Uint8List(32),
      nonce: Uint8List(8),
      psk: Uint8List(48),
      ageAdd: 1,
      cipherSuite: 0x1302,
      issuedAt: DateTime.utc(2026),
    );
    final decoded = decodeNewSessionTicket(
      encodeNewSessionTicket(
        ticket,
        transportParameters: remembered.valueOrNull,
      ),
    );
    expect(decoded.isSuccess, isTrue, reason: '${decoded.errorOrNull}');
    final params = QuicTransportParameters.decode(
      decoded.valueOrNull!.transportParameters!,
    );
    expect(params.isSuccess, isTrue, reason: '${params.errorOrNull}');
    final value = params.valueOrNull!;
    expect(value.initialMaxData, 1000);
    expect(value.initialMaxStreamDataBidiLocal, 200);
    expect(value.originalDestinationConnectionId, isNull);
    expect(value.statelessResetToken, isNull);
    expect(value.initialSourceConnectionId, isNull);
    expect(value.retrySourceConnectionId, isNull);
  });

  test('HTTP/3 0-RTT request is accepted once and empty on replay', () async {
    final crypto = PqTransportCrypto();
    final store = QuicEarlyDataStore();
    final first = PqQuicConn.pair(
      crypto: crypto,
      alpnProtocols: const [httpAlpnH3],
    );
    expect((await first.$1.handshake()).isSuccess, isTrue);
    expect((await first.$2.handshake()).isSuccess, isTrue);
    final issued = await first.$2.sendNewSessionTicket(store);
    expect(issued.isSuccess, isTrue, reason: '${issued.errorOrNull}');
    final ticket = first.$1.receivedTicket!;

    final req = PqHttpRequest(
      method: 'GET',
      uri: Uri.parse('https://localhost/pq'),
      body: 'pq'.codeUnits,
      trailers: const {'x-pq': '1'},
    );
    final second = PqQuicConn.pair(
      crypto: crypto,
      alpnProtocols: const [httpAlpnH3],
      ticket: ticket,
      earlyData: store,
    );
    final h3c = PqHttp3Session.client(second.$1);
    final queued = h3c.writeEarlyRequest(req);
    expect(queued.isSuccess, isTrue, reason: '${queued.errorOrNull}');
    expect(queued.valueOrNull, 0);
    expect((await second.$1.handshake()).isSuccess, isTrue);
    expect((await second.$2.handshake()).isSuccess, isTrue);
    expect(second.$2.earlyDataAccepted, isTrue);
    final early = _earlyBytes(second.$2, 0);
    final parsed = decodeHttp3RequestBytes(early);
    expect(parsed.isSuccess, isTrue, reason: '${parsed.errorOrNull}');
    expect(parsed.valueOrNull!.method, 'GET');
    expect(parsed.valueOrNull!.uri.path, '/pq');
    expect(parsed.valueOrNull!.body, 'pq'.codeUnits);
    expect(parsed.valueOrNull!.trailers['x-pq'], '1');

    final h3s = PqHttp3Session.server(second.$2);
    final accepted = h3s.accept();
    final started = await h3c.start();
    expect(started.isSuccess, isTrue, reason: '${started.errorOrNull}');
    final got = await accepted;
    expect(got.isSuccess, isTrue, reason: '${got.errorOrNull}');
    expect(got.valueOrNull!.$2.method, 'GET');
    expect(got.valueOrNull!.$2.uri.path, '/pq');
    expect(got.valueOrNull!.$2.body, 'pq'.codeUnits);

    final replay = PqQuicConn.pair(
      crypto: crypto,
      alpnProtocols: const [httpAlpnH3],
      ticket: ticket,
      earlyData: store,
    );
    final again = PqHttp3Session.client(replay.$1).writeEarlyRequest(req);
    expect(again.isSuccess, isTrue, reason: '${again.errorOrNull}');
    expect((await replay.$1.handshake()).isSuccess, isTrue);
    expect((await replay.$2.handshake()).isSuccess, isTrue);
    expect(replay.$1.earlyDataAccepted, isFalse);
    expect(replay.$2.earlyDataAccepted, isFalse);
    expect(replay.$2.earlyData, isEmpty);
    await _pump();
    final replayServer = PqHttp3Session.server(replay.$2);
    final replayAccept = replayServer.accept();
    final replayStart = await PqHttp3Session.client(replay.$1).start();
    expect(replayStart.isSuccess, isTrue, reason: '${replayStart.errorOrNull}');
    final replayed = await replayAccept;
    expect(replayed.isSuccess, isTrue, reason: '${replayed.errorOrNull}');
    expect(replayed.valueOrNull!.$2.body, 'pq'.codeUnits);
  });

  test('0-RTT DATAGRAM is accepted once and is not resent', () async {
    final crypto = PqTransportCrypto();
    final store = QuicEarlyDataStore();
    final first = PqQuicConn.pair(crypto: crypto);
    expect((await first.$1.handshake()).isSuccess, isTrue);
    expect((await first.$2.handshake()).isSuccess, isTrue);
    final issued = await first.$2.sendNewSessionTicket(store);
    expect(issued.isSuccess, isTrue, reason: '${issued.errorOrNull}');
    final ticket = first.$1.receivedTicket!;
    expect(ticket.maxEarlyDatagram, quicLocalMaxDatagramFrameSize);

    final payload = Uint8List.fromList([9, 8, 7]);
    final second = PqQuicConn.pair(
      crypto: crypto,
      ticket: ticket,
      earlyData: store,
    );
    expect(second.$1.writeEarlyDatagram(payload).isSuccess, isTrue);
    expect((await second.$1.handshake()).isSuccess, isTrue);
    expect((await second.$2.handshake()).isSuccess, isTrue);
    expect(second.$2.earlyDataAccepted, isTrue);
    expect(second.$2.takeDatagrams(), [payload]);

    final replay = PqQuicConn.pair(
      crypto: crypto,
      ticket: ticket,
      earlyData: store,
    );
    expect(replay.$1.writeEarlyDatagram(payload).isSuccess, isTrue);
    expect((await replay.$1.handshake()).isSuccess, isTrue);
    expect((await replay.$2.handshake()).isSuccess, isTrue);
    expect(replay.$2.earlyDataAccepted, isFalse);
    await _pump();
    expect(replay.$2.takeDatagrams(), isEmpty);
    expect(replay.$2.earlyData, isEmpty);
  });

  test('unidirectional 0-RTT is accepted once', () async {
    final crypto = PqTransportCrypto();
    final store = QuicEarlyDataStore();
    final first = PqQuicConn.pair(crypto: crypto);
    expect((await first.$1.handshake()).isSuccess, isTrue);
    expect((await first.$2.handshake()).isSuccess, isTrue);
    final issued = await first.$2.sendNewSessionTicket(store);
    expect(issued.isSuccess, isTrue, reason: '${issued.errorOrNull}');
    final ticket = first.$1.receivedTicket!;

    final early = Uint8List.fromList([4, 5, 6]);
    final second = PqQuicConn.pair(
      crypto: crypto,
      ticket: ticket,
      earlyData: store,
    );
    expect(
      second.$1.writeEarly(early, streamId: 2, fin: true).isSuccess,
      isTrue,
    );
    expect(second.$1.openUni(), 6);
    expect((await second.$1.handshake()).isSuccess, isTrue);
    expect((await second.$2.handshake()).isSuccess, isTrue);
    expect(second.$2.earlyDataAccepted, isTrue);
    expect(_earlyBytes(second.$2, 2), early);
    expect(second.$2.readStream(2), early);
    expect(second.$2.streamFin(2), isTrue);

    final replay = PqQuicConn.pair(
      crypto: crypto,
      ticket: ticket,
      earlyData: store,
    );
    expect(
      replay.$1.writeEarly(early, streamId: 2, fin: true).isSuccess,
      isTrue,
    );
    expect((await replay.$1.handshake()).isSuccess, isTrue);
    expect((await replay.$2.handshake()).isSuccess, isTrue);
    expect(replay.$2.earlyData, isEmpty);
    await _pump();
    expect(replay.$2.readStream(2), early);
    expect(replay.$2.streamFin(2), isTrue);
  });

  test('0-RTT refuses a server stream id and a stream past the ticket', () {
    final ticket = QuicResumptionTicket(
      identity: Uint8List(32),
      nonce: Uint8List(8),
      psk: Uint8List(48),
      ageAdd: 1,
      cipherSuite: 0x1302,
      issuedAt: DateTime.utc(2026),
      maxEarlyStreamsUni: 1,
      maxEarlyDatagram: 0,
    );
    final client = PqQuicConn.client(ticket: ticket);
    expect(
      client.writeEarly(Uint8List.fromList([1]), streamId: 1).isFailure,
      isTrue,
    );
    expect(
      client.writeEarly(Uint8List.fromList([1]), streamId: 2).isSuccess,
      isTrue,
    );
    expect(
      client.writeEarly(Uint8List.fromList([1]), streamId: 6).isFailure,
      isTrue,
    );
    expect(
      client
          .writeEarly(Uint8List.fromList([1]), streamId: 2, fin: true)
          .isSuccess,
      isTrue,
    );
    expect(
      client.writeEarly(Uint8List.fromList([1]), streamId: 2).isFailure,
      isTrue,
    );
    expect(
      client.writeEarlyDatagram(Uint8List.fromList([1])).isFailure,
      isTrue,
    );
    expect(client.openUni(), 6);
  });
}

Future<void> _pump() async {
  for (var i = 0; i < 16; i++) {
    await Future<void>.delayed(Duration.zero);
  }
}

Uint8List _earlyBytes(PqQuicConn conn, int streamId) {
  final out = BytesBuilder(copy: false);
  for (final part in conn.earlyData) {
    if (part.streamId == streamId) out.add(part.data);
  }
  return out.takeBytes();
}
