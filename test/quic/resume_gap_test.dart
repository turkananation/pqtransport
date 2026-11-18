import 'dart:typed_data';

import 'package:pqtransport/pqtransport.dart';
import 'package:swissarmyknife/swissarmyknife.dart';
import 'package:test/test.dart';

void main() {
  test('path 1 PTO probes once without an acknowledgement', () async {
    final crypto = PqTransportCrypto();
    final clock = QuicManualClock();
    final held = <Uint8List>[];
    final clientCid = crypto.randomBytes(quicShortDcidBytes);
    final serverCid = crypto.randomBytes(quicShortDcidBytes);
    late final PqQuicConn client;
    late final PqQuicConn server;
    client = PqQuicConn.client(
      crypto: crypto,
      localCid: clientCid,
      peerCid: serverCid,
      clock: clock,
      initialMaxPathId: 2,
      deliver: (packet) => server.ingestDatagram(packet),
      deliverOnPath: (packet, pathId) {
        if (pathId == 0) return server.ingestDatagram(packet);
        held.add(packet);
        return Future<Result<void, PqTransportError>>.value(
          const Result.success(null),
        );
      },
    );
    server = PqQuicConn.server(
      crypto: crypto,
      localCid: serverCid,
      peerCid: clientCid,
      clock: clock,
      initialMaxPathId: 2,
      deliver: (packet) => client.ingestDatagram(packet),
    );
    expect(
      (await client.handshake()).isSuccess,
      isTrue,
      reason: '${client.isComplete}',
    );
    expect((await server.handshake()).isSuccess, isTrue);
    await _pump();
    expect(client.multipathNegotiated, isTrue);
    expect(client.multipath!.peerCidByPath[1], isNotNull);
    final sent = await client.sendOnPath(
      1,
      Uint8List.fromList([quicFramePing]),
    );
    expect(sent.isSuccess, isTrue, reason: '${sent.errorOrNull}');
    expect(client.pathPtoCount(1), 0);
    expect(held, isNotEmpty);
    clock.advance(const Duration(seconds: 2));
    final driven = await client.driveLossRecovery();
    expect(driven.isSuccess, isTrue, reason: '${driven.errorOrNull}');
    expect(client.pathPtoCount(1), 1);
    expect(client.isClosed, isFalse);
    expect(held.length, greaterThan(1));
  });

  test('commitMigration uses a connection id that was not current', () async {
    final pair = PqQuicConn.pair(crypto: PqTransportCrypto());
    final client = pair.$1;
    final server = pair.$2;
    expect((await client.handshake()).isSuccess, isTrue);
    expect((await server.handshake()).isSuccess, isTrue);
    await _pump();
    expect((await client.commitMigration()).isFailure, isTrue);
    final before = Uint8List.fromList(client.destinationConnectionId);
    final challenged = await client.sendPathChallenge();
    expect(challenged.isSuccess, isTrue, reason: '${challenged.errorOrNull}');
    await _pump();
    expect(client.pathResponseMatched, isTrue);
    final issued = await server.issueConnectionId();
    expect(issued.isSuccess, isTrue, reason: '${issued.errorOrNull}');
    await _pump();
    final moved = await client.commitMigration();
    expect(moved.isSuccess, isTrue, reason: '${moved.errorOrNull}');
    expect(client.migrated, isTrue);
    expect(client.destinationConnectionId, isNot(equals(before)));
    expect(client.destinationConnectionId, issued.valueOrNull);
  });

  test('a restarted store resumes and refuses 0-RTT', () async {
    final crypto = PqTransportCrypto();
    final key = crypto.randomBytes(32);
    expect(
      () => QuicEarlyDataStore(ticketKey: Uint8List(16)),
      throwsArgumentError,
    );
    final store = QuicEarlyDataStore(ticketKey: key);
    final first = PqQuicConn.pair(crypto: crypto);
    expect((await first.$1.handshake()).isSuccess, isTrue);
    expect((await first.$2.handshake()).isSuccess, isTrue);
    final issued = await first.$2.sendNewSessionTicket(store);
    expect(issued.isSuccess, isTrue, reason: '${issued.errorOrNull}');
    final ticket = first.$1.receivedTicket!;
    expect(store.find(ticket.identity)!.allowEarlyData, isTrue);

    final early = Uint8List.fromList([4, 5, 6]);
    final live = PqQuicConn.pair(
      crypto: crypto,
      ticket: ticket,
      earlyData: store,
    );
    expect(live.$1.writeEarly(early).isSuccess, isTrue);
    expect((await live.$1.handshake()).isSuccess, isTrue);
    expect((await live.$2.handshake()).isSuccess, isTrue);
    expect(live.$2.earlyDataAccepted, isTrue);
    expect(live.$2.selectedPskIndex, 0);

    final restarted = QuicEarlyDataStore(ticketKey: key);
    final opened = restarted.find(ticket.identity);
    expect(opened, isNotNull);
    expect(opened!.allowEarlyData, isFalse);
    expect(opened.psk, ticket.psk);
    expect(
      QuicEarlyDataStore(
        ticketKey: crypto.randomBytes(32),
      ).find(ticket.identity),
      isNull,
    );

    final again = PqQuicConn.pair(
      crypto: crypto,
      ticket: ticket,
      earlyData: restarted,
    );
    expect(again.$1.writeEarly(early).isSuccess, isTrue);
    expect((await again.$1.handshake()).isSuccess, isTrue);
    expect((await again.$2.handshake()).isSuccess, isTrue);
    expect(again.$1.earlyDataAccepted, isFalse);
    expect(again.$2.earlyDataAccepted, isFalse);
    expect(again.$2.earlyData, isEmpty);
    expect(again.$1.selectedPskIndex, 0);
    expect(again.$2.selectedPskIndex, 0);
    await _pump();
    expect(again.$2.readStream(0), early);
  });

  test('the server selects the PSK identity it knows', () async {
    final crypto = PqTransportCrypto();
    final store = QuicEarlyDataStore();
    final first = PqQuicConn.pair(crypto: crypto);
    expect((await first.$1.handshake()).isSuccess, isTrue);
    expect((await first.$2.handshake()).isSuccess, isTrue);
    final knownIssued = await first.$2.sendNewSessionTicket(store);
    final otherIssued = await first.$2.sendNewSessionTicket(store);
    expect(knownIssued.isSuccess, isTrue);
    expect(otherIssued.isSuccess, isTrue);
    final known = knownIssued.valueOrNull!;
    final other = otherIssued.valueOrNull!;
    final unknown = QuicResumptionTicket(
      identity: crypto.randomBytes(32),
      nonce: crypto.randomBytes(8),
      psk: crypto.randomBytes(known.psk.length),
      ageAdd: 3,
      cipherSuite: known.cipherSuite,
      issuedAt: DateTime.utc(2026),
    );

    final early = Uint8List.fromList([9, 9]);
    final indexZero = PqQuicConn.pair(
      crypto: crypto,
      ticket: known,
      moreTickets: [unknown],
      earlyData: store,
    );
    expect(indexZero.$1.writeEarly(early).isSuccess, isTrue);
    expect((await indexZero.$1.handshake()).isSuccess, isTrue);
    expect((await indexZero.$2.handshake()).isSuccess, isTrue);
    expect(indexZero.$1.selectedPskIndex, 0);
    expect(indexZero.$2.selectedPskIndex, 0);
    expect(indexZero.$2.earlyDataAccepted, isTrue);
    expect(indexZero.$2.earlyData.single.data, early);

    final later = PqQuicConn.pair(
      crypto: crypto,
      ticket: unknown,
      moreTickets: [other],
      earlyData: store,
    );
    expect((await later.$1.handshake()).isSuccess, isTrue);
    expect((await later.$2.handshake()).isSuccess, isTrue);
    expect(later.$1.selectedPskIndex, 1);
    expect(later.$2.selectedPskIndex, 1);
    expect(later.$1.earlyDataAccepted, isFalse);
    expect(later.$2.earlyDataAccepted, isFalse);
    final wrote = await later.$1.writeStream(0, Uint8List.fromList([1]));
    expect(wrote.isSuccess, isTrue, reason: '${wrote.errorOrNull}');
    await _pump();
    expect(later.$2.readStream(0), [1]);
  });

  test('a bad binder on a known identity is decrypt_error', () async {
    final crypto = PqTransportCrypto();
    final store = QuicEarlyDataStore();
    final first = PqQuicConn.pair(crypto: crypto);
    expect((await first.$1.handshake()).isSuccess, isTrue);
    expect((await first.$2.handshake()).isSuccess, isTrue);
    final knownIssued = await first.$2.sendNewSessionTicket(store);
    final otherIssued = await first.$2.sendNewSessionTicket(store);
    final known = knownIssued.valueOrNull!;
    final other = otherIssued.valueOrNull!;
    final client = PqTlsClient(
      crypto: crypto,
      quic: true,
      ticket: known,
      moreTickets: [other],
    );
    final started = await client.startHandshake();
    expect(started.isSuccess, isTrue, reason: '${started.errorOrNull}');
    final hello = Uint8List.fromList(started.valueOrNull!);
    final binders = 2 * (1 + known.psk.length);
    hello[hello.length - binders + 1] ^= 0xff;
    final server = PqTlsServer(crypto: crypto, quic: true, earlyData: store);
    final got = await server.ingest(hello);
    expect(got.isFailure, isTrue);
    expect(got.errorOrNull!.code, PqTransportErrorCode.decryptError);
    expect(store.find(known.identity), isNull);
    expect(store.find(other.identity), isNotNull);
    expect(server.earlyDataAccepted, isFalse);
    expect(server.selectedPskIndex, 0);
  });
}

Future<void> _pump() async {
  for (var i = 0; i < 16; i++) {
    await Future<void>.delayed(Duration.zero);
  }
}
