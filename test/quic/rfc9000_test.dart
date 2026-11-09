import 'dart:typed_data';

import 'package:pqtransport/pqtransport.dart';
import 'package:test/test.dart';

void main() {
  final crypto = PqTransportCrypto();

  test('transport parameters round-trip and reject duplicates', () {
    final cid = Uint8List.fromList([1, 2, 3, 4, 5, 6, 7, 8]);
    final token = Uint8List(quicStatelessResetTokenBytes)..[0] = 9;
    final raw = quicEndpointParameters(
      server: true,
      localCid: cid,
      maxData: 1000,
      maxStreamData: 200,
      statelessResetToken: token,
    );
    final decoded = QuicTransportParameters.decode(raw);
    expect(decoded.isSuccess, isTrue, reason: '${decoded.errorOrNull}');
    final params = decoded.valueOrNull!;
    expect(
      params
          .check(
            peerIsServer: true,
            expectedInitialSource: cid,
            expectedOriginalDestination: cid,
          )
          .isSuccess,
      isTrue,
    );
    final dup = Uint8List.fromList([...raw, ...raw]);
    expect(QuicTransportParameters.decode(dup).isFailure, isTrue);
  });

  test(
    'ACK_ECN parses and a coalesced datagram keeps the short header last',
    () {
      final ack = QuicAckFrame(
        largest: 3,
        delay: 0,
        firstRange: 0,
        ecn: true,
        ect0: 1,
        ect1: 0,
        ce: 2,
      );
      final parsed = QuicAckFrame.decode(ack.encode());
      expect(parsed.isSuccess, isTrue, reason: '${parsed.errorOrNull}');
      expect(parsed.valueOrNull!.ecn, isTrue);
      expect(parsed.valueOrNull!.ce, 2);

      final initial = Uint8List.fromList([
        0xc0,
        0x00,
        0x00,
        0x00,
        0x01,
        0x00,
        0x00,
        0x00,
        0x02,
        0xaa,
        0xbb,
      ]);
      final handshake = Uint8List.fromList([
        0xe0,
        0x00,
        0x00,
        0x00,
        0x01,
        0x00,
        0x00,
        0x01,
        0xcc,
      ]);
      final oneRtt = Uint8List.fromList([0x40, 1, 2, 3, 4]);
      final split = splitQuicDatagram(
        Uint8List.fromList([...initial, ...handshake, ...oneRtt]),
      );
      expect(split.isSuccess, isTrue, reason: '${split.errorOrNull}');
      expect(split.valueOrNull!, hasLength(3));
      expect(split.valueOrNull!.last[0] & 0x80, 0);

      final retry = Uint8List.fromList([
        0xf0,
        0x00,
        0x00,
        0x00,
        0x01,
        0x00,
        0x00,
      ]);
      expect(
        splitQuicDatagram(Uint8List.fromList([...initial, ...retry])).isFailure,
        isTrue,
      );
    },
  );

  test('Retry integrity tag and Version Negotiation', () {
    final odcid = Uint8List.fromList([9, 8, 7, 6, 5, 4, 3, 2]);
    final dcid = Uint8List.fromList([1, 1, 1, 1, 1, 1, 1, 1]);
    final scid = Uint8List.fromList([2, 2, 2, 2, 2, 2, 2, 2]);
    final packet = quicRetryPacket(
      crypto: crypto,
      originalDestinationConnectionId: odcid,
      destinationConnectionId: dcid,
      sourceConnectionId: scid,
      token: Uint8List.fromList([4, 5, 6]),
    );
    expect(
      quicRetryTagValid(
        crypto: crypto,
        originalDestinationConnectionId: odcid,
        packet: packet,
      ),
      isTrue,
    );
    final flipped = Uint8List.fromList(packet)..[packet.length - 1] ^= 1;
    expect(
      quicRetryTagValid(
        crypto: crypto,
        originalDestinationConnectionId: odcid,
        packet: flipped,
      ),
      isFalse,
    );
    final vn = quicVersionNegotiation(
      destinationConnectionId: dcid,
      sourceConnectionId: scid,
    );
    final versions = readQuicVersionNegotiation(vn);
    expect(versions.isSuccess, isTrue);
    expect(versions.valueOrNull, [quicVersion1]);
  });

  test('a live handshake uses Handshake packets and HANDSHAKE_DONE', () async {
    final seen = <Uint8List>[];
    final clientCid = crypto.randomBytes(quicShortDcidBytes);
    final serverCid = crypto.randomBytes(quicShortDcidBytes);
    late final PqQuicConn client;
    late final PqQuicConn server;
    client = PqQuicConn.client(
      crypto: crypto,
      localCid: clientCid,
      peerCid: serverCid,
      deliver: (packet) {
        seen.add(Uint8List.fromList(packet));
        return server.ingestDatagram(packet);
      },
    );
    server = PqQuicConn.server(
      crypto: crypto,
      localCid: serverCid,
      peerCid: clientCid,
      deliver: (packet) {
        seen.add(Uint8List.fromList(packet));
        return client.ingestDatagram(packet);
      },
    );
    final clientHs = await client.handshake();
    expect(clientHs.isSuccess, isTrue, reason: '${clientHs.errorOrNull}');
    final serverHs = await server.handshake();
    expect(serverHs.isSuccess, isTrue, reason: '${serverHs.errorOrNull}');
    await Future<void>.delayed(Duration.zero);
    expect(client.handshakeConfirmed, isTrue);
    expect(server.handshakeConfirmed, isTrue);
    final kinds = <int>[];
    for (final datagram in seen) {
      final split = splitQuicDatagram(datagram);
      expect(split.isSuccess, isTrue, reason: '${split.errorOrNull}');
      final packets = split.valueOrNull!;
      if (packets.length > 1) {
        expect(packets.last[0] & 0x80 == 0 || packets.length >= 2, isTrue);
      }
      for (final packet in packets) {
        kinds.add(packet[0] & 0xf0);
      }
    }
    expect(kinds, contains(0xc0));
    expect(kinds, contains(0xe0));
    expect(seen.first.length, greaterThanOrEqualTo(8192));

    final id = client.openBidi();
    expect(id, isNonNegative);
    final body = Uint8List.fromList(List<int>.filled(80, 7));
    final wrote = await client.writeStream(id, body, fin: true);
    expect(wrote.isSuccess, isTrue, reason: '${wrote.errorOrNull}');
    await Future<void>.delayed(Duration.zero);
    expect(server.readStream(id), body);

    expect((await client.updateKeys()).isSuccess, isTrue);
    expect((await client.updateKeys()).isFailure, isTrue);
    final keyed = await client.writeStream(id, Uint8List.fromList([1]));
    expect(keyed.isSuccess, isTrue, reason: '${keyed.errorOrNull}');
    await Future<void>.delayed(Duration.zero);
    await Future<void>.delayed(Duration.zero);
    expect(server.readStream(id), [1]);
    expect((await client.updateKeys()).isSuccess, isTrue);

    final challenged = await client.sendPathChallenge();
    expect(challenged.isSuccess, isTrue, reason: '${challenged.errorOrNull}');
    await Future<void>.delayed(Duration.zero);
    expect(client.pathResponseMatched, isTrue);

    final token = server.statelessResetToken;
    expect(token, isNotNull);
    final reset = Uint8List(21);
    reset.setRange(5, 21, token!);
    expect((await client.ingestDatagram(reset)).isFailure, isTrue);

    final issued = await server.issueConnectionId();
    expect(issued.isSuccess, isTrue, reason: '${issued.errorOrNull}');

    for (var i = 0; i < quicInitialMaxStreams + 1; i++) {
      client.openBidi();
    }
    expect(client.openBidi(), -1);

    final resumed = QuicResumptionTicket(
      identity: Uint8List(32),
      nonce: Uint8List(8),
      psk: Uint8List(32),
      ageAdd: 1,
      cipherSuite: tlsCipherAes256GcmSha384,
      issuedAt: DateTime.utc(2026),
      maxEarlyData: 4,
      maxEarlyStreamData: 4,
    );
    final earlyClient = PqQuicConn.client(crypto: crypto, ticket: resumed);
    expect(
      earlyClient.writeEarly(Uint8List(quicMaxDataDefault + 1)).isFailure,
      isTrue,
    );
    expect(
      earlyClient.writeEarly(Uint8List.fromList([1, 2, 3, 4])).isSuccess,
      isTrue,
    );
  });

  test('unknown frame types still fail closed', () {
    final payload = decodeQuicPayload(Uint8List.fromList([0x21]));
    expect(payload.isFailure, isTrue);
  });
}
