import 'dart:typed_data';

import 'package:pqtransport/pqtransport.dart';
import 'package:swissarmyknife/swissarmyknife.dart';
import 'package:test/test.dart';

void main() {
  final app = QuicPacketNumberSpace.application;
  final initial = QuicPacketNumberSpace.initial;

  QuicRetransmitStream streamFrame(int offset, List<int> bytes) {
    return QuicRetransmitStream(
      streamId: 0,
      offset: offset,
      data: Uint8List.fromList(bytes),
    );
  }

  QuicLossRecovery recovery(
    QuicManualClock clock, {
    bool server = true,
    int maxAckDelay = quicMaxAckDelayMicros,
  }) {
    final loss = QuicLossRecovery(
      clock: clock,
      isServer: server,
      maxAckDelay: maxAckDelay,
    );
    loss.markHandshakeConfirmed();
    return loss;
  }

  Result<QuicRecoveryEvent, PqTransportError> ackOnly(
    QuicLossRecovery loss,
    QuicPacketNumberSpace space,
    int largest, {
    int delay = 0,
    int firstRange = 0,
  }) {
    return loss.onAck(
      space,
      QuicAckFrame(largest: largest, delay: delay, firstRange: firstRange),
    );
  }

  void send(
    QuicLossRecovery loss,
    QuicPacketNumberSpace space,
    int packetNumber,
    List<QuicRetransmittable> frames, {
    int sentBytes = quicMinClientInitialUdpBytes,
  }) {
    final sent = loss.onPacketSent(
      space: space,
      packetNumber: packetNumber,
      sentBytes: sentBytes,
      ackEliciting: true,
      inFlight: true,
      frames: frames,
    );
    expect(sent.isSuccess, isTrue, reason: '${sent.errorOrNull}');
  }

  group('QuicNewReno RFC 9002 §7', () {
    test('initial window is 10 datagrams and the 11th send is throttled', () {
      final now = DateTime.utc(2026);
      final cc = QuicNewReno(
        maxDatagramSize: quicMinClientInitialUdpBytes,
        now: () => now,
      );
      expect(
        cc.congestionWindow,
        quicInitialCongestionWindow(quicMinClientInitialUdpBytes),
      );
      expect(cc.inSlowStart, isTrue);
      const size = quicMinClientInitialUdpBytes;
      for (var i = 0; i < quicInitialWindowDatagrams; i++) {
        expect(cc.canSend(size), isTrue, reason: 'packet $i');
        expect(cc.onPacketSent(size).isSuccess, isTrue);
      }
      expect(cc.canSend(size), isFalse);
      expect(cc.canSend(size, probe: true), isTrue);
      final blocked = cc.onPacketSent(size);
      expect(blocked.isFailure, isTrue);
      expect(blocked.errorOrNull!.code, PqTransportErrorCode.throttled);
      expect(
        () => QuicNewReno(
          maxDatagramSize: quicMinClientInitialUdpBytes - 1,
          now: () => now,
        ),
        throwsArgumentError,
      );
    });

    test('slow start grows by bytes acked; one loss halves once', () {
      var now = DateTime.utc(2026);
      final cc = QuicNewReno(
        maxDatagramSize: quicMinClientInitialUdpBytes,
        now: () => now,
      );
      const size = quicMinClientInitialUdpBytes;
      final sentAt = now;
      expect(cc.onPacketSent(size).isSuccess, isTrue);
      now = now.add(const Duration(milliseconds: 5));
      cc.onPacketAcked(
        sentBytes: size,
        timeSent: sentAt,
        inFlight: true,
        appLimited: false,
      );
      expect(cc.congestionWindow, quicInitialCongestionWindow(size) + size);

      final lostAt = now;
      expect(cc.onPacketSent(size).isSuccess, isTrue);
      now = now.add(const Duration(milliseconds: 5));
      final before = cc.congestionWindow;
      final entered = cc.onPacketsLost(
        lost: [(sentBytes: size, timeSent: lostAt, inFlight: true)],
      );
      expect(entered, isTrue);
      expect(cc.ssthresh, before ~/ 2);
      expect(cc.congestionWindow, before ~/ 2);
      expect(cc.takeRecoverySend(), isTrue);
      expect(cc.takeRecoverySend(), isFalse);

      final again = cc.onPacketsLost(
        lost: [(sentBytes: size, timeSent: lostAt, inFlight: true)],
      );
      expect(again, isFalse);
      expect(cc.congestionWindow, before ~/ 2);
    });

    test('congestion avoidance adds one datagram per acknowledged window', () {
      var now = DateTime.utc(2026);
      final cc = QuicNewReno(
        maxDatagramSize: quicMinClientInitialUdpBytes,
        now: () => now,
      );
      const size = quicMinClientInitialUdpBytes;
      final lostAt = now;
      expect(cc.onPacketSent(size).isSuccess, isTrue);
      now = now.add(const Duration(milliseconds: 1));
      cc.onPacketsLost(
        lost: [(sentBytes: size, timeSent: lostAt, inFlight: true)],
      );
      final halved = cc.congestionWindow;
      expect(cc.inSlowStart, isFalse);
      now = now.add(const Duration(milliseconds: 1));
      final sentAt = now;
      var credit = 0;
      while (credit < halved) {
        cc.onPacketAcked(
          sentBytes: size,
          timeSent: sentAt,
          inFlight: true,
          appLimited: false,
        );
        credit += size;
      }
      expect(cc.congestionWindow, halved + size);
    });

    test('app-limited acknowledgements do not grow the window', () {
      final now = DateTime.utc(2026);
      final cc = QuicNewReno(
        maxDatagramSize: quicMinClientInitialUdpBytes,
        now: () => now,
      );
      const size = quicMinClientInitialUdpBytes;
      final before = cc.congestionWindow;
      cc.onPacketAcked(
        sentBytes: size,
        timeSent: now,
        inFlight: true,
        appLimited: true,
      );
      expect(cc.congestionWindow, before);
      expect(cc.bytesInFlight, 0);
    });

    test('persistent congestion collapses to the minimum window', () {
      final now = DateTime.utc(2026);
      final cc = QuicNewReno(
        maxDatagramSize: quicMinClientInitialUdpBytes,
        now: () => now,
      );
      cc.onPersistentCongestion();
      expect(
        cc.congestionWindow,
        quicMinimumCongestionWindow(quicMinClientInitialUdpBytes),
      );
      expect(cc.inSlowStart, isTrue);
      expect(cc.recoveryStart, isNull);
    });
  });

  group('RFC 9002 loss detection', () {
    test('packet threshold 3 loses only the packet three behind', () {
      final clock = QuicManualClock();
      final loss = recovery(clock);
      for (var pn = 0; pn < 4; pn++) {
        send(loss, app, pn, [
          streamFrame(pn, [pn]),
        ]);
      }
      final event = ackOnly(loss, app, 3);
      expect(event.isSuccess, isTrue, reason: '${event.errorOrNull}');
      final body = event.valueOrNull!;
      expect(body.lost.map((packet) => packet.packetNumber), [0]);
      expect(body.retransmit, hasLength(1));
      final again = body.retransmit.single as QuicRetransmitStream;
      expect(again.offset, 0);
      expect(again.data, [0]);
      expect(loss.packetNumberUsed(app, 0), isTrue);
      expect(loss.peekPacketNumber(app), 4);
      expect(loss.allocatePacketNumber(app), 4);
      expect(loss.lostPacketNumbers(app), {0});
    });

    test('an acknowledgement never reuses or crosses packet number spaces', () {
      final clock = QuicManualClock();
      final loss = recovery(clock);
      send(loss, initial, 0, [
        QuicRetransmitCrypto(
          space: initial,
          offset: 0,
          data: Uint8List.fromList([1, 2, 3]),
        ),
      ]);
      send(loss, app, 0, [
        streamFrame(0, [9]),
      ]);
      final event = ackOnly(loss, app, 0);
      expect(event.isSuccess, isTrue, reason: '${event.errorOrNull}');
      expect(loss.hasOutstanding(initial), isTrue);
      expect(loss.hasOutstanding(app), isFalse);
      expect(event.valueOrNull!.lost, isEmpty);
      final reused = loss.onPacketSent(
        space: app,
        packetNumber: 0,
        sentBytes: quicMinClientInitialUdpBytes,
        ackEliciting: true,
        inFlight: true,
        frames: [
          streamFrame(1, [8]),
        ],
      );
      expect(reused.isFailure, isTrue);
      expect(reused.errorOrNull!.code, PqTransportErrorCode.internalError);
    });

    test('time threshold declares loss; PTO does not', () {
      final clock = QuicManualClock();
      final loss = recovery(clock);
      send(loss, app, 0, [
        streamFrame(0, [1]),
      ]);
      send(loss, app, 1, [
        streamFrame(1, [2]),
      ]);
      final early = ackOnly(loss, app, 1);
      expect(early.valueOrNull!.lost, isEmpty);
      final deadline = loss.lossDetectionDeadline;
      expect(deadline, isNotNull);
      clock.advance(deadline!.difference(clock.now()));
      final timed = loss.onLossDetectionTimeout();
      expect(timed.isSuccess, isTrue, reason: '${timed.errorOrNull}');
      expect(timed.valueOrNull!.probeSpace, isNull);
      expect(timed.valueOrNull!.lost.map((packet) => packet.packetNumber), [0]);
      final again =
          timed.valueOrNull!.retransmit.single as QuicRetransmitStream;
      expect(again.data, [1]);

      final tailClock = QuicManualClock();
      final tail = recovery(tailClock);
      send(tail, app, 0, [
        streamFrame(0, [7]),
      ]);
      final ptoAt = tail.lossDetectionDeadline;
      expect(ptoAt, isNotNull);
      final wait = ptoAt!.difference(tailClock.now());
      if (wait > Duration.zero) tailClock.advance(wait);
      final probe = tail.onLossDetectionTimeout();
      expect(probe.isSuccess, isTrue, reason: '${probe.errorOrNull}');
      expect(probe.valueOrNull!.lost, isEmpty);
      expect(probe.valueOrNull!.probeSpace, app);
      expect(tail.hasOutstanding(app), isTrue);
    });

    test('a peer that never ACKs exhausts the PTO budget and stops', () {
      final clock = QuicManualClock();
      final loss = recovery(clock);
      send(loss, app, 0, [
        streamFrame(0, [1]),
      ]);
      var probes = 0;
      while (!loss.ptoBudgetExhausted) {
        final deadline = loss.lossDetectionDeadline;
        expect(deadline, isNotNull);
        final wait = deadline!.difference(clock.now());
        if (wait > Duration.zero) clock.advance(wait);
        final event = loss.onLossDetectionTimeout();
        if (event.isFailure) {
          expect(event.errorOrNull!.code, PqTransportErrorCode.closed);
          break;
        }
        expect(event.valueOrNull!.lost, isEmpty);
        expect(event.valueOrNull!.probeSpace, app);
        probes++;
        expect(probes, lessThan(quicMaxPtoCount + 1));
      }
      expect(probes, quicMaxPtoCount);
      expect(loss.ptoBudgetExhausted, isTrue);
      expect(loss.canSend(quicMinClientInitialUdpBytes, probe: true), isFalse);
      final again = loss.onPacketSent(
        space: app,
        packetNumber: 99,
        sentBytes: quicMinClientInitialUdpBytes,
        ackEliciting: true,
        inFlight: true,
        frames: [
          streamFrame(1, [2]),
        ],
      );
      expect(again.isFailure, isTrue);
      expect(again.errorOrNull!.code, PqTransportErrorCode.closed);
      expect(loss.lossDetectionDeadline, isNull);
    });

    test('§5.3 clamps ack delay only after the handshake is confirmed', () {
      final clock = QuicManualClock();
      final loss = QuicLossRecovery(clock: clock, isServer: true);
      send(loss, app, 0, [
        streamFrame(0, [1]),
      ]);
      clock.advance(const Duration(milliseconds: 100));
      expect(ackOnly(loss, app, 0).isSuccess, isTrue);
      expect(loss.latestRttMicros, 100000);
      expect(loss.smoothedRttMicros, 100000);

      send(loss, app, 1, [
        streamFrame(1, [2]),
      ]);
      clock.advance(const Duration(milliseconds: 200));
      loss.markHandshakeConfirmed();
      // Raw ACK Delay 10000 × 2^3 = 80ms, clamped to max_ack_delay 25ms.
      expect(ackOnly(loss, app, 1, delay: 10000).isSuccess, isTrue);
      expect(loss.latestRttMicros, 200000);
      expect(loss.smoothedRttMicros, (7 * 100000 + 175000) ~/ 8);
    });

    test('§7.6.2 persistent congestion uses newest minus oldest lost', () {
      final clock = QuicManualClock();
      final loss = recovery(clock, maxAckDelay: 0);
      send(loss, app, 0, [
        streamFrame(0, [0]),
      ]);
      clock.advance(const Duration(milliseconds: 100));
      expect(ackOnly(loss, app, 0).isSuccess, isTrue);
      clock.advance(const Duration(milliseconds: 1));
      send(loss, app, 1, [
        streamFrame(1, [1]),
      ]);
      clock.advance(const Duration(seconds: 5));
      send(loss, app, 2, [
        streamFrame(2, [2]),
      ]);
      clock.advance(const Duration(milliseconds: 1));
      for (var pn = 3; pn <= 5; pn++) {
        send(loss, app, pn, [
          streamFrame(pn, [pn]),
        ]);
      }
      final event = ackOnly(loss, app, 5);
      expect(event.isSuccess, isTrue, reason: '${event.errorOrNull}');
      expect(event.valueOrNull!.persistentCongestion, isTrue);
      expect(
        loss.congestionWindow,
        quicMinimumCongestionWindow(quicMinClientInitialUdpBytes) +
            quicMinClientInitialUdpBytes,
      );
      expect(loss.inSlowStart, isTrue);
    });

    test('ack of an unsent packet number fails closed', () {
      final loss = recovery(QuicManualClock());
      final event = ackOnly(loss, app, 4);
      expect(event.isFailure, isTrue);
      expect(event.errorOrNull!.code, PqTransportErrorCode.unexpectedMessage);
    });

    test('congestion window stops sends before the PTO budget does', () {
      final loss = recovery(QuicManualClock());
      const size = quicMinClientInitialUdpBytes;
      var sent = 0;
      while (loss.canSend(size)) {
        send(loss, app, sent, [
          streamFrame(sent, [sent & 0xff]),
        ], sentBytes: size);
        sent++;
        expect(sent, lessThan(quicInitialWindowDatagrams + 2));
      }
      expect(sent, quicInitialWindowDatagrams);
      expect(loss.bytesInFlight, lessThanOrEqualTo(loss.congestionWindow));
      expect(loss.canSend(size), isFalse);
    });

    test('§6.1 does not declare an ack-only packet lost', () {
      final loss = recovery(QuicManualClock());
      final ackOnlyPacket = loss.onPacketSent(
        space: app,
        packetNumber: 0,
        sentBytes: quicShortHeaderOverhead,
        ackEliciting: false,
        inFlight: false,
        frames: const [],
      );
      expect(ackOnlyPacket.isSuccess, isTrue);
      for (var pn = 1; pn <= 4; pn++) {
        send(loss, app, pn, [
          streamFrame(pn, [pn]),
        ]);
      }
      final event = ackOnly(loss, app, 4, firstRange: 2);
      expect(event.isSuccess, isTrue, reason: '${event.errorOrNull}');
      expect(event.valueOrNull!.lost.map((packet) => packet.packetNumber), [1]);
      expect(loss.lostPacketNumbers(app).contains(0), isFalse);
      expect(loss.hasInFlight(app), isFalse);
    });

    test('application PTO stays disarmed until the handshake is confirmed', () {
      final clock = QuicManualClock();
      final loss = QuicLossRecovery(clock: clock, isServer: false);
      send(loss, app, 0, [
        streamFrame(0, [1]),
      ]);
      expect(loss.lossDetectionDeadline, isNull);
      loss.markHandshakeConfirmed();
      expect(loss.lossDetectionDeadline, isNotNull);
      expect(loss.ptoCount, 0);
    });

    test(
      '§7.6.2 an in-flight packet inside the window blocks persistent congestion',
      () {
        final clock = QuicManualClock();
        final loss = recovery(clock, maxAckDelay: 0);
        send(loss, app, 0, [
          streamFrame(0, [0]),
        ]);
        clock.advance(const Duration(milliseconds: 100));
        expect(ackOnly(loss, app, 0).isSuccess, isTrue);
        clock.advance(const Duration(milliseconds: 1));
        send(loss, app, 1, [
          streamFrame(1, [1]),
        ]);
        clock.advance(const Duration(seconds: 2));
        send(loss, initial, 0, [
          QuicRetransmitCrypto(
            space: initial,
            offset: 0,
            data: Uint8List.fromList([9]),
          ),
        ]);
        clock.advance(const Duration(seconds: 3));
        send(loss, app, 2, [
          streamFrame(2, [2]),
        ]);
        clock.advance(const Duration(milliseconds: 1));
        for (var pn = 3; pn <= 5; pn++) {
          send(loss, app, pn, [
            streamFrame(pn, [pn]),
          ]);
        }
        final blocked = ackOnly(loss, app, 5);
        expect(blocked.isSuccess, isTrue, reason: '${blocked.errorOrNull}');
        expect(blocked.valueOrNull!.persistentCongestion, isFalse);
        expect(loss.hasInFlight(initial), isTrue);
        expect(loss.lostPacketNumbers(app), {1, 2});
      },
    );

    test(
      'client Initial padding fills the datagram, not the frame payload',
      () {
        const payload = 1;
        final target = quicClientInitialPayloadBytes(
          dcidLength: quicShortDcidBytes,
          scidLength: quicShortDcidBytes,
          payloadLength: payload,
        );
        expect(target, greaterThan(payload));
        expect(target, lessThan(quicMinClientInitialUdpBytes));
        final bodyLen = quicPacketNumberMaxBytes + target + aeadTagBytes;
        final total =
            1 +
            4 +
            1 +
            quicShortDcidBytes +
            1 +
            quicShortDcidBytes +
            1 +
            quicVarintLength(bodyLen) +
            quicPacketNumberMaxBytes +
            target +
            aeadTagBytes;
        expect(total, quicMinClientInitialUdpBytes);
        expect(
          quicClientInitialPayloadBytes(
            dcidLength: quicShortDcidBytes,
            scidLength: quicShortDcidBytes,
            payloadLength: 2000,
          ),
          2000,
        );
      },
    );
  });

  group('STREAM retransmit is delivered once', () {
    test(
      'consistent overlap is merged; a conflict fails; a replay is empty',
      () {
        final stream = QuicStreamReassembler(4);
        expect(
          stream
              .add(
                QuicStreamFrame(
                  id: 4,
                  offset: 0,
                  data: Uint8List.fromList([0, 1, 2, 3, 4]),
                ),
              )
              .isSuccess,
          isTrue,
        );
        expect(
          stream
              .add(
                QuicStreamFrame(
                  id: 4,
                  offset: 2,
                  data: Uint8List.fromList([2, 3, 4, 5, 6]),
                ),
              )
              .isSuccess,
          isTrue,
        );
        expect(stream.takeAvailable(), [0, 1, 2, 3, 4, 5, 6]);
        expect(
          stream
              .add(
                QuicStreamFrame(
                  id: 4,
                  offset: 0,
                  data: Uint8List.fromList([0, 1, 2, 3, 4, 5, 6]),
                ),
              )
              .isSuccess,
          isTrue,
        );
        expect(stream.takeAvailable(), isEmpty);

        final conflict = QuicStreamReassembler(0);
        conflict.add(
          QuicStreamFrame(
            id: 0,
            offset: 0,
            data: Uint8List.fromList([0, 1, 2]),
          ),
        );
        expect(
          conflict
              .add(
                QuicStreamFrame(
                  id: 0,
                  offset: 0,
                  data: Uint8List.fromList([0, 9, 2]),
                ),
              )
              .isFailure,
          isTrue,
        );
      },
    );

    test(
      'dropped 1-RTT STREAM arrives once, in order, under a new packet number',
      () async {
        final clock = QuicManualClock();
        final linked = await _linked(clock: clock, dropNextClientApp: true);
        final client = linked.client;
        final server = linked.server;
        final id = client.openBidi();
        expect(
          (await client.writeStream(
            id,
            Uint8List.fromList([1, 2, 3, 4]),
          )).isSuccess,
          isTrue,
        );
        await _pump();
        expect(
          (await client.writeStream(
            id,
            Uint8List.fromList([5, 6, 7, 8]),
          )).isSuccess,
          isTrue,
        );
        await _pump();
        expect(server.streamHasData(id), isFalse);
        await _recover(client, clock);
        await _pump();
        expect(server.readStream(id), [1, 2, 3, 4, 5, 6, 7, 8]);
        expect(server.readStream(id), isEmpty);
        final lost = client.lossRecovery.lostPacketNumbers(app);
        expect(lost, isNotEmpty);
        final lostPn = lost.reduce((a, b) => a < b ? a : b);
        expect(client.lossRecovery.packetNumberUsed(app, lostPn), isTrue);
        expect(client.lossRecovery.largestSent(app), greaterThan(lostPn));
        expect(linked.clientApp.length, greaterThan(1));
        expect(linked.clientApp.first, isNot(equals(linked.clientApp.last)));
      },
    );

    test('a peer that never ACKs stops sending', () async {
      final clock = QuicManualClock();
      final linked = await _linked(clock: clock, dropAllClientApp: true);
      final client = linked.client;
      final id = client.openBidi();
      final wrote = await client.writeStream(id, Uint8List(20000));
      expect(wrote.isSuccess, isTrue, reason: '${wrote.errorOrNull}');
      await _pump();
      expect(client.pendingApplicationBytes, greaterThan(0));
      expect(
        client.lossRecovery.bytesInFlight,
        lessThanOrEqualTo(client.lossRecovery.congestionWindow),
      );
      expect(
        linked.appPackets.single,
        lessThan(quicInitialWindowDatagrams + 3),
      );
      var guard = 0;
      while (!client.lossRecovery.ptoBudgetExhausted && guard < 12) {
        final deadline = client.lossRecovery.lossDetectionDeadline;
        expect(deadline, isNotNull, reason: 'timer disarmed at guard $guard');
        final wait = deadline!.difference(clock.now());
        if (wait > Duration.zero) clock.advance(wait);
        final driven = await client.driveLossRecovery();
        await _pump();
        if (driven.isFailure) break;
        guard++;
      }
      expect(client.lossRecovery.ptoBudgetExhausted, isTrue);
      final stopped = linked.appPackets.single;
      clock.advance(const Duration(seconds: 30));
      final again = await client.driveLossRecovery();
      expect(again.isFailure, isTrue);
      expect(again.errorOrNull!.code, PqTransportErrorCode.closed);
      await _pump();
      expect(linked.appPackets.single, stopped);
      final extra = await client.writeStream(id, Uint8List.fromList([1]));
      expect(extra.isFailure, isTrue);
    });

    test('retransmitted CRYPTO at the same offset is not fed twice', () {
      final stream = QuicCryptoStream();
      final frame = QuicCryptoFrame(
        offset: 0,
        data: Uint8List.fromList([1, 2, 3]),
      );
      expect(stream.add(frame).isSuccess, isTrue);
      expect(stream.add(frame).isSuccess, isTrue);
      expect(stream.takeAvailable(), [1, 2, 3]);
      expect(stream.takeAvailable(), isEmpty);
      final conflict = QuicCryptoStream();
      expect(
        conflict
            .add(
              QuicCryptoFrame(offset: 0, data: Uint8List.fromList([1, 2, 3])),
            )
            .isSuccess,
        isTrue,
      );
      expect(
        conflict
            .add(
              QuicCryptoFrame(offset: 0, data: Uint8List.fromList([1, 9, 3])),
            )
            .isFailure,
        isTrue,
      );
    });

    test('a client Initial datagram is at least 1200 bytes', () async {
      final clock = QuicManualClock();
      final crypto = PqTransportCrypto();
      final identity = PqTlsServerIdentity.generate(crypto);
      final clientCid = crypto.randomBytes(quicShortDcidBytes);
      final serverCid = crypto.randomBytes(quicShortDcidBytes);
      late final PqQuicConn client;
      late final PqQuicConn server;
      final initialSizes = <int>[];
      client = PqQuicConn.client(
        crypto: crypto,
        localCid: clientCid,
        peerCid: serverCid,
        clock: clock,
        deliver: (packet) {
          if ((packet[0] & 0x80) != 0) initialSizes.add(packet.length);
          return server.ingestDatagram(packet);
        },
      );
      server = PqQuicConn.server(
        crypto: crypto,
        identity: identity,
        localCid: serverCid,
        peerCid: clientCid,
        clock: clock,
        deliver: (packet) => client.ingestDatagram(packet),
      );
      final started = await client.start();
      expect(started.isSuccess, isTrue, reason: '${started.errorOrNull}');
      await _pump();
      expect(initialSizes, isNotEmpty);
      for (final size in initialSizes) {
        expect(size, greaterThanOrEqualTo(quicMinClientInitialUdpBytes));
      }
    });

    test(
      'a dropped server Initial is retransmitted and the handshake finishes',
      () async {
        final clock = QuicManualClock();
        final crypto = PqTransportCrypto();
        final identity = PqTlsServerIdentity.generate(crypto);
        final clientCid = crypto.randomBytes(quicShortDcidBytes);
        final serverCid = crypto.randomBytes(quicShortDcidBytes);
        late final PqQuicConn client;
        late final PqQuicConn server;
        var dropServerInitial = true;
        client = PqQuicConn.client(
          crypto: crypto,
          localCid: clientCid,
          peerCid: serverCid,
          clock: clock,
          deliver: (packet) => server.ingestDatagram(packet),
        );
        server = PqQuicConn.server(
          crypto: crypto,
          identity: identity,
          localCid: serverCid,
          peerCid: clientCid,
          clock: clock,
          deliver: (packet) {
            if (dropServerInitial && (packet[0] & 0x80) != 0) {
              return Future<Result<void, PqTransportError>>.value(
                const Result.success(null),
              );
            }
            return client.ingestDatagram(packet);
          },
        );
        final started = await client.start();
        expect(started.isSuccess, isTrue, reason: '${started.errorOrNull}');
        await _pump();
        expect(client.isComplete, isFalse);
        dropServerInitial = false;
        for (var i = 0; i < 8 && !client.isComplete; i++) {
          final times = <DateTime>[
            if (client.lossRecovery.lossDetectionDeadline != null)
              client.lossRecovery.lossDetectionDeadline!,
            if (server.lossRecovery.lossDetectionDeadline != null)
              server.lossRecovery.lossDetectionDeadline!,
          ];
          if (times.isNotEmpty) {
            times.sort();
            final wait = times.first.difference(clock.now());
            if (wait > Duration.zero) clock.advance(wait);
          }
          final clientDriven = await client.driveLossRecovery();
          expect(
            clientDriven.isSuccess,
            isTrue,
            reason: '${clientDriven.errorOrNull}',
          );
          final serverDriven = await server.driveLossRecovery();
          expect(
            serverDriven.isSuccess,
            isTrue,
            reason: '${serverDriven.errorOrNull}',
          );
          await _pump();
        }
        expect(client.isComplete, isTrue);
        expect(server.isComplete, isTrue);
        final lostInitial = server.lossRecovery.lostPacketNumbers(initial);
        expect(lostInitial, isNotEmpty);
        for (final pn in lostInitial) {
          expect(server.lossRecovery.packetNumberUsed(initial, pn), isTrue);
          expect(server.lossRecovery.largestSent(initial), greaterThan(pn));
        }
      },
    );
  });
}

Future<void> _pump() async {
  for (var i = 0; i < 40; i++) {
    await Future<void>.delayed(Duration.zero);
  }
}

Future<void> _recover(PqQuicConn conn, QuicManualClock clock) async {
  for (var i = 0; i < 6; i++) {
    await _pump();
    final deadline = conn.lossRecovery.lossDetectionDeadline;
    if (deadline == null) continue;
    final wait = deadline.difference(clock.now());
    if (wait > Duration.zero) clock.advance(wait);
    final driven = await conn.driveLossRecovery();
    expect(driven.isSuccess, isTrue, reason: '${driven.errorOrNull}');
    await _pump();
  }
}

final class _Link {
  _Link(this.client, this.server, this.clientApp, this.appPackets);
  final PqQuicConn client;
  final PqQuicConn server;
  final List<Uint8List> clientApp;
  final List<int> appPackets;
}

Future<_Link> _linked({
  required QuicManualClock clock,
  bool dropNextClientApp = false,
  bool dropAllClientApp = false,
}) async {
  final crypto = PqTransportCrypto();
  final identity = PqTlsServerIdentity.generate(crypto);
  final clientCid = crypto.randomBytes(quicShortDcidBytes);
  final serverCid = crypto.randomBytes(quicShortDcidBytes);
  late final PqQuicConn client;
  late final PqQuicConn server;
  final clientApp = <Uint8List>[];
  final appPackets = <int>[0];
  var dropNext = dropNextClientApp;
  client = PqQuicConn.client(
    crypto: crypto,
    localCid: clientCid,
    peerCid: serverCid,
    clock: clock,
    deliver: (packet) {
      if ((packet[0] & 0x80) == 0) {
        appPackets[0]++;
        clientApp.add(Uint8List.fromList(packet));
        if (dropAllClientApp || dropNext) {
          dropNext = false;
          return Future<Result<void, PqTransportError>>.value(
            const Result.success(null),
          );
        }
      }
      return server.ingestDatagram(packet);
    },
  );
  server = PqQuicConn.server(
    crypto: crypto,
    identity: identity,
    localCid: serverCid,
    peerCid: clientCid,
    clock: clock,
    deliver: (packet) => client.ingestDatagram(packet),
  );
  final hand = await client.handshake();
  expect(hand.isSuccess, isTrue, reason: '${hand.errorOrNull}');
  await _pump();
  return _Link(client, server, clientApp, appPackets);
}
