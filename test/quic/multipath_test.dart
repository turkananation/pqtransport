import 'dart:typed_data';

import 'package:pqtransport/pqtransport.dart';
import 'package:test/test.dart';

void main() {
  test('RFC 10069 nonce example, and path 0 matches RFC 9001', () {
    final iv = Uint8List.fromList([
      0x6b, 0x26, 0x11, 0x4b, 0x9c, 0xba, 0x2b, 0x63, //
      0xa9, 0xe8, 0xdd, 0x4f,
    ]);
    final nonce = quicMultipathNonce(iv, 3, 54321);
    expect(nonce, [
      0x6b, 0x26, 0x11, 0x48, 0x9c, 0xba, 0x2b, 0x63, //
      0xa9, 0xe8, 0x09, 0x7e,
    ]);
    expect(
      quicNonceEqual(
        quicMultipathNonce(iv, 0, 54321),
        quicAeadNonce(iv, 54321),
      ),
      isTrue,
    );
  });

  test(
    'every RFC 10069 frame round-trips and PATH_ACK is not ack-eliciting',
    () {
      final cid = Uint8List.fromList(List.filled(8, 7));
      final token = Uint8List(16)..[0] = 3;
      final frames = <QuicMultipathFrame>[
        const QuicPathAckFrame(
          pathId: 1,
          largest: 9,
          delay: 2,
          firstRange: 1,
          additional: [(1, 0)],
        ),
        const QuicPathAbandonFrame(2, quicErrorPathUnstable),
        const QuicPathStatusFrame(pathId: 1, sequence: 4, backup: true),
        QuicPathNewConnectionIdFrame(
          pathId: 1,
          sequence: 0,
          retirePriorTo: 0,
          connectionId: cid,
          statelessResetToken: token,
        ),
        const QuicPathRetireConnectionIdFrame(1, 0),
        const QuicMaxPathIdFrame(3),
        const QuicPathsBlockedFrame(3),
        const QuicPathCidsBlockedFrame(1, 2),
      ];
      final wire = BytesBuilder(copy: false);
      for (final frame in frames) {
        wire.add(frame.encode());
      }
      final parsed = decodeQuicPayload(wire.takeBytes());
      expect(parsed.isSuccess, isTrue, reason: '${parsed.errorOrNull}');
      final body = parsed.valueOrNull!;
      expect(body.multipath, hasLength(frames.length));
      expect(body.ackEliciting, isTrue);
      expect(body.multipath.first, isA<QuicPathAckFrame>());
      expect(body.multipath.first.ackEliciting, isFalse);
      final again = decodeQuicPayload(frames.first.encode());
      expect(again.valueOrNull!.ackEliciting, isFalse);
      final ack = body.multipath[0] as QuicPathAckFrame;
      expect(ack.pathId, 1);
      expect(ack.packetNumbers(), containsAll([9, 8, 5]));
      final cidFrame = body.multipath[3] as QuicPathNewConnectionIdFrame;
      expect(cidFrame.connectionId, cid);
      expect(decodeQuicPayload(Uint8List.fromList([0x3e])).isFailure, isTrue);
    },
  );

  test('MAX_PATH_ID below the initial value is an error', () {
    final paths = QuicMultipath(localInitialMax: 2, peerInitialMax: 2);
    expect(paths.apply(const QuicMaxPathIdFrame(1)).isFailure, isTrue);
    expect(paths.apply(const QuicMaxPathIdFrame(4)).isSuccess, isTrue);
    expect(paths.peerMax, 4);
    expect(paths.apply(const QuicMaxPathIdFrame(3)).isSuccess, isTrue);
    expect(paths.peerMax, 4);
  });
}
