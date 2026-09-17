import 'dart:typed_data';

import 'package:pqtransport/pqtransport.dart';
import 'package:test/test.dart';

void main() {
  final crypto = PqTransportCrypto();

  TlsRecordLayer layerFor(Uint8List ikm) {
    final hash = Uint8List.fromList(List<int>.generate(32, (i) => i));
    final schedule = TlsKeySchedule(crypto)
      ..derive(
        hybridSharedSecret: ikm,
        handshakeTranscriptHash: hash,
        applicationTranscriptHash: hash,
      );
    return TlsRecordLayer(crypto, schedule);
  }

  test('handshake record AEAD round trip; bit-flip fails', () {
    final ikm = Uint8List.fromList(List<int>.generate(64, (i) => i + 3));
    final send = layerFor(ikm);
    final recv = layerFor(ikm);
    final inner = TlsRecord(
      type: tlsContentHandshake,
      payload: Uint8List.fromList([
        tlsHsFinished,
        0,
        0,
        32,
        ...List.filled(32, 9),
      ]),
    );
    final wire = send.protectWith(
      trafficSecret: send.schedule.serverHandshakeTraffic,
      iv: send.schedule.serverHandshakeIv,
      inner: inner,
    );
    final opened = recv.openWith(
      trafficSecret: recv.schedule.serverHandshakeTraffic,
      iv: recv.schedule.serverHandshakeIv,
      wire: wire,
    );
    expect(opened.isSuccess, isTrue, reason: '${opened.errorOrNull}');
    expect(opened.valueOrNull!.type, tlsContentHandshake);
    expect(opened.valueOrNull!.payload, inner.payload);

    final flipped = Uint8List.fromList(wire);
    flipped[flipped.length - 1] ^= 0x01;
    final bad = recv.openWith(
      trafficSecret: recv.schedule.serverHandshakeTraffic,
      iv: recv.schedule.serverHandshakeIv,
      wire: flipped,
    );
    expect(bad.isFailure, isTrue);
    expect(bad.errorOrNull!.code, PqTransportErrorCode.decryptError);
  });

  test('application epoch sequences start at zero independently', () {
    final ikm = Uint8List.fromList(List<int>.generate(64, (i) => 1));
    final send = layerFor(ikm);
    send.protectWith(
      trafficSecret: send.schedule.clientHandshakeTraffic,
      iv: send.schedule.clientHandshakeIv,
      inner: TlsRecord(
        type: tlsContentHandshake,
        payload: Uint8List.fromList([1]),
      ),
    );
    expect(send.handshakeWriteSequence, 1);
    expect(send.applicationWriteSequence, 0);
    send.protectWith(
      trafficSecret: send.schedule.clientApplicationTraffic,
      iv: send.schedule.clientApplicationIv,
      inner: TlsRecord(
        type: tlsContentApplicationData,
        payload: Uint8List.fromList([2]),
      ),
      epoch: TlsRecordEpoch.application,
    );
    expect(send.applicationWriteSequence, 1);
    expect(send.handshakeWriteSequence, 1);
  });

  test('plain record rejects short and oversized bodies', () {
    expect(decodePlainRecord(Uint8List(3)).isFailure, isTrue);
    final huge = BytesBuilder(copy: false)
      ..addByte(tlsContentHandshake)
      ..addByte(0x03)
      ..addByte(0x03)
      ..addByte(0x40)
      ..addByte(0x01) // 16385
      ..add(Uint8List(16385));
    expect(decodePlainRecord(huge.takeBytes()).isFailure, isTrue);
  });
}
