import 'dart:typed_data';

import 'package:pqtransport/pqtransport.dart';
import 'package:test/test.dart';

void main() {
  test('integer codecs round trip', () {
    final b = BytesBuilder(copy: false);
    writeUint16(b, 0x1234);
    writeUint24(b, 0x123456);
    writeUint32(b, 0x89abcdef);
    final w = b.takeBytes();
    expect(readUint16(w, 0), 0x1234);
    expect(readUint24(w, 2), 0x123456);
    expect(readUint32(w, 5), 0x89abcdef);
  });

  test('ByteReader remaining helpers', () {
    final r = ByteReader(Uint8List.fromList([0, 1, 2, 3, 4, 5, 6, 7]));
    expect(r.u32().isSuccess, isTrue);
    expect(r.u32().isSuccess, isTrue);
    expect(r.isDone, isTrue);
    expect(r.u8().isFailure, isTrue);
    expect(r.u16().isFailure, isTrue);
    expect(r.u24().isFailure, isTrue);
    expect(r.u32().isFailure, isTrue);
    expect(r.u64().isFailure, isTrue);
  });

  test('requireMinLength rejects short buffers', () {
    expect(
      requireMinLength(Uint8List(3), 4, PqLengthLabel.datagram).isFailure,
      isTrue,
    );
    expect(
      requireMinLength(Uint8List(4), 4, PqLengthLabel.datagram).isSuccess,
      isTrue,
    );
  });

  test('isAllZeros and concatBytes', () {
    expect(isAllZeros(Uint8List(4)), isTrue);
    expect(isAllZeros(Uint8List.fromList([0, 1])), isFalse);
    expect(
      concatBytes([
        Uint8List.fromList([1]),
        Uint8List.fromList([2, 3]),
      ]),
      [1, 2, 3],
    );
  });

  test('transcript snapshot is Hash.length and changes when added', () {
    final t = Transcript();
    t.add(Uint8List.fromList([1]));
    final a = t.snapshot();
    expect(a.length, sha384HashBytes);
    t.add(Uint8List.fromList([2]));
    expect(t.snapshot(), isNot(equals(a)));
    t.clear();
    expect(t.length, 0);
    final sha256t = Transcript(hashKind: TranscriptHashKind.sha256);
    sha256t.add(Uint8List.fromList([1]));
    expect(sha256t.snapshot().length, sha256HashBytes);
  });

  test('error toString never contains secret bytes', () {
    final secret = Uint8List.fromList(List<int>.generate(32, (i) => i + 40));
    final err = requireLength(
      secret,
      33,
      PqLengthLabel.sessionKey,
    ).errorOrNull!;
    expect(err.toString().contains(String.fromCharCodes(secret)), isFalse);
    expect(PqTransportError.decryptError('x').alert, tlsAlertDecryptError);
    expect(PqTransportError.replay('x').code, PqTransportErrorCode.replay);
    expect(
      PqTransportError.throttled('x').code,
      PqTransportErrorCode.throttled,
    );
    expect(PqTransportError.closed('x').code, PqTransportErrorCode.closed);
  });

  test('zeroize of null and empty is a no-op', () {
    zeroize(null);
    zeroize(Uint8List(0));
  });

  test('HybridGroup.byCodepoint', () {
    expect(
      HybridGroupContract.byCodepoint(namedGroupX25519MlKem768),
      HybridGroup.x25519MlKem768,
    );
    expect(HybridGroupContract.byCodepoint(0), isNull);
  });
}
