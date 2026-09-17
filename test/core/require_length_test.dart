import 'dart:typed_data';

import 'package:pqtransport/src/core/bytes.dart';
import 'package:pqtransport/src/core/errors.dart';
import 'package:pqtransport/src/core/lengths.dart';
import 'package:pqtransport/src/core/zeroize.dart';
import 'package:test/test.dart';

void main() {
  group('requireLength', () {
    test('accepts exact length', () {
      final bytes = Uint8List(mlKem768PublicKeyBytes);
      final r = requireLength(
        bytes,
        mlKem768PublicKeyBytes,
        PqLengthLabel.mlKem768PublicKey,
      );
      expect(r.isSuccess, isTrue);
      expect(r.valueOrNull, bytes);
    });

    test('rejects n-1 and n+1', () {
      expect(
        requireLength(
          Uint8List(mlKem768PublicKeyBytes - 1),
          mlKem768PublicKeyBytes,
          PqLengthLabel.mlKem768PublicKey,
        ).isFailure,
        isTrue,
      );
      expect(
        requireLength(
          Uint8List(mlKem768PublicKeyBytes + 1),
          mlKem768PublicKeyBytes,
          PqLengthLabel.mlKem768PublicKey,
        ).isFailure,
        isTrue,
      );
    });

    test('error does not embed the buffer', () {
      final secret = Uint8List.fromList(List<int>.generate(32, (i) => i + 1));
      final r = requireLength(secret, nonceBytes + 1, PqLengthLabel.nonce);
      expect(
        r.errorOrNull!.message.contains(String.fromCharCodes(secret)),
        isFalse,
      );
      expect(r.errorOrNull!.code, PqTransportErrorCode.illegalParameter);
    });
  });

  group('zeroize', () {
    test('overwrites the buffer', () {
      final buf = Uint8List.fromList([1, 2, 3, 4]);
      zeroize(buf);
      expect(buf, everyElement(0));
    });

    test('withSecrets wipes even on throw', () {
      final a = Uint8List.fromList([9, 9]);
      expect(
        () => withSecrets([a], () => throw StateError('boom')),
        throwsA(isA<StateError>()),
      );
      expect(a, everyElement(0));
    });
  });

  group('ByteReader', () {
    test('reads and reports truncation', () {
      final r = ByteReader(Uint8List.fromList([0x01, 0x02]));
      expect(r.u16().valueOrNull, 0x0102);
      expect(r.u8().isFailure, isTrue);
    });
  });
}
