import 'dart:typed_data';

import 'package:pqtransport/src/core/hybrid.dart';
import 'package:pqtransport/src/core/lengths.dart';
import 'package:test/test.dart';

Uint8List _filled(int length, int value) =>
    Uint8List(length)..fillRange(0, length, value);

void main() {
  group('HybridGroup contracts', () {
    test('X25519MLKEM768 sizes and ML-KEM-first order', () {
      const g = HybridGroup.x25519MlKem768;
      expect(g.codepoint, namedGroupX25519MlKem768);
      expect(g.clientShareBytes, x25519MlKem768ClientShareBytes);
      expect(g.serverShareBytes, x25519MlKem768ServerShareBytes);
      expect(g.sharedSecretBytes, x25519MlKem768SharedSecretBytes);
      expect(g.concatOrder, HybridConcatOrder.kemThenClassical);
      expect(g.clientShareBytes, g.kemPublicKeyBytes + g.classicalShareBytes);
      expect(g.serverShareBytes, g.kemCiphertextBytes + g.classicalShareBytes);
    });

    test('SecP256r1MLKEM768 sizes and ECDHE-first order', () {
      const g = HybridGroup.secP256r1MlKem768;
      expect(g.codepoint, namedGroupSecP256r1MlKem768);
      expect(g.clientShareBytes, secP256r1MlKem768ClientShareBytes);
      expect(g.serverShareBytes, secP256r1MlKem768ServerShareBytes);
      expect(g.concatOrder, HybridConcatOrder.classicalThenKem);
    });

    test('SecP384r1MLKEM1024 sizes and ECDHE-first order', () {
      const g = HybridGroup.secP384r1MlKem1024;
      expect(g.codepoint, namedGroupSecP384r1MlKem1024);
      expect(g.kemPublicKeyBytes, mlKem1024PublicKeyBytes);
      expect(g.kemCiphertextBytes, mlKem1024CiphertextBytes);
      expect(g.clientShareBytes, secP384r1MlKem1024ClientShareBytes);
      expect(g.serverShareBytes, secP384r1MlKem1024ServerShareBytes);
      expect(g.sharedSecretBytes, secP384r1MlKem1024SharedSecretBytes);
      expect(g.concatOrder, HybridConcatOrder.classicalThenKem);
      expect(
        g.clientShareBytes,
        secp384r1UncompressedBytes + mlKem1024PublicKeyBytes,
      );
    });
  });

  group('X25519MLKEM768 concat', () {
    final g = HybridGroup.x25519MlKem768;
    final ek = _filled(g.kemPublicKeyBytes, 0x11);
    final ct = _filled(g.kemCiphertextBytes, 0x22);
    final x = _filled(g.classicalShareBytes, 0x33);

    test('client share is ek || x25519 and 1216 bytes', () {
      final encoded = encodeClientShare(
        HybridClientShare(group: g, kemEncapsulationKey: ek, classicalShare: x),
      );
      expect(encoded.isSuccess, isTrue);
      final wire = encoded.valueOrNull!;
      expect(wire.length, x25519MlKem768ClientShareBytes);
      expect(wire.sublist(0, g.kemPublicKeyBytes), ek);
      expect(wire.sublist(g.kemPublicKeyBytes), x);
      final decoded = decodeClientShare(g, wire);
      expect(decoded.isSuccess, isTrue);
      expect(decoded.valueOrNull!.kemEncapsulationKey, ek);
      expect(decoded.valueOrNull!.classicalShare, x);
    });

    test('server share is ct || x25519 and 1120 bytes', () {
      final encoded = encodeServerShare(
        HybridServerShare(group: g, kemCiphertext: ct, classicalShare: x),
      );
      expect(encoded.isSuccess, isTrue);
      final wire = encoded.valueOrNull!;
      expect(wire.length, x25519MlKem768ServerShareBytes);
      expect(wire.sublist(0, g.kemCiphertextBytes), ct);
      expect(wire.sublist(g.kemCiphertextBytes), x);
    });

    test('shared secret is ss_mlkem || ss_x25519', () {
      final kemSs = _filled(g.kemSharedSecretBytes, 0xA1);
      final xSs = _filled(g.classicalSharedSecretBytes, 0xB2);
      final combined = combineSharedSecret(
        group: g,
        kemSharedSecret: kemSs,
        classicalSharedSecret: xSs,
      );
      expect(combined.isSuccess, isTrue);
      final ss = combined.valueOrNull!;
      expect(ss.length, x25519MlKem768SharedSecretBytes);
      expect(ss.sublist(0, 32), kemSs);
      expect(ss.sublist(32), xSs);
    });
  });

  group('SecP256r1MLKEM768 concat', () {
    final g = HybridGroup.secP256r1MlKem768;
    final ek = _filled(g.kemPublicKeyBytes, 0x11);
    final ct = _filled(g.kemCiphertextBytes, 0x22);
    final p256 = _filled(g.classicalShareBytes, 0x33)
      ..[0] = uncompressedPointPrefix;

    test('client share is p256 || ek, 1249 bytes, leading 0x04', () {
      final encoded = encodeClientShare(
        HybridClientShare(
          group: g,
          kemEncapsulationKey: ek,
          classicalShare: p256,
        ),
      );
      expect(encoded.isSuccess, isTrue);
      final wire = encoded.valueOrNull!;
      expect(wire.length, secP256r1MlKem768ClientShareBytes);
      expect(wire[0], uncompressedPointPrefix);
      expect(wire.sublist(0, g.classicalShareBytes), p256);
      expect(wire.sublist(g.classicalShareBytes), ek);
    });

    test('server share is p256 || ct and 1153 bytes', () {
      final encoded = encodeServerShare(
        HybridServerShare(group: g, kemCiphertext: ct, classicalShare: p256),
      );
      expect(encoded.isSuccess, isTrue);
      final wire = encoded.valueOrNull!;
      expect(wire.length, secP256r1MlKem768ServerShareBytes);
      expect(wire.sublist(0, g.classicalShareBytes), p256);
      expect(wire.sublist(g.classicalShareBytes), ct);
    });

    test(
      'shared secret is ss_ecdhe || ss_mlkem (opposite of X25519 group)',
      () {
        final kemSs = _filled(g.kemSharedSecretBytes, 0xA1);
        final ecdhSs = _filled(g.classicalSharedSecretBytes, 0xB2);
        final combined = combineSharedSecret(
          group: g,
          kemSharedSecret: kemSs,
          classicalSharedSecret: ecdhSs,
        );
        expect(combined.isSuccess, isTrue);
        final ss = combined.valueOrNull!;
        expect(ss.length, secP256r1MlKem768SharedSecretBytes);
        expect(ss.sublist(0, 32), ecdhSs);
        expect(ss.sublist(32), kemSs);

        final x25519 = combineSharedSecret(
          group: HybridGroup.x25519MlKem768,
          kemSharedSecret: kemSs,
          classicalSharedSecret: ecdhSs,
        ).valueOrNull!;
        expect(ss, isNot(equals(x25519)));
      },
    );

    test('rejects uncompressed point without 0x04 prefix', () {
      final bad = _filled(g.classicalShareBytes, 0x02);
      final encoded = encodeClientShare(
        HybridClientShare(
          group: g,
          kemEncapsulationKey: ek,
          classicalShare: bad,
        ),
      );
      expect(encoded.isFailure, isTrue);
    });
  });

  group('SecP384r1MLKEM1024 concat', () {
    final g = HybridGroup.secP384r1MlKem1024;
    final ek = _filled(g.kemPublicKeyBytes, 0x11);
    final p384 = _filled(g.classicalShareBytes, 0x44)
      ..[0] = uncompressedPointPrefix;

    test('client share is p384 || ek_mlkem1024 and 1665 bytes', () {
      final encoded = encodeClientShare(
        HybridClientShare(
          group: g,
          kemEncapsulationKey: ek,
          classicalShare: p384,
        ),
      );
      expect(encoded.isSuccess, isTrue);
      final wire = encoded.valueOrNull!;
      expect(wire.length, secP384r1MlKem1024ClientShareBytes);
      expect(wire.sublist(0, secp384r1UncompressedBytes), p384);
      expect(wire.sublist(secp384r1UncompressedBytes), ek);
    });

    test('shared secret is 80 bytes, ecdhe (48) then mlkem (32)', () {
      final kemSs = _filled(g.kemSharedSecretBytes, 0xA1);
      final ecdhSs = _filled(g.classicalSharedSecretBytes, 0xB2);
      final combined = combineSharedSecret(
        group: g,
        kemSharedSecret: kemSs,
        classicalSharedSecret: ecdhSs,
      );
      expect(combined.isSuccess, isTrue);
      expect(combined.valueOrNull!.length, secP384r1MlKem1024SharedSecretBytes);
      expect(combined.valueOrNull!.sublist(0, 48), ecdhSs);
      expect(combined.valueOrNull!.sublist(48), kemSs);
    });
  });

  group('length filters', () {
    test('truncated and oversized client shares fail before split', () {
      final g = HybridGroup.x25519MlKem768;
      expect(
        decodeClientShare(g, Uint8List(g.clientShareBytes - 1)).isFailure,
        isTrue,
      );
      expect(
        decodeClientShare(g, Uint8List(g.clientShareBytes + 1)).isFailure,
        isTrue,
      );
      expect(
        decodeServerShare(g, Uint8List(g.serverShareBytes - 1)).isFailure,
        isTrue,
      );
    });

    test('all-zero classical shared secret is rejected', () {
      final r = combineSharedSecret(
        group: HybridGroup.x25519MlKem768,
        kemSharedSecret: _filled(32, 1),
        classicalSharedSecret: Uint8List(32),
      );
      expect(r.isFailure, isTrue);
    });
  });
}
