import 'dart:typed_data';

import 'package:pqforge/pqforge.dart';
import 'package:pqtransport/pqtransport.dart';
import 'package:test/test.dart';

void main() {
  final crypto = PqTransportCrypto();

  test(
    'checkEncapsulationKey accepts a live key and rejects a bad modulus',
    () {
      final pair = crypto.kemKeyGen();
      expect(crypto.checkEncapsulationKey(pair.publicKey), isTrue);
      expect(
        crypto.checkEncapsulationKey(
          Uint8List.sublistView(pair.publicKey, 0, pair.publicKey.length - 1),
        ),
        isFalse,
      );
      final bad = Uint8List.fromList(pair.publicKey);
      // First 384 bytes pack 12-bit coefficients; 0xFF → 4095 ≥ q=3329.
      for (var i = 0; i < 384; i++) {
        bad[i] = 0xff;
      }
      expect(crypto.checkEncapsulationKey(bad), isFalse);
    },
  );

  test('requireGroup refuses compact and maximum with X25519MLKEM768', () {
    final compact = PqTransportCrypto(profile: PqForgeProfile.compact);
    expect(compact.requireGroup(HybridGroup.x25519MlKem768).isFailure, isTrue);
    final max = PqTransportCrypto(profile: PqForgeProfile.maximum);
    expect(max.requireGroup(HybridGroup.x25519MlKem768).isFailure, isTrue);
    expect(max.requireGroup(HybridGroup.secP256r1MlKem768).isFailure, isTrue);
    expect(max.requireGroup(HybridGroup.secP384r1MlKem1024).isSuccess, isTrue);
    expect(crypto.requireGroup(HybridGroup.x25519MlKem768).isSuccess, isTrue);
    expect(
      crypto.requireGroup(HybridGroup.secP256r1MlKem768).isSuccess,
      isTrue,
    );
  });

  test('P-256 ECDH round-trip through the facade', () async {
    final a = await crypto.p256KeyGen();
    final b = await crypto.p256KeyGen();
    final ab = await crypto.p256Agree(
      secretKey: a.secretKey,
      remotePublicKey: b.publicKey,
    );
    final ba = await crypto.p256Agree(
      secretKey: b.secretKey,
      remotePublicKey: a.publicKey,
    );
    expect(ab, ba);
    expect(ab.length, secp256r1SharedSecretBytes);
    expect(a.publicKey.length, secp256r1UncompressedBytes);
    expect(a.publicKey[0], uncompressedPointPrefix);
  });
}
