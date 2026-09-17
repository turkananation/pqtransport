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

  test('ChaCha is dart2js-safe via pqforge and round-trips', () {
    expect(crypto.supportsChaCha20Poly1305, isTrue);
    expect(
      crypto.supportsChaCha20Poly1305,
      PqSymmetricPrimitives.supportsChaCha20Poly1305,
    );
    final key = crypto.randomBytes(aeadKeyBytes);
    final nonce = crypto.randomBytes(aeadNonceBytes);
    final pt = Uint8List.fromList([1, 2, 3, 4]);
    final ct = crypto.aeadSeal(
      key: key,
      nonce: nonce,
      plaintext: pt,
      aead: TransportAead.chacha20Poly1305,
    );
    expect(
      crypto.aeadOpen(
        key: key,
        nonce: nonce,
        ciphertextWithTag: ct,
        aead: TransportAead.chacha20Poly1305,
      ),
      pt,
    );
  });

  test('RFC 8439 §2.8.2 through the transport facade', () {
    final key = _hex(
      '808182838485868788898a8b8c8d8e8f'
      '909192939495969798999a9b9c9d9e9f',
    );
    final nonce = _hex('070000004041424344454647');
    final aad = _hex('50515253c0c1c2c3c4c5c6c7');
    final plaintext = _hex(
      '4c616469657320616e642047656e746c'
      '656d656e206f662074686520636c6173'
      '73206f66202739393a20496620492063'
      '6f756c64206f6666657220796f75206f'
      '6e6c79206f6e652074697020666f7220'
      '746865206675747572652c2073756e73'
      '637265656e20776f756c642062652069'
      '742e',
    );
    final expected = _hex(
      'd31a8d34648e60db7b86afbc53ef7ec2'
      'a4aded51296e08fea9e2b5a736ee62d6'
      '3dbea45e8ca9671282fafb69da92728b'
      '1a71de0a9e060b2905d6a5b67ecd3b36'
      '92ddbd7f2d778b8c9803aee328091b58'
      'fab324e4fad675945585808b4831d7bc'
      '3ff4def08e4b7a9de576d26586cec64b'
      '6116'
      '1ae10b594f09e26a7e902ecbd0600691',
    );
    final sealed = crypto.aeadSeal(
      key: key,
      nonce: nonce,
      plaintext: plaintext,
      aad: aad,
      aead: TransportAead.chacha20Poly1305,
    );
    expect(sealed, orderedEquals(expected));
    expect(
      crypto.aeadOpen(
        key: key,
        nonce: nonce,
        ciphertextWithTag: sealed,
        aad: aad,
        aead: TransportAead.chacha20Poly1305,
      ),
      plaintext,
    );
  });
}

Uint8List _hex(String s) {
  final out = Uint8List(s.length ~/ 2);
  for (var i = 0; i < out.length; i++) {
    out[i] = int.parse(s.substring(i * 2, i * 2 + 2), radix: 16);
  }
  return out;
}
