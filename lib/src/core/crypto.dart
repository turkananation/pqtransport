import 'dart:typed_data';

import 'package:pqforge/pqforge.dart';

import 'bytes.dart';
import 'hybrid.dart';
import 'lengths.dart';
import 'zeroize.dart';

/// Thin facade over `package:pqforge`. Protocol files must not invent primitives.
final class PqTransportCrypto {
  const PqTransportCrypto({this.profile = PqForgeProfile.balanced});

  final PqForgeProfile profile;

  PqKemAlgorithm get kem => profile.kem;
  PqSignatureAlgorithm get signature => profile.signature;

  PqKeyPair kemKeyGen({Uint8List? seed}) =>
      PqKemPrimitives.generateKeyPair(kem, seed: seed);

  PqKemEncapsulation encapsulate(Uint8List publicKey) =>
      PqKemPrimitives.encapsulate(kem, publicKey);

  Uint8List decapsulate(Uint8List secretKey, Uint8List ciphertext) =>
      PqKemPrimitives.decapsulate(kem, secretKey, ciphertext);

  Future<({Uint8List publicKey, Uint8List secretKey})> x25519KeyGen({
    Uint8List? seed,
  }) => const PqForgeHybridKeyAgreement().generateClassicalKeyPairBytes(
    seed: seed,
  );

  Future<Uint8List> x25519Agree({
    required Uint8List secretKey,
    required Uint8List remotePublicKey,
  }) => PqForgeHybridKeyAgreement.x25519SharedSecret(
    secretKey: secretKey,
    remotePublicKey: remotePublicKey,
  );

  PqKeyPair mlDsaKeyGen() => PqSignaturePrimitives.generateKeyPair(signature);

  Uint8List mlDsaSign({
    required Uint8List secretKey,
    required Uint8List message,
    Uint8List? context,
  }) => PqSignaturePrimitives.sign(
    signature,
    secretKey,
    message,
    context: context,
  );

  bool mlDsaVerify({
    required Uint8List publicKey,
    required Uint8List message,
    required Uint8List signatureBytes,
    Uint8List? context,
  }) => PqSignaturePrimitives.verify(
    signature,
    publicKey,
    message,
    signatureBytes,
    context: context,
  );

  Uint8List hmac(Uint8List key, Uint8List data) =>
      PqBytes.hmacSha256(key: key, data: data);

  Uint8List sha256(Uint8List data) => PqBytes.sha256(data);

  Uint8List randomBytes(int length) => PqBytes.randomBytes(length);

  /// RFC 5869 Extract using pqforge HMAC-SHA-256.
  Uint8List hkdfExtract(Uint8List salt, Uint8List ikm) =>
      PqBytes.hmacSha256(key: salt, data: ikm);

  /// RFC 5869 Expand composed from pqforge HMAC-SHA-256.
  ///
  /// pqforge exports combined HKDF but not Expand-Label. This is protocol
  /// framing over the HMAC primitive, tested against RFC 5869 Appendix A.1.
  Uint8List hkdfExpand(Uint8List prk, Uint8List info, int length) {
    const hashLen = transcriptHashBytes;
    final n = (length + hashLen - 1) ~/ hashLen;
    final out = BytesBuilder(copy: false);
    var previous = Uint8List(0);
    for (var i = 1; i <= n; i++) {
      final block = hmac(
        prk,
        concatBytes([
          previous,
          info,
          Uint8List.fromList([i]),
        ]),
      );
      out.add(block);
      previous = block;
    }
    return Uint8List.fromList(out.takeBytes().sublist(0, length));
  }

  Uint8List hkdf({
    required Uint8List ikm,
    required Uint8List salt,
    required Uint8List info,
    int length = appSessionKeyBytes,
  }) => PqSymmetricPrimitives.hkdfSha256(
    ikm: ikm,
    salt: salt,
    info: info,
    outputBytes: length,
  );

  /// AES-256-GCM via pqforge (sync). Nonce uniqueness is the caller's duty.
  Uint8List aeadSeal({
    required Uint8List key,
    required Uint8List nonce,
    required Uint8List plaintext,
    Uint8List? aad,
  }) => PqSymmetricPrimitives.aesGcmEncrypt(
    key: key,
    nonce: nonce,
    plaintext: plaintext,
    aad: aad,
  );

  Uint8List aeadOpen({
    required Uint8List key,
    required Uint8List nonce,
    required Uint8List ciphertextWithTag,
    Uint8List? aad,
  }) => PqSymmetricPrimitives.aesGcmDecrypt(
    key: key,
    nonce: nonce,
    ciphertext: ciphertextWithTag,
    aad: aad,
  );

  HybridGroup get defaultGroup => switch (kem) {
    PqKemAlgorithm.mlKem1024 => HybridGroup.secP384r1MlKem1024,
    _ => HybridGroup.x25519MlKem768,
  };
}

void wipeKey(Uint8List key) => zeroize(key);
