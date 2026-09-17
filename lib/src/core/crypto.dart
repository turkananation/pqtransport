import 'dart:typed_data';

import 'package:pqforge/pqforge.dart';
import 'package:swissarmyknife/swissarmyknife.dart';

import 'errors.dart';
import 'hybrid.dart';
import 'lengths.dart';
import 'zeroize.dart';

/// AEAD primitive. Protocol files pick one; they do not vendor ChaCha or AES.
enum TransportAead { aes256Gcm, chacha20Poly1305 }

/// PointyCastle Poly1305 (pqforge ChaCha) needs integers wider than the
/// IEEE-754 mantissa. dart2js does not; the VM and dart2wasm do.
/// Runtime, not `const` — dart2js must evaluate this with JS numbers.
final bool transportHasFullWidthInteger =
    9007199254740992 + 1 != 9007199254740992;

/// Why IANA `0x1303` is refused on dart2js. Do not wrap PointyCastle's
/// `PlatformException` as a KEX failure.
const String chachaUnavailableMessage =
    'IANA 0x1303 ChaCha20-Poly1305 requires 64-bit integers; '
    'this runtime does not provide them';

/// Thin facade over `package:pqforge`. Protocol files must not invent primitives.
final class PqTransportCrypto {
  const PqTransportCrypto({this.profile = PqForgeProfile.balanced});

  final PqForgeProfile profile;

  PqKemAlgorithm get kem => profile.kem;
  PqSignatureAlgorithm get signature => profile.signature;

  /// KEM required by [group]. Compact (ML-KEM-512) matches no RFC 10024 group.
  static PqKemAlgorithm requiredKem(HybridGroup group) => switch (group) {
    HybridGroup.x25519MlKem768 => PqKemAlgorithm.mlKem768,
    HybridGroup.secP256r1MlKem768 => PqKemAlgorithm.mlKem768,
    HybridGroup.secP384r1MlKem1024 => PqKemAlgorithm.mlKem1024,
  };

  /// OPEN-03: refuse a profile whose KEM is not the group's ML-KEM.
  Result<void, PqTransportError> requireGroup(HybridGroup group) {
    final need = requiredKem(group);
    if (kem != need) {
      return Result.failure(
        PqTransportError.unsupported(
          'profile ${profile.name} (${kem.name}) is incompatible with '
          '${group.name} (needs ${need.name})',
        ),
      );
    }
    return const Result.success(null);
  }

  PqKeyPair kemKeyGen({Uint8List? seed}) =>
      PqKemPrimitives.generateKeyPair(kem, seed: seed);

  /// FIPS 203 §7.2 check **before** encapsulate (BLK-05). Never throws.
  bool checkEncapsulationKey(Uint8List publicKey) =>
      PqKemPrimitives.checkEncapsulationKey(kem, publicKey);

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

  Future<({Uint8List publicKey, Uint8List secretKey})> p256KeyGen({
    Uint8List? seed,
  }) => PqForgeHybridKeyAgreement.generateP256KeyPairBytes(seed: seed);

  Future<Uint8List> p256Agree({
    required Uint8List secretKey,
    required Uint8List remotePublicKey,
  }) => PqForgeHybridKeyAgreement.p256SharedSecret(
    secretKey: secretKey,
    remotePublicKey: remotePublicKey,
  );

  Future<({Uint8List publicKey, Uint8List secretKey})> p384KeyGen({
    Uint8List? seed,
  }) => PqForgeHybridKeyAgreement.generateP384KeyPairBytes(seed: seed);

  Future<Uint8List> p384Agree({
    required Uint8List secretKey,
    required Uint8List remotePublicKey,
  }) => PqForgeHybridKeyAgreement.p384SharedSecret(
    secretKey: secretKey,
    remotePublicKey: remotePublicKey,
  );

  /// Group-dispatched classical keygen (X25519 / P-256 / P-384).
  Future<({Uint8List publicKey, Uint8List secretKey})> classicalKeyGen(
    HybridGroup group, {
    Uint8List? seed,
  }) => switch (group) {
    HybridGroup.x25519MlKem768 => x25519KeyGen(seed: seed),
    HybridGroup.secP256r1MlKem768 => p256KeyGen(seed: seed),
    HybridGroup.secP384r1MlKem1024 => p384KeyGen(seed: seed),
  };

  /// Group-dispatched classical ECDH. Shared secret is the raw coordinate
  /// (X25519 output / NIST x-coordinate). Caller concatenates per RFC 10024.
  Future<Uint8List> classicalAgree(
    HybridGroup group, {
    required Uint8List secretKey,
    required Uint8List remotePublicKey,
  }) => switch (group) {
    HybridGroup.x25519MlKem768 => x25519Agree(
      secretKey: secretKey,
      remotePublicKey: remotePublicKey,
    ),
    HybridGroup.secP256r1MlKem768 => p256Agree(
      secretKey: secretKey,
      remotePublicKey: remotePublicKey,
    ),
    HybridGroup.secP384r1MlKem1024 => p384Agree(
      secretKey: secretKey,
      remotePublicKey: remotePublicKey,
    ),
  };

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

  Uint8List hmacSha384(Uint8List key, Uint8List data) =>
      PqBytes.hmacSha384(key: key, data: data);

  Uint8List sha256(Uint8List data) => PqBytes.sha256(data);

  Uint8List sha384(Uint8List data) => PqBytes.sha384(data);

  Uint8List randomBytes(int length) => PqBytes.randomBytes(length);

  /// PointyCastle Poly1305 needs 64-bit integers. dart2js cannot run ChaCha.
  bool get supportsChaCha20Poly1305 => transportHasFullWidthInteger;

  /// RFC 5869 Extract (SHA-256) via pqforge. UDP and the ChaCha suite.
  Uint8List hkdfExtract(Uint8List salt, Uint8List ikm) =>
      PqSymmetricPrimitives.hkdfExtractSha256(ikm: ikm, salt: salt);

  /// RFC 5869 Expand (SHA-256) via pqforge. Expand-Label stays in TLS.
  Uint8List hkdfExpand(Uint8List prk, Uint8List info, int length) =>
      PqSymmetricPrimitives.hkdfExpandSha256(
        prk: prk,
        info: info,
        outputBytes: length,
      );

  /// RFC 5869 Extract (SHA-384) via pqforge. TLS `0x1302` schedule (OPEN-02).
  Uint8List hkdfExtractSha384(Uint8List salt, Uint8List ikm) =>
      PqSymmetricPrimitives.hkdfExtractSha384(ikm: ikm, salt: salt);

  /// RFC 5869 Expand (SHA-384) via pqforge. Expand-Label stays in TLS.
  Uint8List hkdfExpandSha384(Uint8List prk, Uint8List info, int length) =>
      PqSymmetricPrimitives.hkdfExpandSha384(
        prk: prk,
        info: info,
        outputBytes: length,
      );

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

  Uint8List hkdfSha384({
    required Uint8List ikm,
    required Uint8List salt,
    required Uint8List info,
    int length = sha384HashBytes,
  }) => PqSymmetricPrimitives.hkdfSha384(
    ikm: ikm,
    salt: salt,
    info: info,
    outputBytes: length,
  );

  /// AEAD via pqforge (sync). Nonce uniqueness is the caller's duty.
  /// Default is AES-256-GCM (UDP, TLS `0x1302`). ChaCha is TLS `0x1303`.
  /// ChaCha on dart2js throws [PqTransportError.unsupported] — do not call
  /// PointyCastle and relabel the result as KEX.
  Uint8List aeadSeal({
    required Uint8List key,
    required Uint8List nonce,
    required Uint8List plaintext,
    Uint8List? aad,
    TransportAead aead = TransportAead.aes256Gcm,
  }) {
    _requireChaCha(aead);
    return switch (aead) {
      TransportAead.aes256Gcm => PqSymmetricPrimitives.aesGcmEncrypt(
        key: key,
        nonce: nonce,
        plaintext: plaintext,
        aad: aad,
      ),
      TransportAead.chacha20Poly1305 =>
        PqSymmetricPrimitives.chacha20Poly1305Encrypt(
          key: key,
          nonce: nonce,
          plaintext: plaintext,
          aad: aad,
        ),
    };
  }

  Uint8List aeadOpen({
    required Uint8List key,
    required Uint8List nonce,
    required Uint8List ciphertextWithTag,
    Uint8List? aad,
    TransportAead aead = TransportAead.aes256Gcm,
  }) {
    _requireChaCha(aead);
    return switch (aead) {
      TransportAead.aes256Gcm => PqSymmetricPrimitives.aesGcmDecrypt(
        key: key,
        nonce: nonce,
        ciphertext: ciphertextWithTag,
        aad: aad,
      ),
      TransportAead.chacha20Poly1305 =>
        PqSymmetricPrimitives.chacha20Poly1305Decrypt(
          key: key,
          nonce: nonce,
          ciphertext: ciphertextWithTag,
          aad: aad,
        ),
    };
  }

  void _requireChaCha(TransportAead aead) {
    if (aead == TransportAead.chacha20Poly1305 && !supportsChaCha20Poly1305) {
      throw PqTransportError.unsupported(chachaUnavailableMessage);
    }
  }

  HybridGroup get defaultGroup => switch (kem) {
    PqKemAlgorithm.mlKem1024 => HybridGroup.secP384r1MlKem1024,
    _ => HybridGroup.x25519MlKem768,
  };
}

void wipeKey(Uint8List key) => zeroize(key);
