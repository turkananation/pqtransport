import 'dart:typed_data';

import 'package:pqforge/pqforge.dart';
import 'package:swissarmyknife/swissarmyknife.dart';

import '../core/bytes.dart';
import '../core/crypto.dart';
import '../core/errors.dart';
import '../core/hybrid.dart';
import '../core/zeroize.dart';
import 'named_group.dart';

/// One key share this stack generated, plus the secret that finishes it.
final class TlsLocalShare {
  TlsLocalShare({
    required this.group,
    required this.wire,
    this.kemSecret,
    this.classicalSecret,
  });

  final TlsNamedGroup group;
  final Uint8List wire;
  Uint8List? kemSecret;
  Uint8List? classicalSecret;

  void wipe() {
    zeroize(kemSecret);
    zeroize(classicalSecret);
    kemSecret = null;
    classicalSecret = null;
  }
}

void wipeTlsShares(List<TlsLocalShare> shares) {
  for (final share in shares) {
    share.wipe();
  }
}

/// Client key share for [group]. Hybrid groups still go through the profile gate.
Future<Result<TlsLocalShare, PqTransportError>> mintTlsClientShare(
  PqTransportCrypto crypto,
  TlsNamedGroup group,
) async {
  final hybrid = group.asHybrid;
  if (hybrid != null) {
    final gate = crypto.requireGroup(hybrid);
    if (gate.isFailure) return Result.failure(gate.errorOrNull!);
    final kem = crypto.kemKeyGen();
    final classical = await crypto.classicalKeyGen(hybrid);
    final wire = encodeClientShare(
      HybridClientShare(
        group: hybrid,
        kemEncapsulationKey: kem.publicKey,
        classicalShare: classical.publicKey,
      ),
    );
    if (wire.isFailure) {
      zeroize(kem.secretKey);
      zeroize(classical.secretKey);
      return Result.failure(wire.errorOrNull!);
    }
    return Result.success(
      TlsLocalShare(
        group: group,
        wire: wire.valueOrNull!,
        kemSecret: kem.secretKey,
        classicalSecret: classical.secretKey,
      ),
    );
  }
  switch (group) {
    case TlsNamedGroup.x25519:
      final kp = await crypto.x25519KeyGen();
      return Result.success(
        TlsLocalShare(
          group: group,
          wire: kp.publicKey,
          classicalSecret: kp.secretKey,
        ),
      );
    case TlsNamedGroup.secp256r1:
      final kp = await crypto.p256KeyGen();
      return Result.success(
        TlsLocalShare(
          group: group,
          wire: kp.publicKey,
          classicalSecret: kp.secretKey,
        ),
      );
    case TlsNamedGroup.secp384r1:
      final kp = await crypto.p384KeyGen();
      return Result.success(
        TlsLocalShare(
          group: group,
          wire: kp.publicKey,
          classicalSecret: kp.secretKey,
        ),
      );
    case TlsNamedGroup.mlKem1024:
      final kem = PqKemPrimitives.generateKeyPair(PqKemAlgorithm.mlKem1024);
      return Result.success(
        TlsLocalShare(
          group: group,
          wire: kem.publicKey,
          kemSecret: kem.secretKey,
        ),
      );
    case TlsNamedGroup.x25519MlKem768:
    case TlsNamedGroup.secP256r1MlKem768:
    case TlsNamedGroup.secP384r1MlKem1024:
      return Result.failure(
        PqTransportError.unsupported('named group ${group.codepoint}'),
      );
  }
}

/// Finish our client share with the server's key share. Wipes [local].
Future<Result<Uint8List, PqTransportError>> deriveTlsSharedSecret(
  PqTransportCrypto crypto,
  TlsLocalShare local,
  Uint8List serverShare,
) async {
  try {
    final checked = validateTlsKeyShare(
      local.group,
      serverShare,
      fromServer: true,
    );
    if (checked.isFailure) return Result.failure(checked.errorOrNull!);
    final hybrid = local.group.asHybrid;
    if (hybrid != null) {
      final decoded = decodeServerShare(hybrid, serverShare);
      if (decoded.isFailure) return Result.failure(decoded.errorOrNull!);
      final share = decoded.valueOrNull!;
      final kemSecret = local.kemSecret;
      final classicalSecret = local.classicalSecret;
      if (kemSecret == null || classicalSecret == null) {
        return Result.failure(PqTransportError.decryptError('missing share'));
      }
      final ssKem = crypto.decapsulate(kemSecret, share.kemCiphertext);
      Uint8List? ssClassical;
      try {
        ssClassical = await crypto.classicalAgree(
          hybrid,
          secretKey: classicalSecret,
          remotePublicKey: share.classicalShare,
        );
        if (isAllZeros(ssClassical)) {
          return Result.failure(
            PqTransportError.decryptError('classical all-zero'),
          );
        }
        return combineSharedSecret(
          group: hybrid,
          kemSharedSecret: ssKem,
          classicalSharedSecret: ssClassical,
        );
      } finally {
        zeroize(ssKem);
        zeroize(ssClassical);
      }
    }
    switch (local.group) {
      case TlsNamedGroup.x25519:
      case TlsNamedGroup.secp256r1:
      case TlsNamedGroup.secp384r1:
        final secretKey = local.classicalSecret;
        if (secretKey == null) {
          return Result.failure(PqTransportError.decryptError('missing share'));
        }
        final ss = switch (local.group) {
          TlsNamedGroup.x25519 => await crypto.x25519Agree(
            secretKey: secretKey,
            remotePublicKey: serverShare,
          ),
          TlsNamedGroup.secp256r1 => await crypto.p256Agree(
            secretKey: secretKey,
            remotePublicKey: serverShare,
          ),
          _ => await crypto.p384Agree(
            secretKey: secretKey,
            remotePublicKey: serverShare,
          ),
        };
        if (isAllZeros(ss)) {
          return Result.failure(
            PqTransportError.decryptError('classical all-zero'),
          );
        }
        return Result.success(ss);
      case TlsNamedGroup.mlKem1024:
        final secretKey = local.kemSecret;
        if (secretKey == null) {
          return Result.failure(PqTransportError.decryptError('missing share'));
        }
        return Result.success(
          PqKemPrimitives.decapsulate(
            PqKemAlgorithm.mlKem1024,
            secretKey,
            serverShare,
          ),
        );
      case TlsNamedGroup.x25519MlKem768:
      case TlsNamedGroup.secP256r1MlKem768:
      case TlsNamedGroup.secP384r1MlKem1024:
        return Result.failure(
          PqTransportError.unsupported('named group ${local.group.codepoint}'),
        );
    }
  } on PqTransportError catch (error) {
    return Result.failure(error);
  } on Object catch (error) {
    return Result.failure(
      PqTransportError.decryptError('kex ${error.runtimeType}'),
    );
  } finally {
    local.wipe();
  }
}

/// Server accepts [clientShare] and returns the TLS secret plus its share.
Future<Result<({Uint8List secret, Uint8List serverShare}), PqTransportError>>
acceptTlsClientShare(
  PqTransportCrypto crypto,
  TlsNamedGroup group,
  Uint8List clientShare,
) async {
  final checked = validateTlsKeyShare(group, clientShare, fromServer: false);
  if (checked.isFailure) return Result.failure(checked.errorOrNull!);
  final hybrid = group.asHybrid;
  if (hybrid != null) {
    final gate = crypto.requireGroup(hybrid);
    if (gate.isFailure) return Result.failure(gate.errorOrNull!);
    final decoded = decodeClientShare(hybrid, clientShare);
    if (decoded.isFailure) return Result.failure(decoded.errorOrNull!);
    final share = decoded.valueOrNull!;
    if (!crypto.checkEncapsulationKey(share.kemEncapsulationKey)) {
      return Result.failure(
        PqTransportError.illegalKemKey(hybrid.kemPublicLabel),
      );
    }
    final classical = await crypto.classicalKeyGen(hybrid);
    Uint8List? ssKem;
    Uint8List? ssClassical;
    try {
      final enc = crypto.encapsulate(share.kemEncapsulationKey);
      ssKem = enc.sharedSecret;
      ssClassical = await crypto.classicalAgree(
        hybrid,
        secretKey: classical.secretKey,
        remotePublicKey: share.classicalShare,
      );
      if (isAllZeros(ssClassical)) {
        return Result.failure(
          PqTransportError.decryptError('classical all-zero'),
        );
      }
      final combined = combineSharedSecret(
        group: hybrid,
        kemSharedSecret: ssKem,
        classicalSharedSecret: ssClassical,
      );
      if (combined.isFailure) return Result.failure(combined.errorOrNull!);
      final serverShare = encodeServerShare(
        HybridServerShare(
          group: hybrid,
          kemCiphertext: enc.ciphertext,
          classicalShare: classical.publicKey,
        ),
      );
      if (serverShare.isFailure) {
        return Result.failure(serverShare.errorOrNull!);
      }
      return Result.success((
        secret: combined.valueOrNull!,
        serverShare: serverShare.valueOrNull!,
      ));
    } on PqTransportError catch (error) {
      return Result.failure(error);
    } on Object catch (error) {
      return Result.failure(
        PqTransportError.decryptError('kex ${error.runtimeType}'),
      );
    } finally {
      zeroize(classical.secretKey);
      zeroize(ssKem);
      zeroize(ssClassical);
    }
  }
  try {
    switch (group) {
      case TlsNamedGroup.x25519:
        final kp = await crypto.x25519KeyGen();
        try {
          final ss = await crypto.x25519Agree(
            secretKey: kp.secretKey,
            remotePublicKey: clientShare,
          );
          if (isAllZeros(ss)) {
            return Result.failure(
              PqTransportError.decryptError('classical all-zero'),
            );
          }
          return Result.success((secret: ss, serverShare: kp.publicKey));
        } finally {
          zeroize(kp.secretKey);
        }
      case TlsNamedGroup.secp256r1:
        final kp = await crypto.p256KeyGen();
        try {
          final ss = await crypto.p256Agree(
            secretKey: kp.secretKey,
            remotePublicKey: clientShare,
          );
          if (isAllZeros(ss)) {
            return Result.failure(
              PqTransportError.decryptError('classical all-zero'),
            );
          }
          return Result.success((secret: ss, serverShare: kp.publicKey));
        } finally {
          zeroize(kp.secretKey);
        }
      case TlsNamedGroup.secp384r1:
        final kp = await crypto.p384KeyGen();
        try {
          final ss = await crypto.p384Agree(
            secretKey: kp.secretKey,
            remotePublicKey: clientShare,
          );
          if (isAllZeros(ss)) {
            return Result.failure(
              PqTransportError.decryptError('classical all-zero'),
            );
          }
          return Result.success((secret: ss, serverShare: kp.publicKey));
        } finally {
          zeroize(kp.secretKey);
        }
      case TlsNamedGroup.mlKem1024:
        if (!PqKemPrimitives.checkEncapsulationKey(
          PqKemAlgorithm.mlKem1024,
          clientShare,
        )) {
          return Result.failure(
            PqTransportError.illegalKemKey(PqLengthLabel.mlKem1024PublicKey),
          );
        }
        final enc = PqKemPrimitives.encapsulate(
          PqKemAlgorithm.mlKem1024,
          clientShare,
        );
        return Result.success((
          secret: enc.sharedSecret,
          serverShare: enc.ciphertext,
        ));
      case TlsNamedGroup.x25519MlKem768:
      case TlsNamedGroup.secP256r1MlKem768:
      case TlsNamedGroup.secP384r1MlKem1024:
        return Result.failure(
          PqTransportError.unsupported('named group ${group.codepoint}'),
        );
    }
  } on PqTransportError catch (error) {
    return Result.failure(error);
  } on Object catch (error) {
    return Result.failure(
      PqTransportError.decryptError('kex ${error.runtimeType}'),
    );
  }
}
