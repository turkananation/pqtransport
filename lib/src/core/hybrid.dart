import 'dart:typed_data';

import 'package:pqforge/pqforge.dart' hide requireLength;
import 'package:swissarmyknife/swissarmyknife.dart';

import 'bytes.dart';
import 'errors.dart';
import 'lengths.dart';

/// RFC 10024 concatenation order.
///
/// X25519MLKEM768 does **not** follow RFC 9954 naming order: ML-KEM is first.
/// NIST-curve groups put ECDHE first so the FIPS-approved secret leads the
/// SP 800-56C combiner.
enum HybridConcatOrder {
  /// Place the KEM secret before the classical secret.
  kemThenClassical,

  /// Place the classical secret before the KEM secret.
  classicalThenKem,
}

/// RFC 10024 hybrid named groups.
enum HybridGroup {
  /// X25519 with ML-KEM-768.
  x25519MlKem768,

  /// P-256 ECDH with ML-KEM-768.
  secP256r1MlKem768,

  /// P-384 ECDH with ML-KEM-1024.
  secP384r1MlKem1024,
}

extension HybridGroupContract on HybridGroup {
  /// RFC 10024 named-group codepoint.
  int get codepoint => switch (this) {
    HybridGroup.x25519MlKem768 => namedGroupX25519MlKem768,
    HybridGroup.secP256r1MlKem768 => namedGroupSecP256r1MlKem768,
    HybridGroup.secP384r1MlKem1024 => namedGroupSecP384r1MlKem1024,
  };

  /// Secret concatenation order required for this group.
  HybridConcatOrder get concatOrder => switch (this) {
    HybridGroup.x25519MlKem768 => HybridConcatOrder.kemThenClassical,
    HybridGroup.secP256r1MlKem768 => HybridConcatOrder.classicalThenKem,
    HybridGroup.secP384r1MlKem1024 => HybridConcatOrder.classicalThenKem,
  };

  /// Encapsulation-key size for this group's KEM.
  int get kemPublicKeyBytes => switch (this) {
    HybridGroup.x25519MlKem768 => mlKem768PublicKeyBytes,
    HybridGroup.secP256r1MlKem768 => mlKem768PublicKeyBytes,
    HybridGroup.secP384r1MlKem1024 => mlKem1024PublicKeyBytes,
  };

  /// Ciphertext size for this group's KEM.
  int get kemCiphertextBytes => switch (this) {
    HybridGroup.x25519MlKem768 => mlKem768CiphertextBytes,
    HybridGroup.secP256r1MlKem768 => mlKem768CiphertextBytes,
    HybridGroup.secP384r1MlKem1024 => mlKem1024CiphertextBytes,
  };

  /// KEM shared-secret size.
  int get kemSharedSecretBytes => switch (this) {
    HybridGroup.x25519MlKem768 => mlKem768SharedSecretBytes,
    HybridGroup.secP256r1MlKem768 => mlKem768SharedSecretBytes,
    HybridGroup.secP384r1MlKem1024 => mlKem1024SharedSecretBytes,
  };

  /// Classical public-share size.
  int get classicalShareBytes => switch (this) {
    HybridGroup.x25519MlKem768 => x25519ShareBytes,
    HybridGroup.secP256r1MlKem768 => secp256r1UncompressedBytes,
    HybridGroup.secP384r1MlKem1024 => secp384r1UncompressedBytes,
  };

  /// Classical shared-secret size.
  int get classicalSharedSecretBytes => switch (this) {
    HybridGroup.x25519MlKem768 => x25519SharedSecretBytes,
    HybridGroup.secP256r1MlKem768 => secp256r1SharedSecretBytes,
    HybridGroup.secP384r1MlKem1024 => secp384r1SharedSecretBytes,
  };

  /// Total client key-share size.
  int get clientShareBytes => switch (this) {
    HybridGroup.x25519MlKem768 => x25519MlKem768ClientShareBytes,
    HybridGroup.secP256r1MlKem768 => secP256r1MlKem768ClientShareBytes,
    HybridGroup.secP384r1MlKem1024 => secP384r1MlKem1024ClientShareBytes,
  };

  /// Total server key-share size.
  int get serverShareBytes => switch (this) {
    HybridGroup.x25519MlKem768 => x25519MlKem768ServerShareBytes,
    HybridGroup.secP256r1MlKem768 => secP256r1MlKem768ServerShareBytes,
    HybridGroup.secP384r1MlKem1024 => secP384r1MlKem1024ServerShareBytes,
  };

  /// Total hybrid shared-secret size.
  int get sharedSecretBytes => switch (this) {
    HybridGroup.x25519MlKem768 => x25519MlKem768SharedSecretBytes,
    HybridGroup.secP256r1MlKem768 => secP256r1MlKem768SharedSecretBytes,
    HybridGroup.secP384r1MlKem1024 => secP384r1MlKem1024SharedSecretBytes,
  };

  /// Length label for the KEM public key.
  PqLengthLabel get kemPublicLabel => switch (this) {
    HybridGroup.x25519MlKem768 => PqLengthLabel.mlKem768PublicKey,
    HybridGroup.secP256r1MlKem768 => PqLengthLabel.mlKem768PublicKey,
    HybridGroup.secP384r1MlKem1024 => PqLengthLabel.mlKem1024PublicKey,
  };

  /// Length label for the KEM ciphertext.
  PqLengthLabel get kemCiphertextLabel => switch (this) {
    HybridGroup.x25519MlKem768 => PqLengthLabel.mlKem768Ciphertext,
    HybridGroup.secP256r1MlKem768 => PqLengthLabel.mlKem768Ciphertext,
    HybridGroup.secP384r1MlKem1024 => PqLengthLabel.mlKem1024Ciphertext,
  };

  /// Length label for the classical share.
  PqLengthLabel get classicalShareLabel => switch (this) {
    HybridGroup.x25519MlKem768 => PqLengthLabel.x25519Share,
    HybridGroup.secP256r1MlKem768 => PqLengthLabel.secp256r1Share,
    HybridGroup.secP384r1MlKem1024 => PqLengthLabel.secp384r1Share,
  };

  /// Resolves an RFC 10024 codepoint, or returns `null` when unknown.
  static HybridGroup? byCodepoint(int codepoint) {
    for (final g in HybridGroup.values) {
      if (g.codepoint == codepoint) return g;
    }
    return null;
  }
}

/// Client key_share payload (encapsulation key + classical ephemeral share).
final class HybridClientShare {
  /// Creates a client hybrid key-share payload.
  const HybridClientShare({
    required this.group,
    required this.kemEncapsulationKey,
    required this.classicalShare,
  });

  /// Group encoded by this share.
  final HybridGroup group;

  /// KEM encapsulation key.
  final Uint8List kemEncapsulationKey;

  /// Classical public share.
  final Uint8List classicalShare;
}

/// Server key_share payload (KEM ciphertext + classical ephemeral share).
final class HybridServerShare {
  /// Creates a server hybrid key-share payload.
  const HybridServerShare({
    required this.group,
    required this.kemCiphertext,
    required this.classicalShare,
  });

  /// Group encoded by this share.
  final HybridGroup group;

  /// KEM ciphertext.
  final Uint8List kemCiphertext;

  /// Classical public share.
  final Uint8List classicalShare;
}

Result<Uint8List, PqTransportError> encodeClientShare(HybridClientShare share) {
  final g = share.group;
  final kem = requireLength(
    share.kemEncapsulationKey,
    g.kemPublicKeyBytes,
    g.kemPublicLabel,
  );
  if (kem.isFailure) return Result.failure(kem.errorOrNull!);
  final cls = requireLength(
    share.classicalShare,
    g.classicalShareBytes,
    g.classicalShareLabel,
  );
  if (cls.isFailure) return Result.failure(cls.errorOrNull!);
  final classicalCheck = _checkClassicalShare(g, share.classicalShare);
  if (classicalCheck.isFailure) {
    return Result.failure(classicalCheck.errorOrNull!);
  }
  return Result.success(
    _concat(g.concatOrder, kem.valueOrNull!, cls.valueOrNull!),
  );
}

Result<HybridClientShare, PqTransportError> decodeClientShare(
  HybridGroup group,
  Uint8List wire,
) {
  final sized = requireLength(
    wire,
    group.clientShareBytes,
    PqLengthLabel.hybridClientShare,
  );
  if (sized.isFailure) return Result.failure(sized.errorOrNull!);
  final split = _split(
    group.concatOrder,
    wire,
    kemLen: group.kemPublicKeyBytes,
    classicalLen: group.classicalShareBytes,
  );
  final classicalCheck = _checkClassicalShare(group, split.classical);
  if (classicalCheck.isFailure) {
    return Result.failure(classicalCheck.errorOrNull!);
  }
  return Result.success(
    HybridClientShare(
      group: group,
      kemEncapsulationKey: split.kem,
      classicalShare: split.classical,
    ),
  );
}

Result<Uint8List, PqTransportError> encodeServerShare(HybridServerShare share) {
  final g = share.group;
  final ct = requireLength(
    share.kemCiphertext,
    g.kemCiphertextBytes,
    g.kemCiphertextLabel,
  );
  if (ct.isFailure) return Result.failure(ct.errorOrNull!);
  final cls = requireLength(
    share.classicalShare,
    g.classicalShareBytes,
    g.classicalShareLabel,
  );
  if (cls.isFailure) return Result.failure(cls.errorOrNull!);
  final classicalCheck = _checkClassicalShare(g, share.classicalShare);
  if (classicalCheck.isFailure) {
    return Result.failure(classicalCheck.errorOrNull!);
  }
  return Result.success(
    _concat(g.concatOrder, ct.valueOrNull!, cls.valueOrNull!),
  );
}

Result<HybridServerShare, PqTransportError> decodeServerShare(
  HybridGroup group,
  Uint8List wire,
) {
  final sized = requireLength(
    wire,
    group.serverShareBytes,
    PqLengthLabel.hybridServerShare,
  );
  if (sized.isFailure) return Result.failure(sized.errorOrNull!);
  final split = _split(
    group.concatOrder,
    wire,
    kemLen: group.kemCiphertextBytes,
    classicalLen: group.classicalShareBytes,
  );
  final classicalCheck = _checkClassicalShare(group, split.classical);
  if (classicalCheck.isFailure) {
    return Result.failure(classicalCheck.errorOrNull!);
  }
  return Result.success(
    HybridServerShare(
      group: group,
      kemCiphertext: split.kem,
      classicalShare: split.classical,
    ),
  );
}

/// Concatenate component shared secrets in RFC 10024 group order.
Result<Uint8List, PqTransportError> combineSharedSecret({
  required HybridGroup group,
  required Uint8List kemSharedSecret,
  required Uint8List classicalSharedSecret,
}) {
  final kem = requireLength(
    kemSharedSecret,
    group.kemSharedSecretBytes,
    switch (group) {
      HybridGroup.x25519MlKem768 => PqLengthLabel.mlKem768SharedSecret,
      HybridGroup.secP256r1MlKem768 => PqLengthLabel.mlKem768SharedSecret,
      HybridGroup.secP384r1MlKem1024 => PqLengthLabel.mlKem1024SharedSecret,
    },
  );
  if (kem.isFailure) return Result.failure(kem.errorOrNull!);
  final cls = requireLength(
    classicalSharedSecret,
    group.classicalSharedSecretBytes,
    switch (group) {
      HybridGroup.x25519MlKem768 => PqLengthLabel.x25519SharedSecret,
      HybridGroup.secP256r1MlKem768 => PqLengthLabel.secp256r1SharedSecret,
      HybridGroup.secP384r1MlKem1024 => PqLengthLabel.secp384r1SharedSecret,
    },
  );
  if (cls.isFailure) return Result.failure(cls.errorOrNull!);
  if (isAllZeros(classicalSharedSecret)) {
    return Result.failure(
      PqTransportError.illegalParameter(
        PqLengthLabel.hybridSharedSecret,
        0,
        group.sharedSecretBytes,
      ),
    );
  }
  final order = switch (group.concatOrder) {
    HybridConcatOrder.kemThenClassical => PqHybridConcatOrder.pqThenClassical,
    HybridConcatOrder.classicalThenKem => PqHybridConcatOrder.classicalThenPq,
  };
  return Result.success(
    PqForgeCombiner.concatenateSharedSecrets(
      classicalSharedSecret: cls.valueOrNull!,
      postQuantumSharedSecret: kem.valueOrNull!,
      order: order,
    ),
  );
}

Result<void, PqTransportError> _checkClassicalShare(
  HybridGroup group,
  Uint8List share,
) {
  switch (group) {
    case HybridGroup.x25519MlKem768:
      return const Result.success(null);
    case HybridGroup.secP256r1MlKem768:
    case HybridGroup.secP384r1MlKem1024:
      if (share.isEmpty || share[0] != uncompressedPointPrefix) {
        return Result.failure(
          PqTransportError.illegalParameter(
            group.classicalShareLabel,
            share.isEmpty ? 0 : share[0],
            uncompressedPointPrefix,
          ),
        );
      }
      return const Result.success(null);
  }
}

Uint8List _concat(HybridConcatOrder order, Uint8List kem, Uint8List classical) {
  return switch (order) {
    HybridConcatOrder.kemThenClassical => concatBytes([kem, classical]),
    HybridConcatOrder.classicalThenKem => concatBytes([classical, kem]),
  };
}

({Uint8List kem, Uint8List classical}) _split(
  HybridConcatOrder order,
  Uint8List wire, {
  required int kemLen,
  required int classicalLen,
}) {
  return switch (order) {
    HybridConcatOrder.kemThenClassical => (
      kem: slice(wire, 0, kemLen),
      classical: slice(wire, kemLen, kemLen + classicalLen),
    ),
    HybridConcatOrder.classicalThenKem => (
      classical: slice(wire, 0, classicalLen),
      kem: slice(wire, classicalLen, classicalLen + kemLen),
    ),
  };
}
