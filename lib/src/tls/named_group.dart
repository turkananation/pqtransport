import 'dart:typed_data';

import 'package:swissarmyknife/swissarmyknife.dart';

import '../core/errors.dart';
import '../core/hybrid.dart';
import '../core/lengths.dart';

/// A TLS 1.3 named group this stack will select.
///
/// The three RFC 10024 values stay hybrids. The other four are whole
/// groups: the key share is only that algorithm, and the TLS secret is
/// not concatenated.
enum TlsNamedGroup {
  x25519(namedGroupX25519),
  secp256r1(namedGroupSecp256r1),
  secp384r1(namedGroupSecp384r1),
  mlKem1024(namedGroupMlKem1024),
  x25519MlKem768(namedGroupX25519MlKem768),
  secP256r1MlKem768(namedGroupSecP256r1MlKem768),
  secP384r1MlKem1024(namedGroupSecP384r1MlKem1024);

  const TlsNamedGroup(this.codepoint);

  final int codepoint;

  static TlsNamedGroup? byCodepoint(int codepoint) {
    for (final group in values) {
      if (group.codepoint == codepoint) return group;
    }
    return null;
  }

  static TlsNamedGroup fromHybrid(HybridGroup group) => switch (group) {
    HybridGroup.x25519MlKem768 => TlsNamedGroup.x25519MlKem768,
    HybridGroup.secP256r1MlKem768 => TlsNamedGroup.secP256r1MlKem768,
    HybridGroup.secP384r1MlKem1024 => TlsNamedGroup.secP384r1MlKem1024,
  };

  HybridGroup? get asHybrid => switch (this) {
    TlsNamedGroup.x25519MlKem768 => HybridGroup.x25519MlKem768,
    TlsNamedGroup.secP256r1MlKem768 => HybridGroup.secP256r1MlKem768,
    TlsNamedGroup.secP384r1MlKem1024 => HybridGroup.secP384r1MlKem1024,
    _ => null,
  };

  int get clientShareBytes => switch (this) {
    TlsNamedGroup.x25519 => x25519ShareBytes,
    TlsNamedGroup.secp256r1 => secp256r1UncompressedBytes,
    TlsNamedGroup.secp384r1 => secp384r1UncompressedBytes,
    TlsNamedGroup.mlKem1024 => mlKem1024PublicKeyBytes,
    TlsNamedGroup.x25519MlKem768 => x25519MlKem768ClientShareBytes,
    TlsNamedGroup.secP256r1MlKem768 => secP256r1MlKem768ClientShareBytes,
    TlsNamedGroup.secP384r1MlKem1024 => secP384r1MlKem1024ClientShareBytes,
  };

  int get serverShareBytes => switch (this) {
    TlsNamedGroup.x25519 => x25519ShareBytes,
    TlsNamedGroup.secp256r1 => secp256r1UncompressedBytes,
    TlsNamedGroup.secp384r1 => secp384r1UncompressedBytes,
    TlsNamedGroup.mlKem1024 => mlKem1024CiphertextBytes,
    TlsNamedGroup.x25519MlKem768 => x25519MlKem768ServerShareBytes,
    TlsNamedGroup.secP256r1MlKem768 => secP256r1MlKem768ServerShareBytes,
    TlsNamedGroup.secP384r1MlKem1024 => secP384r1MlKem1024ServerShareBytes,
  };
}

extension HybridTlsGroup on HybridGroup {
  TlsNamedGroup get named => TlsNamedGroup.fromHybrid(this);
}

/// Groups a classical or pure-only peer can force. Hybrid stays ahead of
/// these whenever the peer actually offered it.
const List<TlsNamedGroup> tlsClassicalFallbackGroups = [
  TlsNamedGroup.x25519,
  TlsNamedGroup.secp256r1,
  TlsNamedGroup.secp384r1,
  TlsNamedGroup.mlKem1024,
];

Result<void, PqTransportError> validateTlsKeyShare(
  TlsNamedGroup group,
  Uint8List share, {
  required bool fromServer,
}) {
  final hybrid = group.asHybrid;
  if (hybrid != null) {
    final decoded = fromServer
        ? decodeServerShare(hybrid, share)
        : decodeClientShare(hybrid, share);
    if (decoded.isFailure) return Result.failure(decoded.errorOrNull!);
    return const Result.success(null);
  }
  final expected = fromServer ? group.serverShareBytes : group.clientShareBytes;
  if (share.length != expected) {
    return Result.failure(
      PqTransportError.illegalParameter(
        _shareLabel(group, fromServer: fromServer),
        share.length,
        expected,
      ),
    );
  }
  if (group == TlsNamedGroup.secp256r1 || group == TlsNamedGroup.secp384r1) {
    if (share[0] != uncompressedPointPrefix) {
      return Result.failure(
        PqTransportError.illegalParameter(
          _shareLabel(group, fromServer: fromServer),
          share[0],
          uncompressedPointPrefix,
        ),
      );
    }
  }
  return const Result.success(null);
}

PqLengthLabel _shareLabel(TlsNamedGroup group, {required bool fromServer}) =>
    switch (group) {
      TlsNamedGroup.x25519 => PqLengthLabel.x25519Share,
      TlsNamedGroup.secp256r1 => PqLengthLabel.secp256r1Share,
      TlsNamedGroup.secp384r1 => PqLengthLabel.secp384r1Share,
      TlsNamedGroup.mlKem1024 =>
        fromServer
            ? PqLengthLabel.mlKem1024Ciphertext
            : PqLengthLabel.mlKem1024PublicKey,
      _ =>
        fromServer
            ? PqLengthLabel.hybridServerShare
            : PqLengthLabel.hybridClientShare,
    };
