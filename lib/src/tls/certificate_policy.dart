import 'dart:typed_data';

import 'package:pqforge/pqforge.dart';
import 'package:swissarmyknife/swissarmyknife.dart';

import '../core/errors.dart';
import '../core/lengths.dart';
import 'handshake.dart';

/// Called only after the certificate signature and the path or pin succeeded.
/// A failure is `certificate_unknown`. It cannot authorize a bad signature.
typedef PqCertificateHook =
    Result<void, PqTransportError> Function(
      PqX509Certificate leaf,
      List<Uint8List> chain,
      TlsCertificateVerify verify,
    );

PqTransportError x509Failure(PqX509Failure failure) => switch (failure) {
  PqX509Failure.truncated ||
  PqX509Failure.notDer ||
  PqX509Failure.depth ||
  PqX509Failure.tooLarge => PqTransportError.decodeFailure(failure.name),
  PqX509Failure.unsupportedAlgorithm || PqX509Failure.unsupportedVersion =>
    PqTransportError.unsupportedCertificate(failure.name),
  _ => PqTransportError.badCertificate(failure.name),
};

/// Trust decision for an X.509 Certificate message. Does not check
/// CertificateVerify. The caller does that under the returned leaf.
Result<PqX509Certificate, PqTransportError> authenticateX509({
  required List<Uint8List> entries,
  required List<Uint8List> trustAnchors,
  required Uint8List? trustedSpki,
  required DateTime now,
  required String? serverName,
  required PqCertificateHook? verifyPeer,
  required TlsCertificateVerify verify,
}) {
  if (entries.length > tlsCertificateListMax) {
    return Result.failure(
      PqTransportError.unsupportedCertificate('certificate list'),
    );
  }
  final parsed = <PqX509Certificate>[];
  for (final der in entries) {
    final one = PqX509.parse(der);
    final certificate = one.certificate;
    if (certificate == null) {
      return Result.failure(x509Failure(one.failure!));
    }
    parsed.add(certificate);
  }
  final leaf = parsed.first;
  if (decodeMlDsa65Spki(entries.first).isSuccess &&
      leaf.publicKey is! PqX509MlDsaKey) {
    return Result.failure(
      PqTransportError.unsupportedCertificate('raw public key'),
    );
  }
  if (trustAnchors.isEmpty && trustedSpki == null) {
    return Result.failure(PqTransportError.badCertificate('no trust anchor'));
  }
  if (trustAnchors.isNotEmpty) {
    final path = PqX509.validate(
      chain: entries,
      anchors: trustAnchors,
      now: now,
    );
    if (!path.trusted) return Result.failure(x509Failure(path.failure!));
  }
  if (trustedSpki != null) {
    if (entries.length != 1) {
      return Result.failure(PqTransportError.badCertificate('pin'));
    }
    if (!_sameDer(leaf.issuerDer, leaf.subjectDer) ||
        !PqX509.checkSignature(leaf, leaf.publicKey)) {
      return Result.failure(PqTransportError.badCertificate('pin'));
    }
    final spki = _leafSpki(leaf);
    if (spki == null ||
        spki.length != trustedSpki.length ||
        !PqBytes.constantTimeEquals(spki, trustedSpki)) {
      return Result.failure(PqTransportError.badCertificate('pin'));
    }
  }
  final name = _matchServerName(leaf, serverName);
  if (name.isFailure) return Result.failure(name.errorOrNull!);
  final usage = _tlsKeyUsage(leaf);
  if (usage.isFailure) return Result.failure(usage.errorOrNull!);
  if (verifyPeer != null) {
    final hook = verifyPeer(leaf, entries, verify);
    if (hook.isFailure) {
      return Result.failure(
        PqTransportError.certificateUnknown(hook.errorOrNull!.message),
      );
    }
  }
  return Result.success(leaf);
}

Result<void, PqTransportError> verifyLeafSignature({
  required PqX509Certificate leaf,
  required TlsCertificateVerify verify,
  required Uint8List content,
  required bool Function({
    required Uint8List publicKey,
    required Uint8List message,
    required Uint8List signatureBytes,
  })
  mlDsaVerify,
}) {
  final scheme = _schemeFor(leaf);
  if (scheme == null) {
    return Result.failure(
      PqTransportError.unsupportedCertificate(leaf.algorithm.name),
    );
  }
  if (verify.scheme != scheme) {
    return Result.failure(
      PqTransportError.decryptError('signature_scheme ${verify.scheme}'),
    );
  }
  final ok = switch (leaf.publicKey) {
    final PqX509MlDsaKey key => mlDsaVerify(
      publicKey: key.raw,
      message: content,
      signatureBytes: verify.signature,
    ),
    final PqX509EcdsaP256Key key => PqEcdsaP256.verify(
      publicKey: key.uncompressed,
      message: content,
      signature: verify.signature,
    ),
    final PqX509EcdsaP384Key key => PqEcdsaP384.verify(
      publicKey: key.uncompressed,
      message: content,
      signature: verify.signature,
    ),
    final PqX509Ed25519Key key => PqEd25519.verify(
      publicKey: key.raw,
      message: content,
      signature: verify.signature,
    ),
    final PqX509RsaKey key =>
      verify.scheme == tlsSignatureRsaPssSha256 ||
              verify.scheme == tlsSignatureRsaPssSha384 ||
              verify.scheme == tlsSignatureRsaPssSha512
          ? PqRsa.verifyPss(
              modulus: key.modulus,
              exponent: key.exponent,
              message: content,
              signature: verify.signature,
              hash: switch (verify.scheme) {
                tlsSignatureRsaPssSha384 => PqRsaHash.sha384,
                tlsSignatureRsaPssSha512 => PqRsaHash.sha512,
                _ => PqRsaHash.sha256,
              },
            )
          : false,
  };
  if (!ok) return Result.failure(PqTransportError.decryptError('verify'));
  return const Result.success(null);
}

int? _schemeFor(PqX509Certificate leaf) => switch (leaf.algorithm) {
  PqX509Algorithm.mlDsa65 => tlsSignatureMldsa65,
  PqX509Algorithm.mlDsa87 => tlsSignatureMldsa87,
  PqX509Algorithm.ecdsaP256Sha256 => tlsSignatureEcdsaP256Sha256,
  PqX509Algorithm.ecdsaP384Sha384 => tlsSignatureEcdsaP384Sha384,
  PqX509Algorithm.ed25519 => tlsSignatureEd25519,
  PqX509Algorithm.rsaPssSha256 => tlsSignatureRsaPssSha256,
  PqX509Algorithm.rsaPssSha384 => tlsSignatureRsaPssSha384,
  PqX509Algorithm.rsaPssSha512 => tlsSignatureRsaPssSha512,
  PqX509Algorithm.mlDsa44 ||
  PqX509Algorithm.rsaPkcs1Sha256 ||
  PqX509Algorithm.rsaPkcs1Sha384 ||
  PqX509Algorithm.rsaPkcs1Sha512 => null,
};

Uint8List? _leafSpki(PqX509Certificate leaf) => switch (leaf.publicKey) {
  final PqX509MlDsaKey key => encodeMlDsa65Spki(key.raw),
  _ => null,
};

bool _sameDer(Uint8List a, Uint8List b) {
  if (a.length != b.length) return false;
  return PqBytes.constantTimeEquals(a, b);
}

Result<void, PqTransportError> _tlsKeyUsage(PqX509Certificate leaf) {
  final bits = leaf.keyUsageBits;
  if (bits != null && (bits & 1) == 0) {
    return Result.failure(PqTransportError.badCertificate('keyUsage'));
  }
  if (leaf.extKeyUsage.isNotEmpty && !leaf.extKeyUsage.any(_isServerAuth)) {
    return Result.failure(PqTransportError.badCertificate('serverAuth'));
  }
  return const Result.success(null);
}

bool _isServerAuth(List<int> oid) {
  const server = [1, 3, 6, 1, 5, 5, 7, 3, 1];
  if (oid.length != server.length) return false;
  for (var i = 0; i < server.length; i++) {
    if (oid[i] != server[i]) return false;
  }
  return true;
}

Result<void, PqTransportError> _matchServerName(
  PqX509Certificate leaf,
  String? serverName,
) {
  if (serverName == null || serverName.isEmpty) {
    return const Result.success(null);
  }
  if (!_isAscii(serverName)) {
    return Result.failure(PqTransportError.badCertificate('serverName'));
  }
  final host = serverName.toLowerCase();
  for (final name in leaf.subjectAltNames) {
    if (name is PqX509DnsName && _dnsMatch(host, name.ascii.toLowerCase())) {
      return const Result.success(null);
    }
  }
  return Result.failure(PqTransportError.badCertificate('name'));
}

bool _dnsMatch(String host, String pattern) {
  if (!_isAscii(pattern)) return false;
  if (!pattern.startsWith('*.')) return host == pattern;
  final rest = pattern.substring(2);
  if (rest.isEmpty || rest.startsWith('.') || rest.contains('*')) return false;
  final dot = host.indexOf('.');
  if (dot <= 0) return false;
  return host.substring(dot + 1) == rest;
}

bool _isAscii(String value) {
  for (final unit in value.codeUnits) {
    if (unit > 0x7f) return false;
  }
  return true;
}
