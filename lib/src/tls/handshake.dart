import 'dart:typed_data';

import 'package:swissarmyknife/swissarmyknife.dart';

import '../core/bytes.dart';
import '../core/errors.dart';
import '../core/hybrid.dart';
import '../core/lengths.dart';
import 'record.dart';

final class ClientHello {
  const ClientHello({
    required this.random,
    required this.group,
    required this.share,
  });

  final Uint8List random;
  final HybridGroup group;
  final Uint8List share;

  Uint8List encode() {
    final b = BytesBuilder(copy: false);
    b.add(random);
    writeUint16(b, group.codepoint);
    writeUint16(b, share.length);
    b.add(share);
    return encodeHandshake(tlsHsClientHello, b.takeBytes());
  }

  static Result<ClientHello, PqTransportError> decode(Uint8List handshake) {
    final hs = decodeHandshake(handshake);
    if (hs.isFailure) return Result.failure(hs.errorOrNull!);
    final (type, body) = hs.valueOrNull!;
    if (type != tlsHsClientHello) {
      return Result.failure(
        PqTransportError.unexpectedMessage('expected client hello'),
      );
    }
    final r = ByteReader(body);
    final random = r.take(handshakeRandomBytes, PqLengthLabel.handshakeRandom);
    if (random.isFailure) return Result.failure(random.errorOrNull!);
    final cp = r.u16();
    if (cp.isFailure) return Result.failure(cp.errorOrNull!);
    final group = HybridGroupContract.byCodepoint(cp.valueOrNull!);
    if (group == null) {
      return Result.failure(
        PqTransportError.unsupported('named group ${cp.valueOrNull}'),
      );
    }
    final slen = r.u16();
    if (slen.isFailure) return Result.failure(slen.errorOrNull!);
    final share = r.take(slen.valueOrNull!, PqLengthLabel.hybridClientShare);
    if (share.isFailure) return Result.failure(share.errorOrNull!);
    final decoded = decodeClientShare(group, share.valueOrNull!);
    if (decoded.isFailure) return Result.failure(decoded.errorOrNull!);
    return Result.success(
      ClientHello(
        random: random.valueOrNull!,
        group: group,
        share: share.valueOrNull!,
      ),
    );
  }
}

final class ServerHello {
  const ServerHello({
    required this.random,
    required this.group,
    required this.share,
  });

  final Uint8List random;
  final HybridGroup group;
  final Uint8List share;

  Uint8List encode() {
    final b = BytesBuilder(copy: false);
    b.add(random);
    writeUint16(b, group.codepoint);
    writeUint16(b, share.length);
    b.add(share);
    return encodeHandshake(tlsHsServerHello, b.takeBytes());
  }

  static Result<ServerHello, PqTransportError> decode(Uint8List handshake) {
    final hs = decodeHandshake(handshake);
    if (hs.isFailure) return Result.failure(hs.errorOrNull!);
    final (type, body) = hs.valueOrNull!;
    if (type != tlsHsServerHello) {
      return Result.failure(
        PqTransportError.unexpectedMessage('expected server hello'),
      );
    }
    final r = ByteReader(body);
    final random = r.take(handshakeRandomBytes, PqLengthLabel.handshakeRandom);
    if (random.isFailure) return Result.failure(random.errorOrNull!);
    final cp = r.u16();
    if (cp.isFailure) return Result.failure(cp.errorOrNull!);
    final group = HybridGroupContract.byCodepoint(cp.valueOrNull!);
    if (group == null) {
      return Result.failure(
        PqTransportError.unsupported('named group ${cp.valueOrNull}'),
      );
    }
    final slen = r.u16();
    if (slen.isFailure) return Result.failure(slen.errorOrNull!);
    final share = r.take(slen.valueOrNull!, PqLengthLabel.hybridServerShare);
    if (share.isFailure) return Result.failure(share.errorOrNull!);
    final decoded = decodeServerShare(group, share.valueOrNull!);
    if (decoded.isFailure) return Result.failure(decoded.errorOrNull!);
    return Result.success(
      ServerHello(
        random: random.valueOrNull!,
        group: group,
        share: share.valueOrNull!,
      ),
    );
  }
}

Uint8List encodeCertificate(Uint8List mlDsaPublicKey) {
  final b = BytesBuilder(copy: false);
  writeUint16(b, mlDsaPublicKey.length);
  b.add(mlDsaPublicKey);
  return encodeHandshake(tlsHsCertificate, b.takeBytes());
}

Result<Uint8List, PqTransportError> decodeCertificate(Uint8List handshake) {
  final hs = decodeHandshake(handshake);
  if (hs.isFailure) return Result.failure(hs.errorOrNull!);
  final (type, body) = hs.valueOrNull!;
  if (type != tlsHsCertificate) {
    return Result.failure(
      PqTransportError.unexpectedMessage('expected certificate'),
    );
  }
  final r = ByteReader(body);
  final len = r.u16();
  if (len.isFailure) return Result.failure(len.errorOrNull!);
  return r.take(len.valueOrNull!, PqLengthLabel.mlDsa65PublicKey);
}

Uint8List encodeCertVerify(Uint8List signature) {
  final b = BytesBuilder(copy: false);
  writeUint16(b, signature.length);
  b.add(signature);
  return encodeHandshake(tlsHsCertificateVerify, b.takeBytes());
}

Result<Uint8List, PqTransportError> decodeCertVerify(Uint8List handshake) {
  final hs = decodeHandshake(handshake);
  if (hs.isFailure) return Result.failure(hs.errorOrNull!);
  final (type, body) = hs.valueOrNull!;
  if (type != tlsHsCertificateVerify) {
    return Result.failure(
      PqTransportError.unexpectedMessage('expected certificate verify'),
    );
  }
  final r = ByteReader(body);
  final len = r.u16();
  if (len.isFailure) return Result.failure(len.errorOrNull!);
  return r.take(len.valueOrNull!, PqLengthLabel.mlDsa65Signature);
}

Uint8List encodeFinished(Uint8List verifyData) =>
    encodeHandshake(tlsHsFinished, verifyData);

Result<Uint8List, PqTransportError> decodeFinished(Uint8List handshake) {
  final hs = decodeHandshake(handshake);
  if (hs.isFailure) return Result.failure(hs.errorOrNull!);
  final (type, body) = hs.valueOrNull!;
  if (type != tlsHsFinished) {
    return Result.failure(
      PqTransportError.unexpectedMessage('expected finished'),
    );
  }
  return requireLength(body, verifyDataBytes, PqLengthLabel.verifyData);
}

Uint8List encodeEncryptedExtensions() =>
    encodeHandshake(tlsHsEncryptedExtensions, Uint8List(0));
