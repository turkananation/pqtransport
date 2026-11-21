import 'dart:convert';
import 'dart:typed_data';

import 'package:pqforge/pqforge.dart';
import 'package:swissarmyknife/swissarmyknife.dart';

import '../core/bytes.dart';
import '../core/crypto.dart';
import '../core/errors.dart';
import '../core/lengths.dart';
import 'cert_compress.dart';
import 'handshake.dart';
import 'record.dart';

/// IANA code point for one SLH-DSA parameter set, or null.
int? tlsSlhDsaOidLast(int scheme) => switch (scheme) {
  tlsSignatureSlhDsaSha2128s => 20,
  tlsSignatureSlhDsaSha2128f => 21,
  tlsSignatureSlhDsaSha2192s => 22,
  tlsSignatureSlhDsaSha2192f => 23,
  tlsSignatureSlhDsaSha2256s => 24,
  tlsSignatureSlhDsaSha2256f => 25,
  tlsSignatureSlhDsaShake128s => 26,
  tlsSignatureSlhDsaShake128f => 27,
  tlsSignatureSlhDsaShake192s => 28,
  tlsSignatureSlhDsaShake192f => 29,
  tlsSignatureSlhDsaShake256s => 30,
  tlsSignatureSlhDsaShake256f => 31,
  _ => null,
};

PqSlhDsaAlgorithm? tlsSlhDsaAlgorithm(int scheme) => switch (scheme) {
  tlsSignatureSlhDsaSha2128s => PqSlhDsaAlgorithm.sha2128s,
  tlsSignatureSlhDsaSha2128f => PqSlhDsaAlgorithm.sha2128f,
  tlsSignatureSlhDsaSha2192s => PqSlhDsaAlgorithm.sha2192s,
  tlsSignatureSlhDsaSha2192f => PqSlhDsaAlgorithm.sha2192f,
  tlsSignatureSlhDsaSha2256s => PqSlhDsaAlgorithm.sha2256s,
  tlsSignatureSlhDsaSha2256f => PqSlhDsaAlgorithm.sha2256f,
  tlsSignatureSlhDsaShake128s => PqSlhDsaAlgorithm.shake128s,
  tlsSignatureSlhDsaShake128f => PqSlhDsaAlgorithm.shake128f,
  tlsSignatureSlhDsaShake192s => PqSlhDsaAlgorithm.shake192s,
  tlsSignatureSlhDsaShake192f => PqSlhDsaAlgorithm.shake192f,
  tlsSignatureSlhDsaShake256s => PqSlhDsaAlgorithm.shake256s,
  tlsSignatureSlhDsaShake256f => PqSlhDsaAlgorithm.shake256f,
  _ => null,
};

int tlsSlhDsaPublicKeyBytes(int scheme) => switch (scheme) {
  tlsSignatureSlhDsaSha2128s ||
  tlsSignatureSlhDsaSha2128f ||
  tlsSignatureSlhDsaShake128s ||
  tlsSignatureSlhDsaShake128f => slhDsa128PublicKeyBytes,
  tlsSignatureSlhDsaSha2192s ||
  tlsSignatureSlhDsaSha2192f ||
  tlsSignatureSlhDsaShake192s ||
  tlsSignatureSlhDsaShake192f => slhDsa192PublicKeyBytes,
  tlsSignatureSlhDsaSha2256s ||
  tlsSignatureSlhDsaSha2256f ||
  tlsSignatureSlhDsaShake256s ||
  tlsSignatureSlhDsaShake256f => slhDsa256PublicKeyBytes,
  _ => -1,
};

/// Scheme this raw key will use. SLH follows [leafScheme]. ML-DSA
/// follows the key length, which is what [encodeCertVerify] already did.
int tlsRawCertificateScheme({
  required int leafScheme,
  required Uint8List publicKey,
}) {
  if (tlsSlhDsaAlgorithm(leafScheme) != null) return leafScheme;
  if (publicKey.length == mlDsa87PublicKeyBytes) return tlsSignatureMldsa87;
  return tlsSignatureMldsa65;
}

Uint8List encodeSlhDsaSpki(Uint8List rawPublicKey, int scheme) {
  final oidLast = tlsSlhDsaOidLast(scheme);
  final expect = tlsSlhDsaPublicKeyBytes(scheme);
  if (oidLast == null || rawPublicKey.length != expect) {
    throw ArgumentError.value(scheme, 'scheme', 'not an SLH-DSA public key');
  }
  const oidHead = [
    0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, //
  ];
  final algorithm = BytesBuilder(copy: false)
    ..addByte(0x30)
    ..addByte(oidHead.length + 1)
    ..add(oidHead)
    ..addByte(oidLast);
  final bitBody = rawPublicKey.length + 1;
  final bitString = BytesBuilder(copy: false)
    ..addByte(0x03)
    ..add(_derLength(bitBody))
    ..addByte(0x00)
    ..add(rawPublicKey);
  final seq = concatBytes([algorithm.takeBytes(), bitString.takeBytes()]);
  final out = BytesBuilder(copy: false)
    ..addByte(0x30)
    ..add(_derLength(seq.length))
    ..add(seq);
  return out.takeBytes();
}

/// ML-DSA or SLH-DSA SubjectPublicKeyInfo. The scheme is the OID.
Result<({Uint8List key, int scheme}), PqTransportError> decodeRawPublicKey(
  Uint8List spki,
) {
  final ml = decodeMlDsa65Spki(spki);
  if (ml.isSuccess) {
    final key = ml.valueOrNull!;
    final scheme = key.length == mlDsa87PublicKeyBytes
        ? tlsSignatureMldsa87
        : tlsSignatureMldsa65;
    return Result.success((key: key, scheme: scheme));
  }
  return _decodeSlhSpki(spki);
}

Result<({Uint8List key, int scheme}), PqTransportError> _decodeSlhSpki(
  Uint8List spki,
) {
  if (spki.isEmpty || spki[0] != 0x30) {
    return Result.failure(PqTransportError.decodeFailure('SLH-DSA SPKI'));
  }
  final r = ByteReader(spki);
  r.u8();
  final seqLen = _readDerLength(r);
  if (seqLen.isFailure) return Result.failure(seqLen.errorOrNull!);
  final seq = r.take(seqLen.valueOrNull!, PqLengthLabel.tlsExtension);
  if (seq.isFailure || !r.isDone) {
    return Result.failure(PqTransportError.decodeFailure('SLH-DSA SPKI'));
  }
  final inner = ByteReader(seq.valueOrNull!);
  final algTag = inner.u8();
  if (algTag.isFailure || algTag.valueOrNull != 0x30) {
    return Result.failure(PqTransportError.decodeFailure('SLH-DSA SPKI'));
  }
  final algLen = _readDerLength(inner);
  if (algLen.isFailure) return Result.failure(algLen.errorOrNull!);
  final alg = inner.take(algLen.valueOrNull!, PqLengthLabel.tlsExtension);
  if (alg.isFailure) return Result.failure(alg.errorOrNull!);
  const oidHead = [0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03];
  final oid = alg.valueOrNull!;
  if (oid.length != oidHead.length + 1) {
    return Result.failure(PqTransportError.decodeFailure('SLH-DSA OID'));
  }
  for (var i = 0; i < oidHead.length; i++) {
    if (oid[i] != oidHead[i]) {
      return Result.failure(PqTransportError.decodeFailure('SLH-DSA OID'));
    }
  }
  final scheme = _schemeForOid(oid.last);
  if (scheme == null) {
    return Result.failure(
      PqTransportError.unsupported('SLH-DSA OID ${oid.last}'),
    );
  }
  final bitTag = inner.u8();
  if (bitTag.isFailure || bitTag.valueOrNull != 0x03) {
    return Result.failure(PqTransportError.decodeFailure('SLH-DSA SPKI'));
  }
  final bitLen = _readDerLength(inner);
  if (bitLen.isFailure) return Result.failure(bitLen.errorOrNull!);
  final unused = inner.u8();
  if (unused.isFailure || unused.valueOrNull != 0) {
    return Result.failure(PqTransportError.decodeFailure('SLH-DSA SPKI'));
  }
  final keyLen = tlsSlhDsaPublicKeyBytes(scheme);
  final key = inner.take(keyLen, PqLengthLabel.tlsExtension);
  if (key.isFailure || !inner.isDone) {
    return Result.failure(PqTransportError.decodeFailure('SLH-DSA SPKI'));
  }
  return Result.success((key: key.valueOrNull!, scheme: scheme));
}

int? _schemeForOid(int last) => switch (last) {
  20 => tlsSignatureSlhDsaSha2128s,
  21 => tlsSignatureSlhDsaSha2128f,
  22 => tlsSignatureSlhDsaSha2192s,
  23 => tlsSignatureSlhDsaSha2192f,
  24 => tlsSignatureSlhDsaSha2256s,
  25 => tlsSignatureSlhDsaSha2256f,
  26 => tlsSignatureSlhDsaShake128s,
  27 => tlsSignatureSlhDsaShake128f,
  28 => tlsSignatureSlhDsaShake192s,
  29 => tlsSignatureSlhDsaShake192f,
  30 => tlsSignatureSlhDsaShake256s,
  31 => tlsSignatureSlhDsaShake256f,
  _ => null,
};

Uint8List encodeRawPublicKeyCertificate(Uint8List publicKey, int scheme) {
  final spki = tlsSlhDsaAlgorithm(scheme) != null
      ? encodeSlhDsaSpki(publicKey, scheme)
      : encodeMlDsa65Spki(publicKey);
  final entry = BytesBuilder(copy: false);
  writeUint24(entry, spki.length);
  entry.add(spki);
  writeUint16(entry, 0);
  final list = entry.takeBytes();
  final body = BytesBuilder(copy: false);
  body.addByte(0);
  writeUint24(body, list.length);
  body.add(list);
  return encodeHandshake(tlsHsCertificate, body.takeBytes());
}

/// RFC 8446 client Certificate with an empty list. No CertificateVerify.
Uint8List encodeEmptyCertificate() {
  final body = BytesBuilder(copy: false);
  body.addByte(0);
  writeUint24(body, 0);
  return encodeHandshake(tlsHsCertificate, body.takeBytes());
}

/// Certificate entries. An empty list is legal for a client that was
/// asked and has nothing to send. A server Certificate still uses
/// [decodeCertificateEntries], which rejects that list.
Result<List<Uint8List>, PqTransportError> decodeCertificateList(
  Uint8List handshake,
) {
  final hs = decodeHandshake(handshake);
  if (hs.isFailure) return Result.failure(hs.errorOrNull!);
  final (type, body) = hs.valueOrNull!;
  if (type != tlsHsCertificate) {
    return Result.failure(
      PqTransportError.unexpectedMessage('expected certificate'),
    );
  }
  final r = ByteReader(body);
  final contextLen = r.u8();
  if (contextLen.isFailure || contextLen.valueOrNull != 0) {
    return Result.failure(
      PqTransportError.decodeFailure('certificate context'),
    );
  }
  final listLen = r.u24();
  if (listLen.isFailure) return Result.failure(listLen.errorOrNull!);
  if (listLen.valueOrNull == 0) {
    if (!r.isDone) {
      return Result.failure(
        PqTransportError.decodeFailure('trailing certificate'),
      );
    }
    return Result.success(const []);
  }
  return decodeCertificateEntries(handshake);
}

/// RFC 8446 §4.4.3 content for a client CertificateVerify.
Uint8List tls13ClientCertVerifyContent(Uint8List transcriptHash) {
  final b = BytesBuilder(copy: false);
  b.add(Uint8List(64)..fillRange(0, 64, 0x20));
  b.add(ascii.encode('TLS 1.3, client CertificateVerify'));
  b.addByte(0);
  b.add(transcriptHash);
  return b.takeBytes();
}

/// Identity answering a CertificateRequest. Raw public key only.
final class TlsClientIdentity {
  TlsClientIdentity({
    required this.publicKey,
    required this.secretKey,
    this.scheme = tlsSignatureMldsa65,
  });

  factory TlsClientIdentity.generate(PqTransportCrypto crypto) {
    final kp = crypto.mlDsaKeyGen();
    return TlsClientIdentity(publicKey: kp.publicKey, secretKey: kp.secretKey);
  }

  /// One of the twelve FIPS 205 sets. Not the ML-DSA default.
  factory TlsClientIdentity.slhDsa(PqSlhDsaAlgorithm algorithm) {
    final kp = PqSlhDsaPrimitives.generateKeyPair(algorithm);
    return TlsClientIdentity(
      publicKey: kp.publicKey,
      secretKey: kp.secretKey,
      scheme: tlsSignatureForSlh(algorithm),
    );
  }

  final Uint8List publicKey;
  final Uint8List secretKey;
  final int scheme;
}

int tlsSignatureForSlh(PqSlhDsaAlgorithm algorithm) => switch (algorithm) {
  PqSlhDsaAlgorithm.sha2128s => tlsSignatureSlhDsaSha2128s,
  PqSlhDsaAlgorithm.sha2128f => tlsSignatureSlhDsaSha2128f,
  PqSlhDsaAlgorithm.sha2192s => tlsSignatureSlhDsaSha2192s,
  PqSlhDsaAlgorithm.sha2192f => tlsSignatureSlhDsaSha2192f,
  PqSlhDsaAlgorithm.sha2256s => tlsSignatureSlhDsaSha2256s,
  PqSlhDsaAlgorithm.sha2256f => tlsSignatureSlhDsaSha2256f,
  PqSlhDsaAlgorithm.shake128s => tlsSignatureSlhDsaShake128s,
  PqSlhDsaAlgorithm.shake128f => tlsSignatureSlhDsaShake128f,
  PqSlhDsaAlgorithm.shake192s => tlsSignatureSlhDsaShake192s,
  PqSlhDsaAlgorithm.shake192f => tlsSignatureSlhDsaShake192f,
  PqSlhDsaAlgorithm.shake256s => tlsSignatureSlhDsaShake256s,
  PqSlhDsaAlgorithm.shake256f => tlsSignatureSlhDsaShake256f,
};

/// Raw public keys the server will accept. The request is not sent
/// on a PSK resume. An empty client Certificate is `certificate_required`.
/// Not X.509. Not WebPKI.
final class TlsClientAuth {
  const TlsClientAuth({
    required this.publicKeys,
    this.schemes = const [tlsSignatureMldsa65, tlsSignatureMldsa87],
  });

  final List<Uint8List> publicKeys;
  final List<int> schemes;
}

Uint8List encodeCertificateRequest(List<int> schemes) {
  final algs = BytesBuilder(copy: false);
  for (final scheme in schemes) {
    writeUint16(algs, scheme);
  }
  final ext = BytesBuilder(copy: false);
  writeUint16(ext, tlsExtSignatureAlgorithms);
  writeOpaque16(ext, _u16Vector(algs.takeBytes()));
  final body = BytesBuilder(copy: false);
  body.addByte(0);
  writeOpaque16(body, ext.takeBytes());
  return encodeHandshake(tlsHsCertificateRequest, body.takeBytes());
}

Uint8List _u16Vector(Uint8List body) {
  final b = BytesBuilder(copy: false);
  writeUint16(b, body.length);
  b.add(body);
  return b.takeBytes();
}

Result<List<int>, PqTransportError> decodeCertificateRequest(
  Uint8List handshake,
) {
  final hs = decodeHandshake(handshake);
  if (hs.isFailure) return Result.failure(hs.errorOrNull!);
  final (type, body) = hs.valueOrNull!;
  if (type != tlsHsCertificateRequest) {
    return Result.failure(
      PqTransportError.unexpectedMessage('expected certificate request'),
    );
  }
  final r = ByteReader(body);
  final contextLen = r.u8();
  if (contextLen.isFailure || contextLen.valueOrNull != 0) {
    return Result.failure(
      PqTransportError.decodeFailure('certificate request context'),
    );
  }
  final extBlock = r.opaque16(PqLengthLabel.tlsExtension);
  if (extBlock.isFailure || !r.isDone) {
    return Result.failure(
      PqTransportError.decodeFailure('certificate request'),
    );
  }
  final exts = _parseExtensions(extBlock.valueOrNull!);
  if (exts == null) {
    return Result.failure(
      PqTransportError.decodeFailure('certificate request'),
    );
  }
  final data = exts[tlsExtSignatureAlgorithms];
  if (data == null) {
    return Result.failure(
      PqTransportError.decodeFailure('missing signature_algorithms'),
    );
  }
  final inner = ByteReader(data);
  final len = inner.u16();
  if (len.isFailure) return Result.failure(len.errorOrNull!);
  final list = inner.take(len.valueOrNull!, PqLengthLabel.tlsExtension);
  if (list.isFailure || !inner.isDone) {
    return Result.failure(
      PqTransportError.decodeFailure('signature_algorithms'),
    );
  }
  final bytes = list.valueOrNull!;
  if (bytes.length < 2 || bytes.length.isOdd) {
    return Result.failure(
      PqTransportError.decodeFailure('signature_algorithms length'),
    );
  }
  final schemes = <int>[];
  for (var i = 0; i < bytes.length; i += 2) {
    schemes.add(readUint16(bytes, i));
  }
  return Result.success(schemes);
}

Map<int, Uint8List>? _parseExtensions(Uint8List block) {
  final out = <int, Uint8List>{};
  final r = ByteReader(block);
  while (!r.isDone) {
    final type = r.u16();
    final data = r.opaque16(PqLengthLabel.tlsExtension);
    if (type.isFailure || data.isFailure) return null;
    if (out.containsKey(type.valueOrNull)) return null;
    out[type.valueOrNull!] = data.valueOrNull!;
  }
  return out;
}

/// RFC 8879 CompressedCertificate around an already-encoded Certificate
/// handshake message. Null when this build has no zlib.
Uint8List? encodeCompressedCertificate(Uint8List certificateMessage) {
  if (!zlibCertificateCompression) return null;
  final compressed = zlibWrapCertificate(certificateMessage);
  if (compressed == null || compressed.isEmpty) return null;
  final body = BytesBuilder(copy: false);
  writeUint16(body, tlsCertCompressZlib);
  writeUint24(body, certificateMessage.length);
  writeUint24(body, compressed.length);
  body.add(compressed);
  return encodeHandshake(tlsHsCompressedCertificate, body.takeBytes());
}

Result<Uint8List, PqTransportError> decodeCompressedCertificate(
  Uint8List handshake,
) {
  final hs = decodeHandshake(handshake);
  if (hs.isFailure) return Result.failure(hs.errorOrNull!);
  final (type, body) = hs.valueOrNull!;
  if (type != tlsHsCompressedCertificate) {
    return Result.failure(
      PqTransportError.unexpectedMessage('expected compressed certificate'),
    );
  }
  final r = ByteReader(body);
  final algorithm = r.u16();
  final uncompressed = r.u24();
  final compressedLen = r.u24();
  if (algorithm.isFailure ||
      uncompressed.isFailure ||
      compressedLen.isFailure) {
    return Result.failure(
      PqTransportError.decodeFailure('compressed certificate'),
    );
  }
  if (algorithm.valueOrNull != tlsCertCompressZlib) {
    return Result.failure(
      PqTransportError.unsupported('certificate compression'),
    );
  }
  final compressed = r.take(
    compressedLen.valueOrNull!,
    PqLengthLabel.tlsExtension,
  );
  if (compressed.isFailure || !r.isDone) {
    return Result.failure(
      PqTransportError.decodeFailure('compressed certificate'),
    );
  }
  final plain = zlibUnwrapCertificate(compressed.valueOrNull!);
  if (plain == null || plain.length != uncompressed.valueOrNull) {
    return Result.failure(
      PqTransportError.decodeFailure('compressed certificate'),
    );
  }
  return Result.success(plain);
}

List<int> parseCompressCertificate(Uint8List? body) {
  if (body == null || body.length < 3) return const [];
  final len = body[0];
  if (len != body.length - 1 || len.isOdd || len < 2) return const [];
  final out = <int>[];
  for (var i = 1; i < body.length; i += 2) {
    out.add(readUint16(body, i));
  }
  return out;
}

Uint8List encodeCompressCertificateExtension(List<int> algorithms) {
  final list = BytesBuilder(copy: false);
  for (final algorithm in algorithms) {
    writeUint16(list, algorithm);
  }
  final packed = list.takeBytes();
  final body = BytesBuilder(copy: false);
  body.addByte(packed.length);
  body.add(packed);
  return _ext(tlsExtCompressCertificate, body.takeBytes());
}

Uint8List _ext(int type, Uint8List data) {
  final b = BytesBuilder(copy: false);
  writeUint16(b, type);
  writeOpaque16(b, data);
  return b.takeBytes();
}

/// Splits a handshake flight so each ciphertext length stays at or
/// below [tlsMaxPlaintextBytes]. QUIC does not use this.
List<Uint8List> protectHandshakeRecords({
  required TlsRecordLayer records,
  required Uint8List trafficSecret,
  required Uint8List iv,
  required Uint8List payload,
}) {
  final out = <Uint8List>[];
  var off = 0;
  if (payload.isEmpty) {
    out.add(
      records.protectWith(
        trafficSecret: trafficSecret,
        iv: iv,
        inner: TlsRecord(type: tlsContentHandshake, payload: payload),
      ),
    );
    return out;
  }
  while (off < payload.length) {
    final room = payload.length - off;
    final n = room > tlsRecordPlaintextLimit ? tlsRecordPlaintextLimit : room;
    out.add(
      records.protectWith(
        trafficSecret: trafficSecret,
        iv: iv,
        inner: TlsRecord(
          type: tlsContentHandshake,
          payload: slice(payload, off, off + n),
        ),
      ),
    );
    off += n;
  }
  return out;
}

Result<int, PqTransportError> _readDerLength(ByteReader r) {
  final first = r.u8();
  if (first.isFailure) return Result.failure(first.errorOrNull!);
  final lead = first.valueOrNull!;
  if (lead < 128) return Result.success(lead);
  final n = lead & 0x7f;
  if (n == 0 || n > 2) {
    return Result.failure(PqTransportError.decodeFailure('DER length'));
  }
  var value = 0;
  for (var i = 0; i < n; i++) {
    final b = r.u8();
    if (b.isFailure) return Result.failure(b.errorOrNull!);
    value = (value << 8) | b.valueOrNull!;
  }
  return Result.success(value);
}

Uint8List _derLength(int length) {
  if (length < 128) return Uint8List.fromList([length]);
  return Uint8List.fromList([(0x80 | 2), (length >> 8) & 0xff, length & 0xff]);
}
