import 'dart:convert';
import 'dart:typed_data';

import 'package:pqforge/pqforge.dart';
import 'package:swissarmyknife/swissarmyknife.dart';

import '../core/bytes.dart';
import '../core/errors.dart';
import '../core/lengths.dart';
import 'handshake.dart';

/// RFC 7468 PEM of an ML-DSA SubjectPublicKeyInfo (RFC 9881).
String encodeMlDsaPublicKeyPem(Uint8List rawPublicKey) =>
    _pem('PUBLIC KEY', encodeMlDsa65Spki(rawPublicKey));

/// RFC 5958 OneAsymmetricKey. The private key is the RFC 9881
/// expandedKey CHOICE, because [PqTlsServerIdentity.generate] does not
/// retain the 32-byte seed.
String encodeMlDsaPrivateKeyPem(Uint8List secretKey) =>
    _pem('PRIVATE KEY', encodeMlDsaPkcs8(secretKey));

/// PKCS#8 wrapping an expanded ML-DSA private key.
Uint8List encodeMlDsaPkcs8(Uint8List secretKey) {
  final oidLast = _oidLast(secretKey.length);
  if (oidLast == null) {
    throw ArgumentError.value(
      secretKey.length,
      'secretKey',
      'not an ML-DSA-65 or ML-DSA-87 private key',
    );
  }
  final oid = BytesBuilder(copy: false)
    ..add(_oidHead)
    ..addByte(oidLast);
  final algorithm = _der(0x30, oid.takeBytes());
  final expanded = _der(0x04, secretKey);
  final privateKey = _der(0x04, expanded);
  final body = BytesBuilder(copy: false)
    ..add(_der(0x02, Uint8List.fromList([0])))
    ..add(algorithm)
    ..add(privateKey);
  return _der(0x30, body.takeBytes());
}

/// Loads an ML-DSA identity from a public key and a private key.
///
/// Each argument is either RFC 7468 PEM or DER. The public key is a
/// SubjectPublicKeyInfo or a raw ML-DSA key. The private key is an
/// RFC 5958 OneAsymmetricKey whose `privateKey` is an RFC 9881
/// ML-DSA-PrivateKey: the 32-byte seed, the expanded key, or both.
/// An encrypted private key is refused. The seed, when present, is
/// expanded and must produce this public key and, if both forms are
/// present, the same expanded key.
Result<({Uint8List publicKey, Uint8List secretKey}), PqTransportError>
decodeMlDsaIdentity(Uint8List publicBytes, Uint8List privateBytes) {
  final public = _publicKey(publicBytes);
  if (public.isFailure) return Result.failure(public.errorOrNull!);
  final secret = _privateKey(privateBytes, public.valueOrNull!);
  if (secret.isFailure) return Result.failure(secret.errorOrNull!);
  return Result.success((
    publicKey: public.valueOrNull!,
    secretKey: secret.valueOrNull!,
  ));
}

/// Same as [decodeMlDsaIdentity] for PEM text.
Result<({Uint8List publicKey, Uint8List secretKey}), PqTransportError>
decodeMlDsaIdentityPem(String publicPem, String privatePem) {
  if (privatePem.contains('ENCRYPTED PRIVATE KEY')) {
    return Result.failure(
      PqTransportError.decodeFailure('encrypted private key'),
    );
  }
  final public = _pemBytes(publicPem, 'PUBLIC KEY');
  if (public.isFailure) return Result.failure(public.errorOrNull!);
  final private = _pemBytes(privatePem, 'PRIVATE KEY');
  if (private.isFailure) return Result.failure(private.errorOrNull!);
  return decodeMlDsaIdentity(public.valueOrNull!, private.valueOrNull!);
}

Result<Uint8List, PqTransportError> _publicKey(Uint8List bytes) {
  if (bytes.length == mlDsa65PublicKeyBytes ||
      bytes.length == mlDsa87PublicKeyBytes) {
    return Result.success(Uint8List.fromList(bytes));
  }
  return decodeMlDsa65Spki(bytes);
}

Result<Uint8List, PqTransportError> _privateKey(
  Uint8List bytes,
  Uint8List publicKey,
) {
  if (bytes.length == mlDsa65SecretKeyBytes ||
      bytes.length == mlDsa87SecretKeyBytes) {
    return _checkExpanded(publicKey, bytes);
  }
  final info = _pkcs8(bytes);
  if (info.isFailure) return Result.failure(info.errorOrNull!);
  final parsed = info.valueOrNull!;
  if (parsed.publicKey != null &&
      !PqBytes.constantTimeEquals(parsed.publicKey!, publicKey)) {
    return Result.failure(
      PqTransportError.decodeFailure('PKCS#8 public key mismatch'),
    );
  }
  if (parsed.seed != null) {
    final derived = PqSignaturePrimitives.generateKeyPairSeeded(
      parsed.algorithm,
      parsed.seed!,
    );
    if (!PqBytes.constantTimeEquals(derived.publicKey, publicKey)) {
      return Result.failure(
        PqTransportError.decodeFailure('ML-DSA seed does not match public key'),
      );
    }
    if (parsed.expanded != null &&
        !PqBytes.constantTimeEquals(derived.secretKey, parsed.expanded!)) {
      return Result.failure(
        PqTransportError.decodeFailure('ML-DSA seed and expanded key disagree'),
      );
    }
    return Result.success(derived.secretKey);
  }
  final expanded = parsed.expanded;
  if (expanded == null) {
    return Result.failure(PqTransportError.decodeFailure('empty ML-DSA key'));
  }
  return _checkExpanded(publicKey, expanded);
}

Result<Uint8List, PqTransportError> _checkExpanded(
  Uint8List publicKey,
  Uint8List secretKey,
) {
  final algorithm = _algorithmFor(publicKey.length, secretKey.length);
  if (algorithm == null) {
    return Result.failure(
      PqTransportError.decodeFailure('ML-DSA key length mismatch'),
    );
  }
  const message = [
    0x70,
    0x71,
    0x74,
    0x72,
    0x61,
    0x6e,
    0x73,
    0x70,
    0x6f,
    0x72,
    0x74,
  ];
  try {
    final sig = PqSignaturePrimitives.sign(
      algorithm,
      secretKey,
      Uint8List.fromList(message),
    );
    final ok = PqSignaturePrimitives.verify(
      algorithm,
      publicKey,
      Uint8List.fromList(message),
      sig,
    );
    if (!ok) {
      return Result.failure(
        PqTransportError.decodeFailure('ML-DSA private key does not match'),
      );
    }
  } on Object {
    return Result.failure(
      PqTransportError.decodeFailure('ML-DSA private key does not match'),
    );
  }
  return Result.success(Uint8List.fromList(secretKey));
}

final class _Pkcs8 {
  _Pkcs8(this.algorithm, this.seed, this.expanded, this.publicKey);

  final PqSignatureAlgorithm algorithm;
  final Uint8List? seed;
  final Uint8List? expanded;
  final Uint8List? publicKey;
}

Result<_Pkcs8, PqTransportError> _pkcs8(Uint8List der) {
  final outer = _tlv(ByteReader(der));
  if (outer.isFailure) return Result.failure(outer.errorOrNull!);
  final (tag, body) = outer.valueOrNull!;
  if (tag != 0x30) {
    return Result.failure(PqTransportError.decodeFailure('PKCS#8'));
  }
  final r = ByteReader(body);
  final versionT = _tlv(r);
  if (versionT.isFailure) return Result.failure(versionT.errorOrNull!);
  if (versionT.valueOrNull!.$1 != 0x02 ||
      versionT.valueOrNull!.$2.length != 1 ||
      versionT.valueOrNull!.$2[0] > 1) {
    return Result.failure(PqTransportError.decodeFailure('PKCS#8 version'));
  }
  final version = versionT.valueOrNull!.$2[0];
  final algT = _tlv(r);
  if (algT.isFailure) return Result.failure(algT.errorOrNull!);
  if (algT.valueOrNull!.$1 != 0x30) {
    return Result.failure(PqTransportError.decodeFailure('PKCS#8 algorithm'));
  }
  final algorithm = _algorithmOid(algT.valueOrNull!.$2);
  if (algorithm == null) {
    return Result.failure(PqTransportError.unsupported('ML-DSA OID'));
  }
  final keyT = _tlv(r);
  if (keyT.isFailure) return Result.failure(keyT.errorOrNull!);
  if (keyT.valueOrNull!.$1 != 0x04) {
    return Result.failure(PqTransportError.decodeFailure('PKCS#8 privateKey'));
  }
  final choice = _choice(keyT.valueOrNull!.$2, algorithm);
  if (choice.isFailure) return Result.failure(choice.errorOrNull!);
  Uint8List? embedded;
  if (r.remaining > 0) {
    if (version == 0) {
      return Result.failure(PqTransportError.decodeFailure('PKCS#8 trailing'));
    }
    final extra = _tlv(r);
    if (extra.isFailure) return Result.failure(extra.errorOrNull!);
    final (extraTag, extraBody) = extra.valueOrNull!;
    if (extraTag == 0xA0) {
      if (r.remaining == 0) {
        return Result.success(
          _Pkcs8(
            algorithm,
            choice.valueOrNull!.$1,
            choice.valueOrNull!.$2,
            null,
          ),
        );
      }
      final pub = _tlv(r);
      if (pub.isFailure) return Result.failure(pub.errorOrNull!);
      if (pub.valueOrNull!.$1 != 0xA1) {
        return Result.failure(PqTransportError.decodeFailure('PKCS#8 public'));
      }
      embedded = _bitStringKey(pub.valueOrNull!.$2);
    } else if (extraTag == 0xA1) {
      embedded = _bitStringKey(extraBody);
    } else {
      return Result.failure(PqTransportError.decodeFailure('PKCS#8 trailing'));
    }
    if (embedded == null) {
      return Result.failure(PqTransportError.decodeFailure('PKCS#8 public'));
    }
    if (!r.isDone) {
      return Result.failure(PqTransportError.decodeFailure('PKCS#8 trailing'));
    }
  }
  return Result.success(
    _Pkcs8(algorithm, choice.valueOrNull!.$1, choice.valueOrNull!.$2, embedded),
  );
}

Uint8List? _bitStringKey(Uint8List body) {
  if (body.isEmpty || body[0] != 0) return null;
  return slice(body, 1, body.length);
}

Result<(Uint8List?, Uint8List?), PqTransportError> _choice(
  Uint8List choice,
  PqSignatureAlgorithm algorithm,
) {
  final r = ByteReader(choice);
  final first = _tlv(r);
  if (first.isFailure) return Result.failure(first.errorOrNull!);
  final (tag, body) = first.valueOrNull!;
  if (tag == 0x04 && r.isDone) {
    if (body.length == mlDsaSeedBytes) {
      return Result.success((body, null));
    }
    if (body.length == algorithm.secretKeyBytes) {
      return Result.success((null, body));
    }
    return Result.failure(
      PqTransportError.decodeFailure('ML-DSA private key length'),
    );
  }
  if (tag != 0x30 || !r.isDone) {
    return Result.failure(PqTransportError.decodeFailure('ML-DSA private key'));
  }
  final inner = ByteReader(body);
  final seedT = _tlv(inner);
  if (seedT.isFailure) return Result.failure(seedT.errorOrNull!);
  final expandedT = _tlv(inner);
  if (expandedT.isFailure) return Result.failure(expandedT.errorOrNull!);
  if (!inner.isDone ||
      seedT.valueOrNull!.$1 != 0x04 ||
      expandedT.valueOrNull!.$1 != 0x04 ||
      seedT.valueOrNull!.$2.length != mlDsaSeedBytes ||
      expandedT.valueOrNull!.$2.length != algorithm.secretKeyBytes) {
    return Result.failure(PqTransportError.decodeFailure('ML-DSA both choice'));
  }
  return Result.success((seedT.valueOrNull!.$2, expandedT.valueOrNull!.$2));
}

PqSignatureAlgorithm? _algorithmOid(Uint8List algorithm) {
  if (algorithm.length != _oidHead.length + 1) return null;
  for (var i = 0; i < _oidHead.length; i++) {
    if (algorithm[i] != _oidHead[i]) return null;
  }
  return switch (algorithm.last) {
    0x12 => PqSignatureAlgorithm.mlDsa65,
    0x13 => PqSignatureAlgorithm.mlDsa87,
    _ => null,
  };
}

PqSignatureAlgorithm? _algorithmFor(int publicLength, int secretLength) {
  if (publicLength == mlDsa65PublicKeyBytes &&
      secretLength == mlDsa65SecretKeyBytes) {
    return PqSignatureAlgorithm.mlDsa65;
  }
  if (publicLength == mlDsa87PublicKeyBytes &&
      secretLength == mlDsa87SecretKeyBytes) {
    return PqSignatureAlgorithm.mlDsa87;
  }
  return null;
}

int? _oidLast(int secretLength) => switch (secretLength) {
  mlDsa65SecretKeyBytes => 0x12,
  mlDsa87SecretKeyBytes => 0x13,
  _ => null,
};

const List<int> _oidHead = [
  0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, //
];

Result<(int, Uint8List), PqTransportError> _tlv(ByteReader r) {
  final tag = r.u8();
  if (tag.isFailure) return Result.failure(tag.errorOrNull!);
  final first = r.u8();
  if (first.isFailure) return Result.failure(first.errorOrNull!);
  final lead = first.valueOrNull!;
  var length = lead;
  if (lead >= 0x80) {
    final n = lead & 0x7f;
    if (n == 0 || n > 3) {
      return Result.failure(PqTransportError.decodeFailure('DER length'));
    }
    length = 0;
    for (var i = 0; i < n; i++) {
      final b = r.u8();
      if (b.isFailure) return Result.failure(b.errorOrNull!);
      length = (length << 8) | b.valueOrNull!;
    }
  }
  final value = r.take(length, PqLengthLabel.tlsExtension);
  if (value.isFailure) return Result.failure(value.errorOrNull!);
  return Result.success((tag.valueOrNull!, value.valueOrNull!));
}

Uint8List _der(int tag, Uint8List body) {
  final b = BytesBuilder(copy: false)
    ..addByte(tag)
    ..add(_derLength(body.length))
    ..add(body);
  return b.takeBytes();
}

Uint8List _derLength(int length) {
  if (length < 0x80) return Uint8List.fromList([length]);
  if (length <= 0xff) return Uint8List.fromList([0x81, length]);
  if (length <= 0xffff) {
    return Uint8List.fromList([0x82, (length >> 8) & 0xff, length & 0xff]);
  }
  return Uint8List.fromList([
    0x83,
    (length >> 16) & 0xff,
    (length >> 8) & 0xff,
    length & 0xff,
  ]);
}

String _pem(String label, Uint8List der) {
  final raw = base64.encode(der);
  final lines = StringBuffer('-----BEGIN $label-----\n');
  for (var i = 0; i < raw.length; i += 64) {
    final end = i + 64 > raw.length ? raw.length : i + 64;
    lines.writeln(raw.substring(i, end));
  }
  lines.write('-----END $label-----\n');
  return lines.toString();
}

Result<Uint8List, PqTransportError> _pemBytes(String text, String label) {
  final begin = '-----BEGIN $label-----';
  final end = '-----END $label-----';
  final start = text.indexOf(begin);
  final stop = text.indexOf(end);
  if (start < 0 || stop < start) {
    return Result.failure(PqTransportError.decodeFailure('PEM $label'));
  }
  final body = text
      .substring(start + begin.length, stop)
      .replaceAll(RegExp(r'\s'), '');
  try {
    return Result.success(Uint8List.fromList(base64.decode(body)));
  } on FormatException {
    return Result.failure(PqTransportError.decodeFailure('PEM $label'));
  }
}
