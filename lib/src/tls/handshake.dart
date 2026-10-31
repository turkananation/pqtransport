import 'dart:convert';
import 'dart:typed_data';

import 'package:swissarmyknife/swissarmyknife.dart';

import '../core/bytes.dart';
import '../core/errors.dart';
import '../core/hybrid.dart';
import '../core/lengths.dart';
import '../core/transcript.dart';
import 'cipher_suite.dart';
import 'record.dart';

/// RFC 7250 certificate type. [x509] is value 0. [rawPublicKey] is value 2.
enum TlsCertificateType {
  x509(tlsCertTypeX509),
  rawPublicKey(tlsCertTypeRawPublicKey);

  const TlsCertificateType(this.wire);

  final int wire;

  static TlsCertificateType? fromWire(int wire) => switch (wire) {
    tlsCertTypeX509 => TlsCertificateType.x509,
    tlsCertTypeRawPublicKey => TlsCertificateType.rawPublicKey,
    _ => null,
  };
}

/// RFC 8446 ClientHello. Compact 0.1 body (random || group || share) is retired.
final class ClientHello {
  const ClientHello({
    required this.random,
    required this.group,
    required this.share,
    this.legacySessionId = const [],
    this.cipherSuites = tlsDefaultOfferedCipherSuites,
    this.serverName = 'localhost',
    this.alpnProtocols = const [httpAlpnH1],
    this.supportedGroups,
    this.cookie,
    this.certificateTypes = const [TlsCertificateType.rawPublicKey],
    this.signatureSchemes = const [tlsSignatureMldsa65, tlsSignatureMldsa87],
  });

  final Uint8List random;
  final HybridGroup group;
  final Uint8List share;
  final List<int> legacySessionId;
  final List<int> cipherSuites;
  final String serverName;
  final List<String> alpnProtocols;

  /// Named-group codepoints in `supported_groups`. Null means `[group]`.
  final List<int>? supportedGroups;
  final Uint8List? cookie;

  /// What this hello offers. `[rawPublicKey]` is the default and sends the
  /// extension. `[x509]` omits the extension, which is the RFC 7250 default.
  /// Null, on a decoded hello, means the peer omitted the extension.
  final List<TlsCertificateType>? certificateTypes;

  final List<int> signatureSchemes;

  List<int> get offeredGroupCodepoints => supportedGroups ?? [group.codepoint];

  bool get offersX509 =>
      certificateTypes == null ||
      certificateTypes!.contains(TlsCertificateType.x509);

  bool get offersRawPublicKey =>
      certificateTypes != null &&
      certificateTypes!.contains(TlsCertificateType.rawPublicKey);

  Uint8List encode() {
    final b = BytesBuilder(copy: false);
    writeUint16(b, tlsLegacyVersion);
    b.add(random);
    writeOpaque8(b, Uint8List.fromList(legacySessionId));
    final suites = BytesBuilder(copy: false);
    for (final c in cipherSuites) {
      writeUint16(suites, c);
    }
    writeOpaque16(b, suites.takeBytes());
    writeOpaque8(b, Uint8List.fromList([tlsCompressionNull]));
    writeOpaque16(b, _clientExtensions());
    return encodeHandshake(tlsHsClientHello, b.takeBytes());
  }

  Uint8List _clientExtensions() {
    final b = BytesBuilder(copy: false);
    b.add(_extSupportedVersionsClient());
    if (serverName.isNotEmpty) {
      b.add(_extServerName(serverName));
    }
    b.add(_extSupportedGroups(offeredGroupCodepoints));
    b.add(_extSignatureAlgorithms(signatureSchemes));
    if (alpnProtocols.isNotEmpty) {
      b.add(_extAlpn(alpnProtocols));
    }
    final types = certificateTypes;
    if (types != null &&
        !(types.length == 1 && types.single == TlsCertificateType.x509)) {
      b.add(_extCertificateTypeOffer(types));
    }
    final c = cookie;
    if (c != null) {
      b.add(_extCookie(c));
    }
    b.add(_extKeyShareClient(group, share));
    return b.takeBytes();
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
    final ver = r.u16();
    if (ver.isFailure) return Result.failure(ver.errorOrNull!);
    if (ver.valueOrNull! != tlsLegacyVersion) {
      return Result.failure(
        PqTransportError.decodeFailure(
          'compact 0.1 ClientHello retired; expected legacy_version 0x0303',
        ),
      );
    }
    final random = r.take(handshakeRandomBytes, PqLengthLabel.handshakeRandom);
    if (random.isFailure) return Result.failure(random.errorOrNull!);
    final sid = r.opaque8(PqLengthLabel.tlsSessionId);
    if (sid.isFailure) return Result.failure(sid.errorOrNull!);
    if (sid.valueOrNull!.length > tlsLegacySessionIdMaxBytes) {
      return Result.failure(
        PqTransportError.illegalParameter(
          PqLengthLabel.tlsSessionId,
          sid.valueOrNull!.length,
          tlsLegacySessionIdMaxBytes,
        ),
      );
    }
    final suiteBytes = r.opaque16(PqLengthLabel.tlsCipherSuite);
    if (suiteBytes.isFailure) return Result.failure(suiteBytes.errorOrNull!);
    final suites = _parseCipherSuites(suiteBytes.valueOrNull!);
    if (suites.isFailure) return Result.failure(suites.errorOrNull!);
    final usable = _requireUsableCiphers(suites.valueOrNull!);
    if (usable.isFailure) return Result.failure(usable.errorOrNull!);
    final comp = r.opaque8(PqLengthLabel.tlsHello);
    if (comp.isFailure) return Result.failure(comp.errorOrNull!);
    if (!comp.valueOrNull!.contains(tlsCompressionNull)) {
      return Result.failure(
        PqTransportError.illegalParameter(PqLengthLabel.tlsHello, 0, 1),
      );
    }
    final extBlock = r.opaque16(PqLengthLabel.tlsExtension);
    if (extBlock.isFailure) return Result.failure(extBlock.errorOrNull!);
    if (!r.isDone) {
      return Result.failure(
        PqTransportError.decodeFailure('trailing ClientHello bytes'),
      );
    }
    final exts = _parseExtensions(extBlock.valueOrNull!);
    if (exts.isFailure) return Result.failure(exts.errorOrNull!);
    final map = exts.valueOrNull!;
    final versions = _parseSupportedVersionsClient(map);
    if (versions.isFailure) return Result.failure(versions.errorOrNull!);
    if (!versions.valueOrNull!.contains(tls13Version)) {
      return Result.failure(
        PqTransportError.unsupported('supported_versions missing TLS 1.3'),
      );
    }
    final groups = _parseSupportedGroups(map);
    if (groups.isFailure) return Result.failure(groups.errorOrNull!);
    final sigs = _parseSignatureAlgorithms(map);
    if (sigs.isFailure) return Result.failure(sigs.errorOrNull!);
    final share = _parseKeyShareClient(map);
    if (share.isFailure) return Result.failure(share.errorOrNull!);
    final (group, keyShare) = share.valueOrNull!;
    if (!groups.valueOrNull!.contains(group.codepoint)) {
      return Result.failure(
        PqTransportError.illegalParameter(PqLengthLabel.tlsKeyShare, 0, 1),
      );
    }
    final decoded = decodeClientShare(group, keyShare);
    if (decoded.isFailure) return Result.failure(decoded.errorOrNull!);
    final sni = _parseServerName(map);
    if (sni.isFailure) return Result.failure(sni.errorOrNull!);
    final alpn = _parseAlpn(map);
    if (alpn.isFailure) return Result.failure(alpn.errorOrNull!);
    final rawPk = _parseCertificateTypeOffer(map, tlsExtServerCertificateType);
    if (rawPk.isFailure) return Result.failure(rawPk.errorOrNull!);
    final cookie = _parseCookie(map);
    if (cookie.isFailure) return Result.failure(cookie.errorOrNull!);
    return Result.success(
      ClientHello(
        random: random.valueOrNull!,
        group: group,
        share: keyShare,
        legacySessionId: sid.valueOrNull!,
        cipherSuites: suites.valueOrNull!,
        serverName: sni.valueOrNull ?? '',
        alpnProtocols: alpn.valueOrNull ?? const [],
        supportedGroups: groups.valueOrNull!,
        cookie: cookie.valueOrNull,
        certificateTypes: rawPk.valueOrNull,
        signatureSchemes: sigs.valueOrNull!,
      ),
    );
  }
}

/// RFC 8446 ServerHello. Compact 0.1 body is retired.
///
/// A HelloRetryRequest is a ServerHello whose [random] is
/// [tlsHelloRetryRequestRandom] (OPEN-05). HRR [share] is empty; [group] is
/// the selected_group and [cookie] is required.
final class ServerHello {
  const ServerHello({
    required this.random,
    required this.group,
    required this.share,
    this.legacySessionId = const [],
    this.cipherSuite = tlsCipherAes256GcmSha384,
    this.cookie,
  });

  factory ServerHello.helloRetryRequest({
    required HybridGroup selectedGroup,
    required Uint8List cookie,
    List<int> legacySessionId = const [],
    int cipherSuite = tlsCipherAes256GcmSha384,
  }) => ServerHello(
    random: Uint8List.fromList(tlsHelloRetryRequestRandom),
    group: selectedGroup,
    share: Uint8List(0),
    legacySessionId: legacySessionId,
    cipherSuite: cipherSuite,
    cookie: cookie,
  );

  final Uint8List random;
  final HybridGroup group;
  final Uint8List share;
  final List<int> legacySessionId;
  final int cipherSuite;
  final Uint8List? cookie;

  bool get isHelloRetryRequest => isHelloRetryRequestRandom(random);

  Uint8List encode() {
    final b = BytesBuilder(copy: false);
    writeUint16(b, tlsLegacyVersion);
    b.add(random);
    writeOpaque8(b, Uint8List.fromList(legacySessionId));
    writeUint16(b, cipherSuite);
    b.addByte(tlsCompressionNull);
    final exts = BytesBuilder(copy: false);
    exts.add(_extSupportedVersionsServer());
    if (isHelloRetryRequest) {
      exts.add(_extKeyShareHelloRetry(group));
      final c = cookie;
      if (c != null) {
        exts.add(_extCookie(c));
      }
    } else {
      exts.add(_extKeyShareServer(group, share));
    }
    writeOpaque16(b, exts.takeBytes());
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
    final ver = r.u16();
    if (ver.isFailure) return Result.failure(ver.errorOrNull!);
    if (ver.valueOrNull! != tlsLegacyVersion) {
      return Result.failure(
        PqTransportError.decodeFailure(
          'compact 0.1 ServerHello retired; expected legacy_version 0x0303',
        ),
      );
    }
    final random = r.take(handshakeRandomBytes, PqLengthLabel.handshakeRandom);
    if (random.isFailure) return Result.failure(random.errorOrNull!);
    final sid = r.opaque8(PqLengthLabel.tlsSessionId);
    if (sid.isFailure) return Result.failure(sid.errorOrNull!);
    final suite = r.u16();
    if (suite.isFailure) return Result.failure(suite.errorOrNull!);
    final selectedSuite = TlsCipherSuite.byCodepoint(suite.valueOrNull!);
    if (selectedSuite == null) {
      if (suite.valueOrNull! == tlsCipherAes256GcmSha256Private) {
        return Result.failure(
          PqTransportError.unsupported(
            'retired private-use 0xFF00; IANA 0x1302 or 0x1303 required',
          ),
        );
      }
      return Result.failure(
        PqTransportError.handshakeFailure('unexpected cipher suite'),
      );
    }
    final comp = r.u8();
    if (comp.isFailure) return Result.failure(comp.errorOrNull!);
    if (comp.valueOrNull! != tlsCompressionNull) {
      return Result.failure(
        PqTransportError.illegalParameter(PqLengthLabel.tlsHello, 0, 1),
      );
    }
    final extBlock = r.opaque16(PqLengthLabel.tlsExtension);
    if (extBlock.isFailure) return Result.failure(extBlock.errorOrNull!);
    if (!r.isDone) {
      return Result.failure(
        PqTransportError.decodeFailure('trailing ServerHello bytes'),
      );
    }
    final exts = _parseExtensions(extBlock.valueOrNull!);
    if (exts.isFailure) return Result.failure(exts.errorOrNull!);
    final map = exts.valueOrNull!;
    final selected = _parseSupportedVersionsServer(map);
    if (selected.isFailure) return Result.failure(selected.errorOrNull!);
    if (selected.valueOrNull! != tls13Version) {
      return Result.failure(
        PqTransportError.unsupported('ServerHello is not TLS 1.3'),
      );
    }
    final hrr = isHelloRetryRequestRandom(random.valueOrNull!);
    if (hrr) {
      final selectedGroup = _parseKeyShareHelloRetry(map);
      if (selectedGroup.isFailure) {
        return Result.failure(selectedGroup.errorOrNull!);
      }
      final cookie = _parseCookie(map);
      if (cookie.isFailure) return Result.failure(cookie.errorOrNull!);
      if (cookie.valueOrNull == null) {
        return Result.failure(
          PqTransportError.decodeFailure('HRR missing cookie (OPEN-05)'),
        );
      }
      return Result.success(
        ServerHello(
          random: random.valueOrNull!,
          group: selectedGroup.valueOrNull!,
          share: Uint8List(0),
          legacySessionId: sid.valueOrNull!,
          cipherSuite: suite.valueOrNull!,
          cookie: cookie.valueOrNull,
        ),
      );
    }
    if (map.containsKey(tlsExtCookie)) {
      return Result.failure(
        PqTransportError.decodeFailure('cookie in ServerHello'),
      );
    }
    final share = _parseKeyShareServer(map);
    if (share.isFailure) return Result.failure(share.errorOrNull!);
    final (group, keyShare) = share.valueOrNull!;
    final decoded = decodeServerShare(group, keyShare);
    if (decoded.isFailure) return Result.failure(decoded.errorOrNull!);
    return Result.success(
      ServerHello(
        random: random.valueOrNull!,
        group: group,
        share: keyShare,
        legacySessionId: sid.valueOrNull!,
        cipherSuite: suite.valueOrNull!,
      ),
    );
  }
}

Uint8List encodeMlDsa65Spki(Uint8List rawPublicKey) {
  final oidLast = switch (rawPublicKey.length) {
    mlDsa65PublicKeyBytes => 0x12,
    mlDsa87PublicKeyBytes => 0x13,
    _ => null,
  };
  if (oidLast == null) {
    throw ArgumentError.value(
      rawPublicKey.length,
      'rawPublicKey',
      'not an ML-DSA-65 or ML-DSA-87 public key',
    );
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

Result<Uint8List, PqTransportError> decodeMlDsa65Spki(Uint8List spki) {
  if (spki.isEmpty || spki[0] != 0x30) {
    return Result.failure(PqTransportError.decodeFailure('ML-DSA SPKI'));
  }
  final r = ByteReader(spki);
  r.u8();
  final seqLen = _readDerLength(r);
  if (seqLen.isFailure) return Result.failure(seqLen.errorOrNull!);
  final seq = r.take(seqLen.valueOrNull!, PqLengthLabel.mlDsa65PublicKey);
  if (seq.isFailure) return Result.failure(seq.errorOrNull!);
  if (!r.isDone) {
    return Result.failure(PqTransportError.decodeFailure('trailing SPKI'));
  }
  final inner = ByteReader(seq.valueOrNull!);
  final algTag = inner.u8();
  if (algTag.isFailure || algTag.valueOrNull != 0x30) {
    return Result.failure(PqTransportError.decodeFailure('ML-DSA SPKI alg'));
  }
  final algLen = _readDerLength(inner);
  if (algLen.isFailure) return Result.failure(algLen.errorOrNull!);
  final alg = inner.take(algLen.valueOrNull!, PqLengthLabel.tlsExtension);
  if (alg.isFailure) return Result.failure(alg.errorOrNull!);
  const oidHead = [0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03];
  final oid = alg.valueOrNull!;
  if (oid.length != oidHead.length + 1) {
    return Result.failure(PqTransportError.decodeFailure('ML-DSA OID'));
  }
  for (var i = 0; i < oidHead.length; i++) {
    if (oid[i] != oidHead[i]) {
      return Result.failure(PqTransportError.decodeFailure('ML-DSA OID'));
    }
  }
  final expectKey = switch (oid.last) {
    0x12 => mlDsa65PublicKeyBytes,
    0x13 => mlDsa87PublicKeyBytes,
    _ => -1,
  };
  if (expectKey < 0) {
    return Result.failure(
      PqTransportError.unsupported('ML-DSA OID ${oid.last}'),
    );
  }
  final bitTag = inner.u8();
  if (bitTag.isFailure || bitTag.valueOrNull != 0x03) {
    return Result.failure(PqTransportError.decodeFailure('ML-DSA bit string'));
  }
  final bitLen = _readDerLength(inner);
  if (bitLen.isFailure) return Result.failure(bitLen.errorOrNull!);
  final bits = inner.take(bitLen.valueOrNull!, PqLengthLabel.mlDsa65PublicKey);
  if (bits.isFailure) return Result.failure(bits.errorOrNull!);
  if (!inner.isDone) {
    return Result.failure(PqTransportError.decodeFailure('trailing SPKI'));
  }
  final raw = bits.valueOrNull!;
  if (raw.isEmpty || raw[0] != 0 || raw.length != expectKey + 1) {
    return Result.failure(
      PqTransportError.illegalParameter(
        PqLengthLabel.mlDsa65PublicKey,
        raw.isEmpty ? 0 : raw.length - 1,
        expectKey,
      ),
    );
  }
  return Result.success(slice(raw, 1, raw.length));
}

Result<int, PqTransportError> _readDerLength(ByteReader r) {
  final first = r.u8();
  if (first.isFailure) return Result.failure(first.errorOrNull!);
  final lead = first.valueOrNull!;
  if (lead < 0x80) return Result.success(lead);
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

Uint8List encodeCertificate(Uint8List mlDsaPublicKey) {
  final spki = encodeMlDsa65Spki(mlDsaPublicKey);
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

/// RFC 8446 Certificate carrying one or more DER certificates, leaf first.
Uint8List encodeX509Certificate(List<Uint8List> ders) {
  if (ders.isEmpty || ders.length > tlsCertificateListMax) {
    throw ArgumentError.value(ders.length, 'ders', 'expected 1..8');
  }
  final list = BytesBuilder(copy: false);
  for (final der in ders) {
    writeUint24(list, der.length);
    list.add(der);
    writeUint16(list, 0);
  }
  final packed = list.takeBytes();
  final body = BytesBuilder(copy: false);
  body.addByte(0);
  writeUint24(body, packed.length);
  body.add(packed);
  return encodeHandshake(tlsHsCertificate, body.takeBytes());
}

/// Certificate entry payloads, in order. Extensions are parsed and ignored.
Result<List<Uint8List>, PqTransportError> decodeCertificateEntries(
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
  if (contextLen.isFailure) return Result.failure(contextLen.errorOrNull!);
  if (contextLen.valueOrNull != 0) {
    return Result.failure(
      PqTransportError.decodeFailure('server certificate context'),
    );
  }
  final listLen = r.u24();
  if (listLen.isFailure) return Result.failure(listLen.errorOrNull!);
  final list = r.take(listLen.valueOrNull!, PqLengthLabel.tlsExtension);
  if (list.isFailure) return Result.failure(list.errorOrNull!);
  if (!r.isDone) {
    return Result.failure(
      PqTransportError.decodeFailure('trailing certificate'),
    );
  }
  final entry = ByteReader(list.valueOrNull!);
  final out = <Uint8List>[];
  while (!entry.isDone) {
    if (out.length == tlsCertificateListMax) {
      return Result.failure(
        PqTransportError.unsupportedCertificate('certificate list'),
      );
    }
    final certLen = entry.u24();
    if (certLen.isFailure) return Result.failure(certLen.errorOrNull!);
    if (certLen.valueOrNull == 0) {
      return Result.failure(PqTransportError.decodeFailure('empty cert_data'));
    }
    final cert = entry.take(certLen.valueOrNull!, PqLengthLabel.tlsExtension);
    if (cert.isFailure) return Result.failure(cert.errorOrNull!);
    final extLen = entry.u16();
    if (extLen.isFailure) return Result.failure(extLen.errorOrNull!);
    final exts = entry.take(extLen.valueOrNull!, PqLengthLabel.tlsExtension);
    if (exts.isFailure) return Result.failure(exts.errorOrNull!);
    out.add(cert.valueOrNull!);
  }
  if (out.isEmpty) {
    return Result.failure(
      PqTransportError.decodeFailure('empty certificate_list'),
    );
  }
  return Result.success(out);
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
  final contextLen = r.u8();
  if (contextLen.isFailure) return Result.failure(contextLen.errorOrNull!);
  if (contextLen.valueOrNull != 0) {
    return Result.failure(
      PqTransportError.decodeFailure('server certificate context'),
    );
  }
  final listLen = r.u24();
  if (listLen.isFailure) return Result.failure(listLen.errorOrNull!);
  final list = r.take(listLen.valueOrNull!, PqLengthLabel.tlsExtension);
  if (list.isFailure) return Result.failure(list.errorOrNull!);
  if (!r.isDone) {
    return Result.failure(
      PqTransportError.decodeFailure('trailing certificate'),
    );
  }
  final entry = ByteReader(list.valueOrNull!);
  final spkiLen = entry.u24();
  if (spkiLen.isFailure) return Result.failure(spkiLen.errorOrNull!);
  final spki = entry.take(spkiLen.valueOrNull!, PqLengthLabel.mlDsa65PublicKey);
  if (spki.isFailure) return Result.failure(spki.errorOrNull!);
  final extLen = entry.u16();
  if (extLen.isFailure) return Result.failure(extLen.errorOrNull!);
  final exts = entry.take(extLen.valueOrNull!, PqLengthLabel.tlsExtension);
  if (exts.isFailure) return Result.failure(exts.errorOrNull!);
  if (!entry.isDone) {
    return Result.failure(
      PqTransportError.decodeFailure('trailing certificate entry'),
    );
  }
  return decodeMlDsa65Spki(spki.valueOrNull!);
}

/// RFC 8446 §4.4.3 content for a server CertificateVerify.
///
/// 64 bytes of 0x20, the context string, a 0 separator, then the
/// transcript hash. ML-DSA signs this message with an empty context.
Uint8List tls13ServerCertVerifyContent(Uint8List transcriptHash) {
  final b = BytesBuilder(copy: false);
  b.add(Uint8List(64)..fillRange(0, 64, 0x20));
  b.add(ascii.encode('TLS 1.3, server CertificateVerify'));
  b.addByte(0);
  b.add(transcriptHash);
  return b.takeBytes();
}

final class TlsCertificateVerify {
  const TlsCertificateVerify(this.scheme, this.signature);

  final int scheme;
  final Uint8List signature;
}

Uint8List encodeCertVerify(Uint8List signature) {
  final scheme = switch (signature.length) {
    mlDsa65SignatureBytes => tlsSignatureMldsa65,
    mlDsa87SignatureBytes => tlsSignatureMldsa87,
    _ => null,
  };
  if (scheme == null) {
    throw ArgumentError.value(
      signature.length,
      'signature',
      'not an ML-DSA-65 or ML-DSA-87 signature',
    );
  }
  return encodeCertVerifyScheme(scheme, signature);
}

Uint8List encodeCertVerifyScheme(int scheme, Uint8List signature) {
  final b = BytesBuilder(copy: false);
  writeUint16(b, scheme);
  writeUint16(b, signature.length);
  b.add(signature);
  return encodeHandshake(tlsHsCertificateVerify, b.takeBytes());
}

Result<TlsCertificateVerify, PqTransportError> decodeCertVerify(
  Uint8List handshake,
) {
  final hs = decodeHandshake(handshake);
  if (hs.isFailure) return Result.failure(hs.errorOrNull!);
  final (type, body) = hs.valueOrNull!;
  if (type != tlsHsCertificateVerify) {
    return Result.failure(
      PqTransportError.unexpectedMessage('expected certificate verify'),
    );
  }
  final r = ByteReader(body);
  final scheme = r.u16();
  if (scheme.isFailure) return Result.failure(scheme.errorOrNull!);
  final len = r.u16();
  if (len.isFailure) return Result.failure(len.errorOrNull!);
  if (len.valueOrNull == 0) {
    return Result.failure(
      PqTransportError.decodeFailure('empty certificate verify'),
    );
  }
  final sig = r.take(len.valueOrNull!, PqLengthLabel.mlDsa65Signature);
  if (sig.isFailure) return Result.failure(sig.errorOrNull!);
  if (!r.isDone) {
    return Result.failure(
      PqTransportError.decodeFailure('trailing certificate verify'),
    );
  }
  return Result.success(
    TlsCertificateVerify(scheme.valueOrNull!, sig.valueOrNull!),
  );
}

Uint8List encodeFinished(Uint8List verifyData) =>
    encodeHandshake(tlsHsFinished, verifyData);

Result<Uint8List, PqTransportError> decodeFinished(
  Uint8List handshake, {
  int verifyDataLength = sha384HashBytes,
}) {
  final hs = decodeHandshake(handshake);
  if (hs.isFailure) return Result.failure(hs.errorOrNull!);
  final (type, body) = hs.valueOrNull!;
  if (type != tlsHsFinished) {
    return Result.failure(
      PqTransportError.unexpectedMessage('expected finished'),
    );
  }
  return requireLength(body, verifyDataLength, PqLengthLabel.verifyData);
}

Uint8List encodeEncryptedExtensions({
  int? serverCertificateType = tlsCertTypeRawPublicKey,
  String? alpnProtocol,
}) {
  final parts = BytesBuilder(copy: false);
  if (serverCertificateType != null) {
    parts.add(
      _ext(
        tlsExtServerCertificateType,
        Uint8List.fromList([serverCertificateType]),
      ),
    );
  }
  if (alpnProtocol != null) {
    parts.add(_extAlpn([alpnProtocol]));
  }
  final b = BytesBuilder(copy: false);
  writeOpaque16(b, parts.takeBytes());
  return encodeHandshake(tlsHsEncryptedExtensions, b.takeBytes());
}

/// RFC 8446 EncryptedExtensions. A null [serverCertificateType] means the
/// extension was absent, which is X.509 when the client allowed it.
final class EncryptedExtensions {
  const EncryptedExtensions({this.serverCertificateType, this.alpnProtocol});

  final int? serverCertificateType;
  final String? alpnProtocol;
}

Result<EncryptedExtensions, PqTransportError> decodeEncryptedExtensions(
  Uint8List handshake,
) {
  final hs = decodeHandshake(handshake);
  if (hs.isFailure) return Result.failure(hs.errorOrNull!);
  final (type, body) = hs.valueOrNull!;
  if (type != tlsHsEncryptedExtensions) {
    return Result.failure(
      PqTransportError.unexpectedMessage('expected encrypted extensions'),
    );
  }
  final r = ByteReader(body);
  final extBlock = r.opaque16(PqLengthLabel.tlsExtension);
  if (extBlock.isFailure) return Result.failure(extBlock.errorOrNull!);
  if (!r.isDone) {
    return Result.failure(
      PqTransportError.decodeFailure('trailing EncryptedExtensions'),
    );
  }
  final exts = _parseExtensions(extBlock.valueOrNull!);
  if (exts.isFailure) return Result.failure(exts.errorOrNull!);
  final map = exts.valueOrNull!;
  final data = map[tlsExtServerCertificateType];
  int? certificateType;
  if (data != null) {
    if (data.length != 1) {
      return Result.failure(
        PqTransportError.decodeFailure('server_certificate_type'),
      );
    }
    if (data[0] != tlsCertTypeRawPublicKey && data[0] != tlsCertTypeX509) {
      return Result.failure(
        PqTransportError.unsupportedCertificate(
          'server_certificate_type ${data[0]}',
        ),
      );
    }
    certificateType = data[0];
  }
  final alpn = _parseAlpn(map);
  if (alpn.isFailure) return Result.failure(alpn.errorOrNull!);
  final protocols = alpn.valueOrNull;
  if (protocols != null && protocols.length != 1) {
    return Result.failure(
      PqTransportError.decodeFailure('EncryptedExtensions ALPN not singleton'),
    );
  }
  return Result.success(
    EncryptedExtensions(
      serverCertificateType: certificateType,
      alpnProtocol: protocols?.first,
    ),
  );
}

/// RFC 7301: first client-offered protocol that the server supports.
/// Empty offer means no ALPN. Non-empty offer with no overlap is fatal.
Result<String?, PqTransportError> selectAlpn({
  required List<String> offered,
  required List<String> supported,
}) {
  if (offered.isEmpty) return const Result.success(null);
  for (final p in offered) {
    if (supported.contains(p)) return Result.success(p);
  }
  return Result.failure(PqTransportError.noApplicationProtocol());
}

/// RFC 8446 §4.1.3: HelloRetryRequest.random is SHA-256("HelloRetryRequest").
bool isHelloRetryRequestRandom(Uint8List random) {
  if (random.length != handshakeRandomBytes) return false;
  var diff = 0;
  for (var i = 0; i < handshakeRandomBytes; i++) {
    diff |= random[i] ^ tlsHelloRetryRequestRandom[i];
  }
  return diff == 0;
}

/// RFC 8446 §4.4.1: replace ClientHello1 with a `message_hash` wrapper.
void rewriteTranscriptForHelloRetry({
  required Transcript transcript,
  required Uint8List clientHello1,
  required Uint8List helloRetryRequest,
  required Uint8List Function(Uint8List) hash,
}) {
  transcript.clear();
  transcript.add(encodeHandshake(tlsHsMessageHash, hash(clientHello1)));
  transcript.add(helloRetryRequest);
}

Uint8List _ext(int type, Uint8List data) {
  final b = BytesBuilder(copy: false);
  writeUint16(b, type);
  writeOpaque16(b, data);
  return b.takeBytes();
}

Uint8List _extSupportedVersionsClient() {
  final versions = BytesBuilder(copy: false);
  writeUint16(versions, tls13Version);
  final inner = versions.takeBytes();
  final body = BytesBuilder(copy: false);
  body.addByte(inner.length);
  body.add(inner);
  return _ext(tlsExtSupportedVersions, body.takeBytes());
}

Uint8List _extSupportedVersionsServer() {
  final body = BytesBuilder(copy: false);
  writeUint16(body, tls13Version);
  return _ext(tlsExtSupportedVersions, body.takeBytes());
}

Uint8List _extSupportedGroups(List<int> codepoints) {
  final list = BytesBuilder(copy: false);
  for (final cp in codepoints) {
    writeUint16(list, cp);
  }
  return _ext(tlsExtSupportedGroups, _u16Vector(list.takeBytes()));
}

Uint8List _extSignatureAlgorithms(List<int> schemes) {
  final list = BytesBuilder(copy: false);
  for (final scheme in schemes) {
    writeUint16(list, scheme);
  }
  return _ext(tlsExtSignatureAlgorithms, _u16Vector(list.takeBytes()));
}

Uint8List _extKeyShareClient(HybridGroup group, Uint8List share) {
  final entry = BytesBuilder(copy: false);
  writeUint16(entry, group.codepoint);
  writeOpaque16(entry, share);
  return _ext(tlsExtKeyShare, _u16Vector(entry.takeBytes()));
}

Uint8List _extKeyShareServer(HybridGroup group, Uint8List share) {
  final body = BytesBuilder(copy: false);
  writeUint16(body, group.codepoint);
  writeOpaque16(body, share);
  return _ext(tlsExtKeyShare, body.takeBytes());
}

Uint8List _extKeyShareHelloRetry(HybridGroup group) {
  final body = BytesBuilder(copy: false);
  writeUint16(body, group.codepoint);
  return _ext(tlsExtKeyShare, body.takeBytes());
}

Uint8List _extCookie(Uint8List cookie) =>
    _ext(tlsExtCookie, _u16Vector(cookie));

Uint8List _extServerName(String host) {
  final hostBytes = Uint8List.fromList(ascii.encode(host));
  final name = BytesBuilder(copy: false);
  name.addByte(tlsServerNameTypeHostName);
  writeOpaque16(name, hostBytes);
  return _ext(tlsExtServerName, _u16Vector(name.takeBytes()));
}

Uint8List _extAlpn(List<String> protos) {
  final list = BytesBuilder(copy: false);
  for (final p in protos) {
    writeOpaque8(list, Uint8List.fromList(ascii.encode(p)));
  }
  return _ext(tlsExtAlpn, _u16Vector(list.takeBytes()));
}

Uint8List _extCertificateTypeOffer(List<TlsCertificateType> types) {
  final body = BytesBuilder(copy: false);
  writeOpaque8(body, Uint8List.fromList([for (final t in types) t.wire]));
  return _ext(tlsExtServerCertificateType, body.takeBytes());
}

Uint8List _u16Vector(Uint8List inner) {
  final b = BytesBuilder(copy: false);
  writeOpaque16(b, inner);
  return b.takeBytes();
}

Result<List<int>, PqTransportError> _parseCipherSuites(Uint8List raw) {
  if (raw.length < 2 || raw.length.isOdd) {
    return Result.failure(
      PqTransportError.decodeFailure('cipher_suites length'),
    );
  }
  final out = <int>[];
  for (var i = 0; i < raw.length; i += 2) {
    out.add(readUint16(raw, i));
  }
  return Result.success(out);
}

Result<void, PqTransportError> _requireUsableCiphers(List<int> suites) {
  if (TlsCipherSuite.select(suites) != null) {
    return const Result.success(null);
  }
  if (suites.contains(tlsCipherAes256GcmSha256Private)) {
    return Result.failure(
      PqTransportError.unsupported(
        'retired private-use 0xFF00; offer IANA 0x1302 or 0x1303',
      ),
    );
  }
  return Result.failure(
    PqTransportError.handshakeFailure('peer did not offer 0x1302 or 0x1303'),
  );
}

Result<Map<int, Uint8List>, PqTransportError> _parseExtensions(Uint8List raw) {
  final r = ByteReader(raw);
  final out = <int, Uint8List>{};
  while (!r.isDone) {
    final t = r.u16();
    if (t.isFailure) return Result.failure(t.errorOrNull!);
    final data = r.opaque16(PqLengthLabel.tlsExtension);
    if (data.isFailure) return Result.failure(data.errorOrNull!);
    if (out.containsKey(t.valueOrNull!)) {
      return Result.failure(
        PqTransportError.decodeFailure('duplicate extension ${t.valueOrNull}'),
      );
    }
    out[t.valueOrNull!] = data.valueOrNull!;
  }
  return Result.success(out);
}

Result<List<int>, PqTransportError> _parseSupportedVersionsClient(
  Map<int, Uint8List> exts,
) {
  final data = exts[tlsExtSupportedVersions];
  if (data == null) {
    return Result.failure(
      PqTransportError.decodeFailure('missing supported_versions'),
    );
  }
  final r = ByteReader(data);
  final list = r.opaque8(PqLengthLabel.tlsHello);
  if (list.isFailure) return Result.failure(list.errorOrNull!);
  if (!r.isDone) {
    return Result.failure(
      PqTransportError.decodeFailure('supported_versions trailing'),
    );
  }
  final raw = list.valueOrNull!;
  if (raw.length < 2 || raw.length.isOdd) {
    return Result.failure(
      PqTransportError.decodeFailure('supported_versions length'),
    );
  }
  final out = <int>[];
  for (var i = 0; i < raw.length; i += 2) {
    out.add(readUint16(raw, i));
  }
  return Result.success(out);
}

Result<int, PqTransportError> _parseSupportedVersionsServer(
  Map<int, Uint8List> exts,
) {
  final data = exts[tlsExtSupportedVersions];
  if (data == null) {
    return Result.failure(
      PqTransportError.decodeFailure('missing supported_versions'),
    );
  }
  if (data.length != 2) {
    return Result.failure(
      PqTransportError.decodeFailure('server supported_versions length'),
    );
  }
  return Result.success(readUint16(data, 0));
}

Result<List<int>, PqTransportError> _parseSupportedGroups(
  Map<int, Uint8List> exts,
) {
  final data = exts[tlsExtSupportedGroups];
  if (data == null) {
    return Result.failure(
      PqTransportError.decodeFailure('missing supported_groups'),
    );
  }
  final r = ByteReader(data);
  final list = r.opaque16(PqLengthLabel.tlsHello);
  if (list.isFailure) return Result.failure(list.errorOrNull!);
  final raw = list.valueOrNull!;
  if (raw.length < 2 || raw.length.isOdd) {
    return Result.failure(
      PqTransportError.decodeFailure('supported_groups length'),
    );
  }
  final out = <int>[];
  for (var i = 0; i < raw.length; i += 2) {
    out.add(readUint16(raw, i));
  }
  return Result.success(out);
}

Result<List<int>, PqTransportError> _parseSignatureAlgorithms(
  Map<int, Uint8List> exts,
) {
  final data = exts[tlsExtSignatureAlgorithms];
  if (data == null) {
    return Result.failure(
      PqTransportError.decodeFailure('missing signature_algorithms'),
    );
  }
  final r = ByteReader(data);
  final list = r.opaque16(PqLengthLabel.tlsHello);
  if (list.isFailure) return Result.failure(list.errorOrNull!);
  final raw = list.valueOrNull!;
  if (raw.length < 2 || raw.length.isOdd) {
    return Result.failure(
      PqTransportError.decodeFailure('signature_algorithms length'),
    );
  }
  final out = <int>[];
  for (var i = 0; i < raw.length; i += 2) {
    out.add(readUint16(raw, i));
  }
  return Result.success(out);
}

Result<(HybridGroup, Uint8List), PqTransportError> _parseKeyShareClient(
  Map<int, Uint8List> exts,
) {
  final data = exts[tlsExtKeyShare];
  if (data == null) {
    return Result.failure(PqTransportError.decodeFailure('missing key_share'));
  }
  final r = ByteReader(data);
  final list = r.opaque16(PqLengthLabel.tlsKeyShare);
  if (list.isFailure) return Result.failure(list.errorOrNull!);
  if (!r.isDone) {
    return Result.failure(PqTransportError.decodeFailure('key_share trailing'));
  }
  final inner = ByteReader(list.valueOrNull!);
  if (inner.isDone) {
    return Result.failure(PqTransportError.decodeFailure('empty key_share'));
  }
  final cp = inner.u16();
  if (cp.isFailure) return Result.failure(cp.errorOrNull!);
  final group = HybridGroupContract.byCodepoint(cp.valueOrNull!);
  if (group == null) {
    return Result.failure(
      PqTransportError.unsupported('named group ${cp.valueOrNull}'),
    );
  }
  final share = inner.opaque16(PqLengthLabel.hybridClientShare);
  if (share.isFailure) return Result.failure(share.errorOrNull!);
  if (!inner.isDone) {
    return Result.failure(
      PqTransportError.decodeFailure('extra key_share entries'),
    );
  }
  return Result.success((group, share.valueOrNull!));
}

Result<(HybridGroup, Uint8List), PqTransportError> _parseKeyShareServer(
  Map<int, Uint8List> exts,
) {
  final data = exts[tlsExtKeyShare];
  if (data == null) {
    return Result.failure(PqTransportError.decodeFailure('missing key_share'));
  }
  final r = ByteReader(data);
  final cp = r.u16();
  if (cp.isFailure) return Result.failure(cp.errorOrNull!);
  final group = HybridGroupContract.byCodepoint(cp.valueOrNull!);
  if (group == null) {
    return Result.failure(
      PqTransportError.unsupported('named group ${cp.valueOrNull}'),
    );
  }
  final share = r.opaque16(PqLengthLabel.hybridServerShare);
  if (share.isFailure) return Result.failure(share.errorOrNull!);
  if (!r.isDone) {
    return Result.failure(PqTransportError.decodeFailure('key_share trailing'));
  }
  return Result.success((group, share.valueOrNull!));
}

Result<HybridGroup, PqTransportError> _parseKeyShareHelloRetry(
  Map<int, Uint8List> exts,
) {
  final data = exts[tlsExtKeyShare];
  if (data == null) {
    return Result.failure(PqTransportError.decodeFailure('missing key_share'));
  }
  if (data.length != 2) {
    return Result.failure(
      PqTransportError.decodeFailure('HRR key_share must be NamedGroup only'),
    );
  }
  final cp = readUint16(data, 0);
  final group = HybridGroupContract.byCodepoint(cp);
  if (group == null) {
    return Result.failure(PqTransportError.unsupported('named group $cp'));
  }
  return Result.success(group);
}

Result<Uint8List?, PqTransportError> _parseCookie(Map<int, Uint8List> exts) {
  final data = exts[tlsExtCookie];
  if (data == null) return const Result.success(null);
  final r = ByteReader(data);
  final cookie = r.opaque16(PqLengthLabel.tlsCookie);
  if (cookie.isFailure) return Result.failure(cookie.errorOrNull!);
  if (cookie.valueOrNull!.isEmpty) {
    return Result.failure(PqTransportError.decodeFailure('empty cookie'));
  }
  if (!r.isDone) {
    return Result.failure(PqTransportError.decodeFailure('cookie trailing'));
  }
  return Result.success(cookie.valueOrNull);
}

Result<String?, PqTransportError> _parseServerName(Map<int, Uint8List> exts) {
  final data = exts[tlsExtServerName];
  if (data == null) return const Result.success(null);
  final r = ByteReader(data);
  final list = r.opaque16(PqLengthLabel.tlsServerName);
  if (list.isFailure) return Result.failure(list.errorOrNull!);
  final inner = ByteReader(list.valueOrNull!);
  final ntype = inner.u8();
  if (ntype.isFailure) return Result.failure(ntype.errorOrNull!);
  if (ntype.valueOrNull! != tlsServerNameTypeHostName) {
    return Result.failure(PqTransportError.unsupported('SNI name type'));
  }
  final host = inner.opaque16(PqLengthLabel.tlsServerName);
  if (host.isFailure) return Result.failure(host.errorOrNull!);
  try {
    return Result.success(ascii.decode(host.valueOrNull!));
  } on FormatException {
    return Result.failure(PqTransportError.decodeFailure('SNI not ASCII'));
  }
}

/// Null means the extension was omitted. RFC 7250 then requires X.509.
Result<List<TlsCertificateType>?, PqTransportError> _parseCertificateTypeOffer(
  Map<int, Uint8List> exts,
  int extType,
) {
  final data = exts[extType];
  if (data == null) return const Result.success(null);
  final r = ByteReader(data);
  final list = r.opaque8(PqLengthLabel.tlsHello);
  if (list.isFailure) return Result.failure(list.errorOrNull!);
  final bytes = list.valueOrNull!;
  if (bytes.isEmpty) {
    return Result.failure(
      PqTransportError.decodeFailure('empty certificate_type'),
    );
  }
  final out = <TlsCertificateType>[];
  for (final b in bytes) {
    final type = TlsCertificateType.fromWire(b);
    if (type == null) {
      return Result.failure(
        PqTransportError.unsupportedCertificate('certificate_type $b'),
      );
    }
    out.add(type);
  }
  return Result.success(out);
}

Result<List<String>?, PqTransportError> _parseAlpn(Map<int, Uint8List> exts) {
  final data = exts[tlsExtAlpn];
  if (data == null) return const Result.success(null);
  final r = ByteReader(data);
  final list = r.opaque16(PqLengthLabel.tlsAlpn);
  if (list.isFailure) return Result.failure(list.errorOrNull!);
  final inner = ByteReader(list.valueOrNull!);
  final out = <String>[];
  while (!inner.isDone) {
    final p = inner.opaque8(PqLengthLabel.tlsAlpn);
    if (p.isFailure) return Result.failure(p.errorOrNull!);
    try {
      out.add(ascii.decode(p.valueOrNull!));
    } on FormatException {
      return Result.failure(PqTransportError.decodeFailure('ALPN not ASCII'));
    }
  }
  if (out.isEmpty) {
    return Result.failure(PqTransportError.decodeFailure('empty ALPN'));
  }
  return Result.success(out);
}
