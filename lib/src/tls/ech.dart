import 'dart:convert';
import 'dart:typed_data';

import 'package:pqforge/pqforge.dart';
import 'package:swissarmyknife/swissarmyknife.dart';

import '../core/bytes.dart';
import '../core/crypto.dart';
import '../core/errors.dart';
import '../core/lengths.dart';
import 'handshake.dart';
import 'key_schedule.dart';
import 'record.dart';

/// RFC 9849 ECHConfig for the one HPKE suite this stack seals.
///
/// DHKEM(X25519, HKDF-SHA256) + HKDF-SHA256 + AES-128-GCM. The KEM, KDF,
/// and AEAD are pqforge's. HPKE itself is not a pqforge type yet, so the
/// base-mode composition stays here. No other KEM, and no cleartext retry.
final class EchConfig {
  EchConfig({
    required this.configId,
    required this.publicKey,
    required this.publicName,
    required this.maximumNameLength,
    this.wire,
  }) {
    if (publicKey.length != x25519ShareBytes) {
      throw ArgumentError.value(publicKey.length, 'publicKey');
    }
    if (configId < 0 || configId > 0xff) {
      throw ArgumentError.value(configId, 'configId');
    }
    if (maximumNameLength < 0 || maximumNameLength > 0xff) {
      throw ArgumentError.value(maximumNameLength, 'maximumNameLength');
    }
    final name = utf8.encode(publicName);
    if (name.isEmpty || name.length > 255) {
      throw ArgumentError.value(publicName, 'publicName');
    }
    final stored = wire;
    if (stored != null && stored.isEmpty) {
      throw ArgumentError.value(stored.length, 'wire');
    }
  }

  final int configId;
  final Uint8List publicKey;
  final String publicName;

  /// RFC 9849 §6.1.3. Padding uses this, not the public name's length.
  final int maximumNameLength;

  /// Original ECHConfig bytes. BoringSSL's generator writes two cipher
  /// suites. HPKE info is those bytes, not a re-encoding that drops one.
  final Uint8List? wire;

  /// One ECHConfig. A parsed config returns the bytes it was given.
  Uint8List encode() {
    final stored = wire;
    if (stored != null) return Uint8List.fromList(stored);
    final contents = _contents();
    final b = BytesBuilder(copy: false);
    writeUint16(b, echConfigVersion);
    writeOpaque16(b, contents);
    return b.takeBytes();
  }

  /// ECHConfigList: a u16 length prefix around one [encode].
  Uint8List encodeList() {
    final config = encode();
    final b = BytesBuilder(copy: false);
    writeOpaque16(b, config);
    return b.takeBytes();
  }

  /// Parse one ECHConfig. Extra HPKE suites are kept in [wire]. The
  /// suite this stack seals is HKDF-SHA256 + AES-128-GCM, which must
  /// be present. Other suites are not sealed.
  static Result<EchConfig, PqTransportError> parse(Uint8List wire) {
    if (wire.length < 4) {
      return Result.failure(PqTransportError.decodeFailure('ech config'));
    }
    if (readUint16(wire, 0) != echConfigVersion) {
      return Result.failure(PqTransportError.decodeFailure('ech version'));
    }
    final contentsLen = readUint16(wire, 2);
    if (wire.length != 4 + contentsLen) {
      return Result.failure(PqTransportError.decodeFailure('ech config'));
    }
    final r = ByteReader(slice(wire, 4, wire.length));
    final configId = r.u8();
    final kem = r.u16();
    final publicKey = r.opaque16(PqLengthLabel.tlsKeyShare);
    final suites = r.opaque16(PqLengthLabel.tlsCipherSuite);
    final maxName = r.u8();
    final name = r.opaque8(PqLengthLabel.tlsHello);
    final extensions = r.opaque16(PqLengthLabel.tlsExtension);
    if (!r.isDone ||
        configId.isFailure ||
        kem.isFailure ||
        publicKey.isFailure ||
        suites.isFailure ||
        maxName.isFailure ||
        name.isFailure ||
        extensions.isFailure) {
      return Result.failure(PqTransportError.decodeFailure('ech config'));
    }
    if (kem.valueOrNull != hpkeKemDhkemX25519HkdfSha256) {
      return Result.failure(PqTransportError.unsupported('ech kem'));
    }
    final suiteBytes = suites.valueOrNull!;
    if (suiteBytes.length < 4 || suiteBytes.length.isOdd) {
      return Result.failure(PqTransportError.decodeFailure('ech suites'));
    }
    var hasAes = false;
    for (var i = 0; i + 3 < suiteBytes.length; i += 4) {
      if (readUint16(suiteBytes, i) == hpkeKdfHkdfSha256 &&
          readUint16(suiteBytes, i + 2) == hpkeAeadAes128Gcm) {
        hasAes = true;
      }
    }
    if (!hasAes) {
      return Result.failure(PqTransportError.unsupported('ech aead'));
    }
    final nameBytes = name.valueOrNull!;
    if (nameBytes.isEmpty || nameBytes.length > 255) {
      return Result.failure(PqTransportError.decodeFailure('ech public name'));
    }
    try {
      final publicName = utf8.decode(nameBytes);
      return Result.success(
        EchConfig(
          configId: configId.valueOrNull!,
          publicKey: publicKey.valueOrNull!,
          publicName: publicName,
          maximumNameLength: maxName.valueOrNull!,
          wire: Uint8List.fromList(wire),
        ),
      );
    } on FormatException {
      return Result.failure(PqTransportError.decodeFailure('ech public name'));
    }
  }

  Uint8List _contents() {
    final b = BytesBuilder(copy: false);
    b.addByte(configId);
    writeUint16(b, hpkeKemDhkemX25519HkdfSha256);
    writeOpaque16(b, publicKey);
    final suite = BytesBuilder(copy: false);
    writeUint16(suite, hpkeKdfHkdfSha256);
    writeUint16(suite, hpkeAeadAes128Gcm);
    writeOpaque16(b, suite.takeBytes());
    b.addByte(maximumNameLength);
    final name = utf8.encode(publicName);
    b.addByte(name.length);
    b.add(name);
    writeUint16(b, 0);
    return b.takeBytes();
  }
}

/// Server-side ECH key. [config] is what a client seals to.
final class EchServerConfig {
  EchServerConfig({required this.secretKey, required this.config});

  final Uint8List secretKey;
  final EchConfig config;

  static Future<EchServerConfig> generate(
    PqTransportCrypto crypto, {
    required String publicName,
    int configId = 1,
    int? maximumNameLength,
  }) async {
    final pair = await crypto.x25519KeyGen();
    final maxName = maximumNameLength ?? publicName.length;
    return EchServerConfig(
      secretKey: pair.secretKey,
      config: EchConfig(
        configId: configId,
        publicKey: pair.publicKey,
        publicName: publicName,
        maximumNameLength: maxName < publicName.length
            ? publicName.length
            : maxName,
      ),
    );
  }
}

/// Build ClientHelloOuter. The caller puts [innerHandshake] in the
/// transcript. The returned bytes are what goes on the wire.
Future<Result<Uint8List, PqTransportError>> sealEchOuter({
  required PqTransportCrypto crypto,
  required EchConfig config,
  required Uint8List innerHandshake,
  required ClientHello inner,
}) async {
  if (innerHandshake.isEmpty || innerHandshake[0] != tlsHsClientHello) {
    return Result.failure(
      PqTransportError.decodeFailure('ech inner is not a ClientHello'),
    );
  }
  final body = slice(
    innerHandshake,
    tlsHandshakeHeaderBytes,
    innerHandshake.length,
  );
  final padded = _padInner(
    body,
    inner.serverName.length,
    config.maximumNameLength,
  );
  final outerRandom = crypto.randomBytes(handshakeRandomBytes);
  final outer = ClientHello(
    random: outerRandom,
    group: inner.group,
    share: inner.share,
    legacySessionId: inner.legacySessionId,
    cipherSuites: inner.cipherSuites,
    serverName: config.publicName,
    alpnProtocols: inner.alpnProtocols,
    supportedGroups: inner.supportedGroups,
    cookie: null,
    certificateTypes: inner.certificateTypes,
    signatureSchemes: inner.signatureSchemes,
    keyShares: inner.keyShares,
    ignoredKeyShareGroups: inner.ignoredKeyShareGroups,
  );
  final partial = outer.encode();
  final setup = await _setupBaseS(crypto, config);
  if (setup == null) {
    return Result.failure(PqTransportError.internalError('ech hpke setup'));
  }
  final payloadLen = padded.length + aeadTagBytes;
  final extension = _outerEchExtension(
    configId: config.configId,
    enc: setup.enc,
    payload: Uint8List(payloadLen),
  );
  final zeroed = _appendExtension(partial, extension);
  if (zeroed == null) {
    return Result.failure(
      PqTransportError.decodeFailure('ech outer extension'),
    );
  }
  final aad = slice(zeroed, tlsHandshakeHeaderBytes, zeroed.length);
  final sealed = setup.context.seal(crypto, aad, padded);
  if (sealed == null || sealed.length != payloadLen) {
    return Result.failure(PqTransportError.internalError('ech seal length'));
  }
  final wire = Uint8List.fromList(zeroed);
  wire.setRange(wire.length - sealed.length, wire.length, sealed);
  return Result.success(wire);
}

/// Decrypt ClientHelloOuter. Failure is terminal: the caller must not
/// continue with the outer hello.
Future<Result<Uint8List, PqTransportError>> openEchOuter({
  required PqTransportCrypto crypto,
  required EchServerConfig server,
  required Uint8List outerHandshake,
}) async {
  final parsed = _parseOuterEch(outerHandshake);
  if (parsed == null) {
    return Result.failure(
      PqTransportError.decryptError('ech extension missing or malformed'),
    );
  }
  if (parsed.configId != server.config.configId ||
      parsed.kdfId != hpkeKdfHkdfSha256 ||
      parsed.aeadId != hpkeAeadAes128Gcm) {
    return Result.failure(PqTransportError.decryptError('ech suite'));
  }
  final aad = Uint8List.fromList(
    slice(outerHandshake, tlsHandshakeHeaderBytes, outerHandshake.length),
  );
  if (parsed.payloadEnd > aad.length) {
    return Result.failure(PqTransportError.decryptError('ech payload'));
  }
  aad.fillRange(parsed.payloadStartInBody, parsed.payloadEnd, 0);
  final context = await _setupBaseR(
    crypto,
    enc: parsed.enc,
    recipientSecret: server.secretKey,
    recipientPublic: server.config.publicKey,
    info: _hpkeInfo(server.config),
  );
  if (context == null) {
    return Result.failure(PqTransportError.decryptError('ech hpke'));
  }
  final opened = context.open(crypto, aad, parsed.payload);
  if (opened == null) {
    return Result.failure(PqTransportError.decryptError('ech payload'));
  }
  final consumed = _clientHelloBodyLength(opened);
  if (consumed == null) {
    return Result.failure(PqTransportError.decodeFailure('ech inner'));
  }
  for (var i = consumed; i < opened.length; i++) {
    if (opened[i] != 0) {
      return Result.failure(
        PqTransportError.illegalParameter(PqLengthLabel.tlsHello, opened[i], 0),
      );
    }
  }
  if (_containsExtension(opened, tlsExtEncryptedClientHello) &&
      !_innerEchIsMarker(opened)) {
    return Result.failure(
      PqTransportError.illegalParameter(
        PqLengthLabel.tlsExtension,
        tlsExtEncryptedClientHello,
        1,
      ),
    );
  }
  final expanded = _expandOuterExtensions(
    slice(opened, 0, consumed),
    outerHandshake,
  );
  if (expanded == null) {
    return Result.failure(
      PqTransportError.illegalParameter(
        PqLengthLabel.tlsExtension,
        tlsExtEchOuterExtensions,
        0,
      ),
    );
  }
  final body = _restoreSessionId(expanded, parsed.outerSessionId);
  return Result.success(encodeHandshake(tlsHsClientHello, body));
}

/// RFC 9849 §7.2. [serverHello] is the wire message. Its last 8 random
/// bytes are compared to the confirmation over the inner transcript.
bool echAcceptConfirmationMatches({
  required PqTransportCrypto crypto,
  required TlsKeySchedule schedule,
  required Uint8List innerHandshake,
  required Uint8List innerRandom,
  required Uint8List serverHello,
}) {
  if (serverHello.length < 38 || innerRandom.length != handshakeRandomBytes) {
    return false;
  }
  final modified = Uint8List.fromList(serverHello);
  final got = slice(
    serverHello,
    echAcceptConfirmationOffset,
    echAcceptConfirmationOffset + 8,
  );
  modified.fillRange(
    echAcceptConfirmationOffset,
    echAcceptConfirmationOffset + 8,
    0,
  );
  final expect = _acceptConfirmation(
    crypto: crypto,
    schedule: schedule,
    label: 'ech accept confirmation',
    innerRandom: innerRandom,
    transcript: concatBytes([innerHandshake, modified]),
  );
  return PqBytes.constantTimeEquals(expect, got);
}

Uint8List echStampAcceptConfirmation({
  required PqTransportCrypto crypto,
  required TlsKeySchedule schedule,
  required Uint8List innerHandshake,
  required Uint8List innerRandom,
  required Uint8List serverHello,
}) {
  final modified = Uint8List.fromList(serverHello);
  modified.fillRange(
    echAcceptConfirmationOffset,
    echAcceptConfirmationOffset + 8,
    0,
  );
  final confirm = _acceptConfirmation(
    crypto: crypto,
    schedule: schedule,
    label: 'ech accept confirmation',
    innerRandom: innerRandom,
    transcript: concatBytes([innerHandshake, modified]),
  );
  final out = Uint8List.fromList(serverHello);
  out.setRange(
    echAcceptConfirmationOffset,
    echAcceptConfirmationOffset + 8,
    confirm,
  );
  return out;
}

/// Last 8 bytes of ServerHello.random. Header (4) + legacy_version (2) + 24.
const int echAcceptConfirmationOffset = 30;

Uint8List _acceptConfirmation({
  required PqTransportCrypto crypto,
  required TlsKeySchedule schedule,
  required String label,
  required Uint8List innerRandom,
  required Uint8List transcript,
}) {
  final zeros = Uint8List(schedule.hashLen);
  final prk = schedule.suite.usesSha384
      ? crypto.hkdfExtractSha384(zeros, innerRandom)
      : crypto.hkdfExtract(zeros, innerRandom);
  return schedule.expandLabel(
    prk,
    label,
    schedule.transcriptHash(transcript),
    8,
  );
}

Uint8List _padInner(
  Uint8List body,
  int serverNameLength,
  int maximumNameLength,
) {
  final namePad = maximumNameLength > serverNameLength
      ? maximumNameLength - serverNameLength
      : 0;
  final withName = body.length + namePad;
  final rounded = 31 - ((withName - 1) % 32);
  final pad = namePad + rounded;
  final out = Uint8List(body.length + pad);
  out.setRange(0, body.length, body);
  return out;
}

Uint8List _outerEchExtension({
  required int configId,
  required Uint8List enc,
  required Uint8List payload,
}) {
  final data = BytesBuilder(copy: false);
  data.addByte(0);
  writeUint16(data, hpkeKdfHkdfSha256);
  writeUint16(data, hpkeAeadAes128Gcm);
  data.addByte(configId);
  writeOpaque16(data, enc);
  writeOpaque16(data, payload);
  return _tlsExtension(tlsExtEncryptedClientHello, data.takeBytes());
}

Uint8List _tlsExtension(int type, Uint8List data) {
  final b = BytesBuilder(copy: false);
  writeUint16(b, type);
  writeOpaque16(b, data);
  return b.takeBytes();
}

final class _OuterEch {
  _OuterEch({
    required this.configId,
    required this.kdfId,
    required this.aeadId,
    required this.enc,
    required this.payload,
    required this.payloadStartInBody,
    required this.outerSessionId,
  });

  final int configId;
  final int kdfId;
  final int aeadId;
  final Uint8List enc;
  final Uint8List payload;
  final int payloadStartInBody;
  final Uint8List outerSessionId;

  int get payloadEnd => payloadStartInBody + payload.length;
}

_OuterEch? _parseOuterEch(Uint8List hs) {
  final located = _locateExtensions(hs);
  if (located == null) return null;
  final sessionId = slice(
    hs,
    located.sessionIdOffset + 1,
    located.sessionIdOffset + 1 + located.sessionIdLength,
  );
  var p = located.extensionsOffset;
  final end = p + located.extensionsLength;
  while (p + 4 <= end) {
    final type = readUint16(hs, p);
    final len = readUint16(hs, p + 2);
    final data = p + 4;
    if (data + len > end) return null;
    if (type == tlsExtEncryptedClientHello) {
      if (len < 1 + 2 + 2 + 1 + 2 + 2) return null;
      if (hs[data] != 0) return null;
      final kdf = readUint16(hs, data + 1);
      final aead = readUint16(hs, data + 3);
      final configId = hs[data + 5];
      final encLen = readUint16(hs, data + 6);
      final encAt = data + 8;
      if (encAt + encLen + 2 > data + len) return null;
      final enc = slice(hs, encAt, encAt + encLen);
      final payloadLen = readUint16(hs, encAt + encLen);
      final payloadAt = encAt + encLen + 2;
      if (payloadAt + payloadLen != data + len) return null;
      return _OuterEch(
        configId: configId,
        kdfId: kdf,
        aeadId: aead,
        enc: enc,
        payload: slice(hs, payloadAt, payloadAt + payloadLen),
        payloadStartInBody: payloadAt - tlsHandshakeHeaderBytes,
        outerSessionId: sessionId,
      );
    }
    p = data + len;
  }
  return null;
}

final class _ExtLocation {
  _ExtLocation({
    required this.extensionsOffset,
    required this.extensionsLength,
    required this.lengthFieldOffset,
    required this.sessionIdOffset,
    required this.sessionIdLength,
  });

  final int extensionsOffset;
  final int extensionsLength;
  final int lengthFieldOffset;
  final int sessionIdOffset;
  final int sessionIdLength;
}

_ExtLocation? _locateExtensions(Uint8List hs) {
  if (hs.length < tlsHandshakeHeaderBytes + 2 + handshakeRandomBytes + 1) {
    return null;
  }
  if (hs[0] != tlsHsClientHello) return null;
  final bodyLen = readUint24(hs, 1);
  if (hs.length != tlsHandshakeHeaderBytes + bodyLen) return null;
  var i = tlsHandshakeHeaderBytes + 2 + handshakeRandomBytes;
  final sidLen = hs[i];
  final sidAt = i;
  i += 1 + sidLen;
  if (i + 2 > hs.length) return null;
  final suiteLen = readUint16(hs, i);
  i += 2 + suiteLen;
  if (i >= hs.length) return null;
  final compLen = hs[i];
  i += 1 + compLen;
  if (i + 2 > hs.length) return null;
  final extLen = readUint16(hs, i);
  if (i + 2 + extLen != hs.length) return null;
  return _ExtLocation(
    extensionsOffset: i + 2,
    extensionsLength: extLen,
    lengthFieldOffset: i,
    sessionIdOffset: sidAt,
    sessionIdLength: sidLen,
  );
}

Uint8List? _appendExtension(Uint8List hs, Uint8List extension) {
  final located = _locateExtensions(hs);
  if (located == null) return null;
  final out = Uint8List(hs.length + extension.length);
  out.setRange(0, hs.length, hs);
  out.setRange(hs.length, out.length, extension);
  final extLen = located.extensionsLength + extension.length;
  final bodyLen = readUint24(hs, 1) + extension.length;
  if (extLen > 0xffff || bodyLen > 0xffffff) return null;
  out[located.lengthFieldOffset] = (extLen >> 8) & 0xff;
  out[located.lengthFieldOffset + 1] = extLen & 0xff;
  out[1] = (bodyLen >> 16) & 0xff;
  out[2] = (bodyLen >> 8) & 0xff;
  out[3] = bodyLen & 0xff;
  return out;
}

int? _clientHelloBodyLength(Uint8List body) {
  if (body.length < 2 + handshakeRandomBytes + 1) return null;
  var i = 2 + handshakeRandomBytes;
  final sidLen = body[i];
  i += 1 + sidLen;
  if (i + 2 > body.length) return null;
  final suiteLen = readUint16(body, i);
  i += 2 + suiteLen;
  if (i >= body.length) return null;
  final compLen = body[i];
  i += 1 + compLen;
  if (i + 2 > body.length) return null;
  final extLen = readUint16(body, i);
  i += 2 + extLen;
  if (i > body.length) return null;
  return i;
}

bool _innerEchIsMarker(Uint8List body) {
  final data = _extensionData(body, tlsExtEncryptedClientHello);
  return data != null && data.length == 1 && data[0] == 1;
}

/// RFC 9849 Appendix A. BoringSSL's client sends this instead of copying
/// the outer extensions into the encrypted hello. Absent, [body] is unchanged.
Uint8List? _expandOuterExtensions(Uint8List body, Uint8List outerHandshake) {
  final hello = _bodyLayout(body);
  final outer = _locateExtensions(outerHandshake);
  if (hello == null || outer == null) return null;
  final exts = slice(body, hello.extStart, hello.extStart + hello.extLen);
  var at = -1;
  var dataLen = 0;
  var p = 0;
  while (p + 4 <= exts.length) {
    final type = readUint16(exts, p);
    final len = readUint16(exts, p + 2);
    if (p + 4 + len > exts.length) return null;
    if (type == tlsExtEchOuterExtensions) {
      if (at != -1) return null;
      at = p;
      dataLen = len;
    }
    p += 4 + len;
  }
  if (p != exts.length) return null;
  if (at == -1) return body;
  final data = slice(exts, at + 4, at + 4 + dataLen);
  if (data.isEmpty) return null;
  final listLen = data[0];
  if (listLen != data.length - 1 || listLen == 0 || listLen.isOdd) return null;
  final outerExt = slice(
    outerHandshake,
    outer.extensionsOffset,
    outer.extensionsOffset + outer.extensionsLength,
  );
  final copied = BytesBuilder(copy: false);
  var o = 0;
  for (var i = 1; i < data.length; i += 2) {
    final want = readUint16(data, i);
    if (want == tlsExtEncryptedClientHello) return null;
    var found = false;
    while (o + 4 <= outerExt.length) {
      final type = readUint16(outerExt, o);
      final len = readUint16(outerExt, o + 2);
      if (o + 4 + len > outerExt.length) return null;
      final next = o + 4 + len;
      if (type == want) {
        copied.add(slice(outerExt, o, next));
        o = next;
        found = true;
        break;
      }
      o = next;
    }
    if (!found) return null;
  }
  final replacement = copied.takeBytes();
  final rebuilt = BytesBuilder(copy: false);
  rebuilt.add(slice(exts, 0, at));
  rebuilt.add(replacement);
  rebuilt.add(slice(exts, at + 4 + dataLen, exts.length));
  final extBytes = rebuilt.takeBytes();
  if (extBytes.length > 0xffff) return null;
  final out = BytesBuilder(copy: false);
  out.add(slice(body, 0, hello.extField));
  writeUint16(out, extBytes.length);
  out.add(extBytes);
  return out.takeBytes();
}

Uint8List? _extensionData(Uint8List body, int type) {
  final hello = _bodyLayout(body);
  if (hello == null) return null;
  var p = hello.extStart;
  final end = p + hello.extLen;
  while (p + 4 <= end) {
    final found = readUint16(body, p);
    final len = readUint16(body, p + 2);
    if (p + 4 + len > end) return null;
    if (found == type) return slice(body, p + 4, p + 4 + len);
    p += 4 + len;
  }
  return null;
}

({int extField, int extStart, int extLen})? _bodyLayout(Uint8List body) {
  if (body.length < 2 + handshakeRandomBytes + 1) return null;
  var i = 2 + handshakeRandomBytes;
  final sidLen = body[i];
  i += 1 + sidLen;
  if (i + 2 > body.length) return null;
  final suiteLen = readUint16(body, i);
  i += 2 + suiteLen;
  if (i >= body.length) return null;
  final compLen = body[i];
  i += 1 + compLen;
  if (i + 2 > body.length) return null;
  final extLen = readUint16(body, i);
  if (i + 2 + extLen > body.length) return null;
  return (extField: i, extStart: i + 2, extLen: extLen);
}

bool _containsExtension(Uint8List body, int type) {
  final n = _clientHelloBodyLength(body);
  if (n == null) return false;
  var i = 2 + handshakeRandomBytes;
  i += 1 + body[i];
  i += 2 + readUint16(body, i);
  i += 1 + body[i];
  final extLen = readUint16(body, i);
  var p = i + 2;
  final end = p + extLen;
  while (p + 4 <= end) {
    if (readUint16(body, p) == type) return true;
    p += 4 + readUint16(body, p + 2);
  }
  return false;
}

Uint8List _restoreSessionId(Uint8List body, Uint8List sessionId) {
  final oldLen = body[2 + handshakeRandomBytes];
  if (oldLen == sessionId.length) {
    var same = true;
    for (var i = 0; i < oldLen; i++) {
      if (body[2 + handshakeRandomBytes + 1 + i] != sessionId[i]) same = false;
    }
    if (same) return body;
  }
  final head = 2 + handshakeRandomBytes;
  final rest = slice(body, head + 1 + oldLen, body.length);
  final b = BytesBuilder(copy: false);
  b.add(slice(body, 0, head));
  b.addByte(sessionId.length);
  b.add(sessionId);
  b.add(rest);
  return b.takeBytes();
}

Uint8List _hpkeInfo(EchConfig config) {
  final encoded = config.encode();
  final out = Uint8List(7 + 1 + encoded.length);
  out.setRange(0, 7, utf8.encode('tls ech'));
  out[7] = 0;
  out.setRange(8, out.length, encoded);
  return out;
}

final class _HpkeContext {
  _HpkeContext(this.key, this.baseNonce);

  final Uint8List key;
  final Uint8List baseNonce;
  var _seq = 0;

  Uint8List? seal(
    PqTransportCrypto crypto,
    Uint8List aad,
    Uint8List plaintext,
  ) {
    final nonce = _nonce();
    _seq++;
    return crypto.aeadSeal(
      key: key,
      nonce: nonce,
      plaintext: plaintext,
      aad: aad,
      aead: TransportAead.aes128Gcm,
    );
  }

  Uint8List? open(
    PqTransportCrypto crypto,
    Uint8List aad,
    Uint8List ciphertext,
  ) {
    final nonce = _nonce();
    _seq++;
    try {
      return crypto.aeadOpen(
        key: key,
        nonce: nonce,
        ciphertextWithTag: ciphertext,
        aad: aad,
        aead: TransportAead.aes128Gcm,
      );
    } on ArgumentError {
      rethrow;
    } catch (_) {
      return null;
    }
  }

  Uint8List _nonce() {
    final n = Uint8List.fromList(baseNonce);
    var seq = _seq;
    for (var i = n.length - 1; i >= 0; i--) {
      n[i] ^= seq & 0xff;
      seq >>= 8;
    }
    return n;
  }
}

Future<({Uint8List enc, _HpkeContext context})?> _setupBaseS(
  PqTransportCrypto crypto,
  EchConfig config,
) async {
  final ephemeral = await crypto.x25519KeyGen();
  final dh = await crypto.x25519Agree(
    secretKey: ephemeral.secretKey,
    remotePublicKey: config.publicKey,
  );
  final secret = _kemSharedSecret(
    crypto,
    dh: dh,
    enc: ephemeral.publicKey,
    recipientPublic: config.publicKey,
  );
  final context = _keySchedule(crypto, secret, _hpkeInfo(config));
  return (enc: ephemeral.publicKey, context: context);
}

Future<_HpkeContext?> _setupBaseR(
  PqTransportCrypto crypto, {
  required Uint8List enc,
  required Uint8List recipientSecret,
  required Uint8List recipientPublic,
  required Uint8List info,
}) async {
  if (enc.length != x25519ShareBytes) return null;
  final dh = await crypto.x25519Agree(
    secretKey: recipientSecret,
    remotePublicKey: enc,
  );
  final secret = _kemSharedSecret(
    crypto,
    dh: dh,
    enc: enc,
    recipientPublic: recipientPublic,
  );
  return _keySchedule(crypto, secret, info);
}

Uint8List _kemSharedSecret(
  PqTransportCrypto crypto, {
  required Uint8List dh,
  required Uint8List enc,
  required Uint8List recipientPublic,
}) {
  final suite = _kemSuiteId();
  final context = concatBytes([enc, recipientPublic]);
  final prk = _labeledExtract(crypto, suite, Uint8List(0), 'eae_prk', dh);
  return _labeledExpand(
    crypto,
    suite,
    prk,
    'shared_secret',
    context,
    sha256HashBytes,
  );
}

_HpkeContext _keySchedule(
  PqTransportCrypto crypto,
  Uint8List sharedSecret,
  Uint8List info,
) {
  final suite = _hpkeSuiteId();
  final pskIdHash = _labeledExtract(
    crypto,
    suite,
    Uint8List(0),
    'psk_id_hash',
    Uint8List(0),
  );
  final infoHash = _labeledExtract(
    crypto,
    suite,
    Uint8List(0),
    'info_hash',
    info,
  );
  final ksContext = concatBytes([
    Uint8List.fromList([0]),
    pskIdHash,
    infoHash,
  ]);
  final secret = _labeledExtract(
    crypto,
    suite,
    sharedSecret,
    'secret',
    Uint8List(0),
  );
  final key = _labeledExpand(
    crypto,
    suite,
    secret,
    'key',
    ksContext,
    hpkeAes128KeyBytes,
  );
  final nonce = _labeledExpand(
    crypto,
    suite,
    secret,
    'base_nonce',
    ksContext,
    aeadNonceBytes,
  );
  return _HpkeContext(key, nonce);
}

Uint8List _labeledExtract(
  PqTransportCrypto crypto,
  Uint8List suiteId,
  Uint8List salt,
  String label,
  Uint8List ikm,
) {
  final labeled = concatBytes([
    Uint8List.fromList(utf8.encode('HPKE-v1')),
    suiteId,
    Uint8List.fromList(utf8.encode(label)),
    ikm,
  ]);
  final usedSalt = salt.isEmpty ? Uint8List(sha256HashBytes) : salt;
  return crypto.hkdfExtract(usedSalt, labeled);
}

Uint8List _labeledExpand(
  PqTransportCrypto crypto,
  Uint8List suiteId,
  Uint8List prk,
  String label,
  Uint8List info,
  int length,
) {
  final labeled = BytesBuilder(copy: false);
  writeUint16(labeled, length);
  labeled.add(utf8.encode('HPKE-v1'));
  labeled.add(suiteId);
  labeled.add(utf8.encode(label));
  labeled.add(info);
  return crypto.hkdfExpand(prk, labeled.takeBytes(), length);
}

Uint8List _kemSuiteId() {
  final out = Uint8List(3 + 2);
  out.setRange(0, 3, utf8.encode('KEM'));
  out[3] = (hpkeKemDhkemX25519HkdfSha256 >> 8) & 0xff;
  out[4] = hpkeKemDhkemX25519HkdfSha256 & 0xff;
  return out;
}

Uint8List _hpkeSuiteId() {
  final out = Uint8List(4 + 6);
  out.setRange(0, 4, utf8.encode('HPKE'));
  out[4] = (hpkeKemDhkemX25519HkdfSha256 >> 8) & 0xff;
  out[5] = hpkeKemDhkemX25519HkdfSha256 & 0xff;
  out[6] = (hpkeKdfHkdfSha256 >> 8) & 0xff;
  out[7] = hpkeKdfHkdfSha256 & 0xff;
  out[8] = (hpkeAeadAes128Gcm >> 8) & 0xff;
  out[9] = hpkeAeadAes128Gcm & 0xff;
  return out;
}
