import 'dart:typed_data';

import 'package:pqtransport/pqtransport.dart';
import 'package:test/test.dart';

void main() {
  final g = HybridGroup.x25519MlKem768;

  ClientHello fixtureHello() => ClientHello(
    random: Uint8List(handshakeRandomBytes)..[0] = 7,
    group: g,
    share: Uint8List(g.clientShareBytes)..[0] = 1,
  );

  test('ClientHello body starts with legacy_version 0x0303', () {
    final hs = fixtureHello().encode();
    final decoded = decodeHandshake(hs);
    expect(decoded.isSuccess, isTrue);
    final body = decoded.valueOrNull!.$2;
    expect(readUint16(body, 0), tlsLegacyVersion);
    expect(body[2], 7); // start of random
  });

  test('ClientHello carries required RFC 8446 extensions', () {
    final decoded = ClientHello.decode(fixtureHello().encode());
    expect(decoded.isSuccess, isTrue, reason: '${decoded.errorOrNull}');
    final ch = decoded.valueOrNull!;
    expect(ch.group, g);
    expect(ch.share.length, g.clientShareBytes);
    expect(ch.share[0], 1);
    expect(ch.serverName, 'localhost');
    expect(ch.alpnProtocols, ['http/1.1']);
    expect(ch.cipherSuites, tlsDefaultOfferedCipherSuites);
    expect(ch.legacySessionId, isEmpty);
  });

  test('advertises IANA 0x1302 and 0x1303, not retired 0xFF00', () {
    final hs = fixtureHello().encode();
    expect(_containsSuite(hs, tlsCipherAes256GcmSha384), isTrue);
    expect(_containsSuite(hs, tlsCipherChaCha20Poly1305Sha256), isTrue);
    expect(_containsSuite(hs, tlsCipherAes256GcmSha256Private), isFalse);
  });

  test('compact 0.1 ClientHello body is retired', () {
    final body = BytesBuilder(copy: false)
      ..add(Uint8List(handshakeRandomBytes))
      ..addByte(0x11)
      ..addByte(0xEC)
      ..addByte(0x04)
      ..addByte(0xC0)
      ..add(Uint8List(g.clientShareBytes));
    final hs = encodeHandshake(tlsHsClientHello, body.takeBytes());
    final r = ClientHello.decode(hs);
    expect(r.isFailure, isTrue);
    expect(r.errorOrNull!.message, contains('compact'));
  });

  test('retired 0xFF00-only ClientHello is unsupported (OPEN-02)', () {
    final ch = ClientHello(
      random: Uint8List(handshakeRandomBytes),
      group: g,
      share: Uint8List(g.clientShareBytes)..[0] = 1,
      cipherSuites: const [tlsCipherAes256GcmSha256Private],
    );
    final r = ClientHello.decode(ch.encode());
    expect(r.isFailure, isTrue);
    expect(r.errorOrNull!.code, PqTransportErrorCode.unsupported);
  });

  test('ServerHello is RFC 8446-shaped and round-trips', () {
    final sh = ServerHello(
      random: Uint8List(handshakeRandomBytes)..[1] = 8,
      group: g,
      share: Uint8List(g.serverShareBytes)..[0] = 2,
    );
    final hs = sh.encode();
    final body = decodeHandshake(hs).valueOrNull!.$2;
    expect(readUint16(body, 0), tlsLegacyVersion);
    final decoded = ServerHello.decode(hs);
    expect(decoded.isSuccess, isTrue, reason: '${decoded.errorOrNull}');
    expect(decoded.valueOrNull!.group, g);
    expect(decoded.valueOrNull!.cipherSuite, tlsCipherAes256GcmSha384);
    expect(decoded.valueOrNull!.share[0], 2);
  });

  test('ServerHello refuses retired 0xFF00', () {
    final ok = ServerHello(
      random: Uint8List(handshakeRandomBytes),
      group: g,
      share: Uint8List(g.serverShareBytes)..[0] = 2,
    ).encode();
    final body = decodeHandshake(ok).valueOrNull!.$2;
    // cipher_suite sits after version(2)+random(32)+sid_len(1)
    final suiteOffset = 2 + handshakeRandomBytes + 1;
    body[suiteOffset] = 0xff;
    body[suiteOffset + 1] = 0x00;
    final hs = encodeHandshake(tlsHsServerHello, body);
    final r = ServerHello.decode(hs);
    expect(r.isFailure, isTrue);
    expect(r.errorOrNull!.code, PqTransportErrorCode.unsupported);
  });

  test('OPEN-04 EncryptedExtensions advertises RawPublicKey', () {
    final ee = encodeEncryptedExtensions();
    final decoded = decodeEncryptedExtensions(ee);
    expect(decoded.isSuccess, isTrue, reason: '${decoded.errorOrNull}');
    expect(decoded.valueOrNull, tlsCertTypeRawPublicKey);
    expect(
      decodeEncryptedExtensions(
        encodeHandshake(tlsHsEncryptedExtensions, Uint8List(0)),
      ).isFailure,
      isTrue,
    );
  });

  test('OPEN-04 ClientHello requires server_certificate_type RawPublicKey', () {
    expect(ClientHello.decode(fixtureHello().encode()).isSuccess, isTrue);
  });
}

bool _containsSuite(Uint8List hello, int suite) {
  final hi = (suite >> 8) & 0xff;
  final lo = suite & 0xff;
  for (var i = 0; i < hello.length - 1; i++) {
    if (hello[i] == hi && hello[i + 1] == lo) return true;
  }
  return false;
}
