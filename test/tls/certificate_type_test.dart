import 'dart:typed_data';

import 'package:pqforge/pqforge.dart';
import 'package:pqtransport/pqtransport.dart';
import 'package:swissarmyknife/swissarmyknife.dart';
import 'package:test/test.dart';

void main() {
  final crypto = PqTransportCrypto();
  final clock = DateTime.utc(2026, 6, 1);
  final notBefore = DateTime.utc(2026, 1, 1);
  final notAfter = DateTime.utc(2027, 1, 1);

  late PqTlsServerIdentity rawIdentity;
  late Uint8List leafDer;
  late Uint8List spki;
  late PqTlsServerIdentity x509Identity;
  late Uint8List chainLeaf;
  late Uint8List chainCa;
  late PqTlsServerIdentity chainIdentity;
  late Uint8List p256Secret;
  late Uint8List p256Leaf;
  late Uint8List p256Ca;
  late PqTlsServerIdentity p256Identity;

  setUpAll(() {
    rawIdentity = PqTlsServerIdentity.generate(crypto);
    final leafKey = PqX509MlDsaKey(
      PqX509Algorithm.mlDsa65,
      rawIdentity.publicKey,
    );
    leafDer = PqX509.mintLeaf(
      subject: PqX509Name.commonName('localhost'),
      publicKey: leafKey,
      algorithm: PqX509Algorithm.mlDsa65,
      sign: (tbs) =>
          crypto.mlDsaSign(secretKey: rawIdentity.secretKey, message: tbs),
      notBefore: notBefore,
      notAfter: notAfter,
      serial: Uint8List.fromList([1]),
      subjectAltNames: const [PqX509DnsName('localhost')],
    );
    spki = encodeMlDsa65Spki(rawIdentity.publicKey);
    x509Identity = PqTlsServerIdentity.x509(
      leafKey: leafKey,
      sign: (content) =>
          crypto.mlDsaSign(secretKey: rawIdentity.secretKey, message: content),
      chain: [leafDer],
      certificateDnsName: 'localhost',
    );

    final caKeys = crypto.mlDsaKeyGen();
    final caName = PqX509Name.commonName('pqtransport-ca');
    final caKey = PqX509MlDsaKey(PqX509Algorithm.mlDsa65, caKeys.publicKey);
    chainCa = PqX509.mint(
      issuer: caName,
      subject: caName,
      publicKey: caKey,
      algorithm: PqX509Algorithm.mlDsa65,
      sign: (tbs) =>
          crypto.mlDsaSign(secretKey: caKeys.secretKey, message: tbs),
      notBefore: notBefore,
      notAfter: notAfter,
      serial: Uint8List.fromList([1]),
      ca: true,
      keyCertSign: true,
      includeEku: false,
    );
    final issued = crypto.mlDsaKeyGen();
    final issuedKey = PqX509MlDsaKey(PqX509Algorithm.mlDsa65, issued.publicKey);
    chainLeaf = PqX509.mint(
      issuer: caName,
      subject: PqX509Name.commonName('localhost'),
      publicKey: issuedKey,
      algorithm: PqX509Algorithm.mlDsa65,
      sign: (tbs) =>
          crypto.mlDsaSign(secretKey: caKeys.secretKey, message: tbs),
      notBefore: notBefore,
      notAfter: notAfter,
      serial: Uint8List.fromList([2]),
      subjectAltNames: const [PqX509DnsName('localhost')],
    );
    chainIdentity = PqTlsServerIdentity.x509(
      leafKey: issuedKey,
      sign: (content) =>
          crypto.mlDsaSign(secretKey: issued.secretKey, message: content),
      chain: [chainLeaf, chainCa],
      certificateDnsName: 'localhost',
    );

    final p256CaKeys = PqEcdsaP256.generateKeyPair();
    final p256LeafKeys = PqEcdsaP256.generateKeyPair();
    p256Secret = p256LeafKeys.secretKey;
    final p256CaName = PqX509Name.commonName('pqtransport-p256');
    p256Ca = PqX509.mint(
      issuer: p256CaName,
      subject: p256CaName,
      publicKey: PqX509EcdsaP256Key(p256CaKeys.publicKey),
      algorithm: PqX509Algorithm.ecdsaP256Sha256,
      sign: (tbs) => PqX509.encodeEcdsaSignature(
        PqEcdsaP256.sign(privateKey: p256CaKeys.secretKey, message: tbs),
      ),
      notBefore: notBefore,
      notAfter: notAfter,
      serial: Uint8List.fromList([1]),
      ca: true,
      keyCertSign: true,
      includeEku: false,
    );
    p256Leaf = PqX509.mint(
      issuer: p256CaName,
      subject: PqX509Name.commonName('localhost'),
      publicKey: PqX509EcdsaP256Key(p256LeafKeys.publicKey),
      algorithm: PqX509Algorithm.ecdsaP256Sha256,
      sign: (tbs) => PqX509.encodeEcdsaSignature(
        PqEcdsaP256.sign(privateKey: p256CaKeys.secretKey, message: tbs),
      ),
      notBefore: notBefore,
      notAfter: notAfter,
      serial: Uint8List.fromList([2]),
      subjectAltNames: const [PqX509DnsName('localhost')],
    );
    p256Identity = PqTlsServerIdentity.x509(
      leafKey: PqX509EcdsaP256Key(p256LeafKeys.publicKey),
      sign: (content) => PqEcdsaP256.sign(
        privateKey: p256LeafKeys.secretKey,
        message: content,
      ),
      chain: [p256Leaf, p256Ca],
      certificateDnsName: 'localhost',
    );
  });

  test('default ClientHello bytes stay raw public key', () {
    final g = HybridGroup.x25519MlKem768;
    final random = Uint8List(handshakeRandomBytes)..[0] = 7;
    final share = Uint8List(g.clientShareBytes)..[0] = 1;
    final implicit = ClientHello(random: random, group: g, share: share);
    final explicit = ClientHello(
      random: random,
      group: g,
      share: share,
      certificateTypes: const [TlsCertificateType.rawPublicKey],
      signatureSchemes: const [tlsSignatureMldsa65, tlsSignatureMldsa87],
    );
    expect(implicit.encode(), explicit.encode());
    final decoded = ClientHello.decode(implicit.encode());
    expect(decoded.isSuccess, isTrue);
    expect(decoded.valueOrNull!.certificateTypes, [
      TlsCertificateType.rawPublicKey,
    ]);
    expect(decoded.valueOrNull!.signatureSchemes, [
      tlsSignatureMldsa65,
      tlsSignatureMldsa87,
    ]);

    final omitted = ClientHello(
      random: random,
      group: g,
      share: share,
      certificateTypes: const [TlsCertificateType.x509],
    );
    final back = ClientHello.decode(omitted.encode());
    expect(back.valueOrNull!.certificateTypes, isNull);
    expect(back.valueOrNull!.offersX509, isTrue);
    expect(back.valueOrNull!.offersRawPublicKey, isFalse);
  });

  test('omitted extension, one ML-DSA certificate, pin, no EE type', () async {
    final client = _x509Client(crypto, clock, trustedSpki: spki, quic: true);
    final server = PqTlsServer(
      crypto: crypto,
      identity: x509Identity,
      quic: true,
    );
    final rest = await _serverRest(client, server);
    final ee = decodeEncryptedExtensions(_messages(rest).first);
    expect(ee.valueOrNull!.serverCertificateType, isNull);
    expect(client.peerAuthenticated, isTrue);
  });

  test('raw client against a chain still receives the SPKI', () async {
    final client = PqTlsClient(crypto: crypto, quic: true);
    final server = PqTlsServer(
      crypto: crypto,
      identity: x509Identity,
      quic: true,
    );
    final rest = await _serverRest(client, server);
    final cert = _messages(rest)[1];
    final key = decodeCertificate(cert);
    expect(key.isSuccess, isTrue, reason: '${key.errorOrNull}');
    expect(key.valueOrNull, rawIdentity.publicKey);
    expect(cert, isNot(equals(encodeX509Certificate([leafDer]))));
    expect(client.peerAuthenticated, isTrue);
  });

  test('X.509 client and a raw identity send no ServerHello', () async {
    final client = _x509Client(crypto, clock, trustedSpki: spki);
    final server = PqTlsServer(crypto: crypto, identity: rawIdentity);
    final hello = await client.startHandshake();
    final flight = await server.ingest(hello.valueOrNull!);
    expect(flight.isFailure, isTrue);
    expect(flight.errorOrNull!.alert, tlsAlertUnsupportedCertificate);
    expect(server.isComplete, isFalse);
    expect(client.isComplete, isFalse);
    final alert = server.certificateAlert(flight.errorOrNull!);
    expect(alert, isNotNull);
    expect(alert![0], tlsContentAlert);
  });

  test('chain of two with an anchor completes', () async {
    final client = _x509Client(
      crypto,
      clock,
      trustAnchors: [chainCa],
      quic: true,
    );
    final server = PqTlsServer(
      crypto: crypto,
      identity: chainIdentity,
      quic: true,
    );
    final rest = await _serverRest(client, server);
    final entries = decodeCertificateEntries(_messages(rest)[1]);
    expect(entries.valueOrNull, hasLength(2));
    expect(client.peerAuthenticated, isTrue);
  });

  test('nine certificates, empty list, and a non-zero context fail', () {
    expect(
      decodeCertificateEntries(_certificateMessage(9)).errorOrNull!.alert,
      tlsAlertUnsupportedCertificate,
    );
    expect(
      decodeCertificateEntries(_certificateMessage(0)).errorOrNull!.alert,
      tlsAlertDecodeError,
    );
    final body = BytesBuilder(copy: false)
      ..addByte(1)
      ..addByte(0)
      ..addByte(0)
      ..addByte(0);
    expect(
      decodeCertificateEntries(
        encodeHandshake(tlsHsCertificate, body.takeBytes()),
      ).errorOrNull!.alert,
      tlsAlertDecodeError,
    );
    expect(
      () => PqTlsServerIdentity.x509(
        leafKey: PqX509MlDsaKey(PqX509Algorithm.mlDsa65, rawIdentity.publicKey),
        sign: (_) => Uint8List(0),
        chain: List<Uint8List>.filled(9, leafDer),
      ),
      throwsArgumentError,
    );
  });

  test('raw negotiated with an X.509 body fails before Finished', () async {
    final client = PqTlsClient(crypto: crypto, quic: true);
    final server = PqTlsServer(
      crypto: crypto,
      identity: rawIdentity,
      quic: true,
    );
    final rest = await _serverRest(client, server, ingestRest: false);
    final msgs = _messages(rest);
    msgs[1] = encodeX509Certificate([leafDer]);
    final failed = await client.ingest(_join(msgs));
    expect(failed.isFailure, isTrue);
    expect(failed.errorOrNull!.alert, tlsAlertUnsupportedCertificate);
    expect(client.isComplete, isFalse);
    expect(client.peerAuthenticated, isFalse);
  });

  test('X.509 negotiated with a bare SPKI fails', () async {
    final client = _x509Client(crypto, clock, trustedSpki: spki, quic: true);
    final server = PqTlsServer(
      crypto: crypto,
      identity: x509Identity,
      quic: true,
    );
    final rest = await _serverRest(client, server, ingestRest: false);
    final msgs = _messages(rest);
    msgs[1] = encodeCertificate(rawIdentity.publicKey);
    final failed = await client.ingest(_join(msgs));
    expect(failed.errorOrNull!.alert, tlsAlertUnsupportedCertificate);
    expect(client.isComplete, isFalse);
  });

  test('ML-DSA-87 CertificateVerify on a 65 leaf is decrypt_error', () {
    final leaf = PqX509.parse(leafDer).certificate!;
    final checked = verifyLeafSignature(
      leaf: leaf,
      verify: TlsCertificateVerify(
        tlsSignatureMldsa87,
        Uint8List(mlDsa87SignatureBytes),
      ),
      content: Uint8List(1),
      mlDsaVerify:
          ({
            required Uint8List publicKey,
            required Uint8List message,
            required Uint8List signatureBytes,
          }) => true,
    );
    expect(checked.errorOrNull!.alert, tlsAlertDecryptError);
  });

  test('RSA PKCS#1 is not a CertificateVerify scheme', () {
    final rsa = PqRsa.generateKeyPair();
    final der = PqX509.mintLeaf(
      subject: PqX509Name.commonName('localhost'),
      publicKey: PqX509RsaKey(rsa.modulus, rsa.exponent),
      algorithm: PqX509Algorithm.rsaPkcs1Sha256,
      sign: (tbs) => PqRsa.signPkcs1(
        privateKey: rsa.privateKey,
        message: tbs,
        hash: PqRsaHash.sha256,
      ),
      notBefore: notBefore,
      notAfter: notAfter,
      serial: Uint8List.fromList([1]),
      subjectAltNames: const [PqX509DnsName('localhost')],
    );
    final leaf = PqX509.parse(der).certificate!;
    expect(PqX509.checkSignature(leaf, leaf.publicKey), isTrue);
    final checked = verifyLeafSignature(
      leaf: leaf,
      verify: TlsCertificateVerify(0x0401, Uint8List(256)),
      content: Uint8List(1),
      mlDsaVerify:
          ({
            required Uint8List publicKey,
            required Uint8List message,
            required Uint8List signatureBytes,
          }) => false,
    );
    expect(checked.errorOrNull!.alert, tlsAlertUnsupportedCertificate);
    expect(
      () => PqTlsServerIdentity.x509(
        leafKey: PqX509RsaKey(rsa.modulus, rsa.exponent),
        sign: (_) => Uint8List(0),
        chain: [der],
      ),
      throwsArgumentError,
    );
  });

  test('no anchor and no pin fails closed', () async {
    final client = _x509Client(crypto, clock);
    final server = PqTlsServer(crypto: crypto, identity: x509Identity);
    final hello = await client.startHandshake();
    final flight = await server.ingest(hello.valueOrNull!);
    expect(flight.isSuccess, isTrue, reason: '${flight.errorOrNull}');
    await client.ingest(flight.valueOrNull![0]);
    final hs = await client.ingest(flight.valueOrNull![1]);
    expect(hs.errorOrNull!.alert, tlsAlertBadCertificate);
    expect(client.isComplete, isFalse);
    expect(client.peerAuthenticated, isFalse);
    expect(client.certificateAlert(hs.errorOrNull!), isNotNull);
  });

  test('allowUnauthenticated finishes without the hook', () async {
    var hooks = 0;
    final client = _x509Client(
      crypto,
      clock,
      allowUnauthenticated: true,
      verifyPeer: (PqX509Certificate _, List<Uint8List> _, TlsCertificateVerify _) {
        hooks++;
        return const Result<void, PqTransportError>.success(null);
      },
    );
    final server = PqTlsServer(crypto: crypto, identity: x509Identity);
    await _finish(client, server);
    expect(client.peerAuthenticated, isFalse);
    expect(hooks, 0);
  });

  test('name mismatch is bad_certificate', () async {
    final client = _x509Client(
      crypto,
      clock,
      trustedSpki: spki,
      serverName: 'other.example',
    );
    final server = PqTlsServer(crypto: crypto, identity: x509Identity);
    final hello = await client.startHandshake();
    final flight = await server.ingest(hello.valueOrNull!);
    await client.ingest(flight.valueOrNull![0]);
    final hs = await client.ingest(flight.valueOrNull![1]);
    expect(hs.errorOrNull!.code, PqTransportErrorCode.badCertificate);
    expect(client.isComplete, isFalse);
  });

  test('P-256 leaf is verified by pqforge, not mlDsaVerify', () {
    final leaf = PqX509.parse(p256Leaf).certificate!;
    final content = Uint8List.fromList([9, 8, 7]);
    final signature = PqEcdsaP256.sign(
      privateKey: p256Secret,
      message: content,
    );
    var calls = 0;
    final checked = verifyLeafSignature(
      leaf: leaf,
      verify: TlsCertificateVerify(tlsSignatureEcdsaP256Sha256, signature),
      content: content,
      mlDsaVerify:
          ({
            required Uint8List publicKey,
            required Uint8List message,
            required Uint8List signatureBytes,
          }) {
            calls++;
            return false;
          },
    );
    expect(checked.isSuccess, isTrue, reason: '${checked.errorOrNull}');
    expect(calls, 0);
  });

  test('browser-shaped hello: no raw key, P-256 chain completes', () async {
    final browser = _x509Client(
      crypto,
      clock,
      trustAnchors: [p256Ca],
      signatureSchemes: const [tlsSignatureEcdsaP256Sha256],
    );
    final refused = PqTlsServer(crypto: crypto, identity: rawIdentity);
    final hello = await browser.startHandshake();
    final decoded = ClientHello.decode(
      unwrapHandshake(hello.valueOrNull!, quic: false).valueOrNull!,
    );
    expect(decoded.valueOrNull!.certificateTypes, isNull);
    expect(
      decoded.valueOrNull!.signatureSchemes.contains(tlsSignatureMldsa65),
      isFalse,
    );
    final no = await refused.ingest(hello.valueOrNull!);
    expect(no.isFailure, isTrue);
    expect(no.errorOrNull!.alert, tlsAlertUnsupportedCertificate);

    final again = _x509Client(
      crypto,
      clock,
      trustAnchors: [p256Ca],
      signatureSchemes: const [tlsSignatureEcdsaP256Sha256],
    );
    final server = PqTlsServer(crypto: crypto, identity: p256Identity);
    await _finish(again, server);
    expect(again.peerAuthenticated, isTrue);
  });

  test('QUIC handshake with certificateTypes x509 completes', () async {
    final client = _x509Client(crypto, clock, trustedSpki: spki, quic: true);
    final server = PqTlsServer(
      crypto: crypto,
      identity: x509Identity,
      quic: true,
    );
    await _finish(client, server);
    expect(client.peerAuthenticated, isTrue);
  });
}

PqTlsClient _x509Client(
  PqTransportCrypto crypto,
  DateTime clock, {
  List<Uint8List> trustAnchors = const [],
  Uint8List? trustedSpki,
  bool allowUnauthenticated = false,
  PqCertificateHook? verifyPeer,
  String? serverName = 'localhost',
  List<int>? signatureSchemes,
  bool quic = false,
}) => PqTlsClient(
  crypto: crypto,
  certificateTypes: const [TlsCertificateType.x509],
  trustAnchors: trustAnchors,
  trustedSpki: trustedSpki,
  allowUnauthenticated: allowUnauthenticated,
  verifyPeer: verifyPeer,
  now: () => clock,
  serverName: serverName,
  signatureSchemes: signatureSchemes,
  quic: quic,
);

Future<void> _finish(PqTlsClient client, PqTlsServer server) async {
  await _serverRest(client, server);
}

Future<Uint8List> _serverRest(
  PqTlsClient client,
  PqTlsServer server, {
  bool ingestRest = true,
}) async {
  final hello = await client.startHandshake();
  expect(hello.isSuccess, isTrue, reason: '${hello.errorOrNull}');
  final flight = await server.ingest(hello.valueOrNull!);
  expect(flight.isSuccess, isTrue, reason: '${flight.errorOrNull}');
  expect(flight.valueOrNull!, hasLength(2));
  final sh = await client.ingest(flight.valueOrNull![0]);
  expect(sh.isSuccess, isTrue, reason: '${sh.errorOrNull}');
  if (!ingestRest) return flight.valueOrNull![1];
  final hs = await client.ingest(flight.valueOrNull![1]);
  expect(hs.isSuccess, isTrue, reason: '${hs.errorOrNull}');
  expect(hs.valueOrNull, isNotEmpty);
  final done = await server.ingest(hs.valueOrNull!.single);
  expect(done.isSuccess, isTrue, reason: '${done.errorOrNull}');
  expect(client.isComplete, isTrue);
  expect(server.isComplete, isTrue);
  return flight.valueOrNull![1];
}

List<Uint8List> _messages(Uint8List bytes) {
  final out = <Uint8List>[];
  var offset = 0;
  while (offset < bytes.length) {
    final n = handshakeWireLength(Uint8List.sublistView(bytes, offset));
    if (n < tlsHandshakeHeaderBytes) {
      fail('truncated handshake at $offset');
    }
    out.add(Uint8List.sublistView(bytes, offset, offset + n));
    offset += n;
  }
  return out;
}

Uint8List _join(List<Uint8List> parts) {
  final b = BytesBuilder(copy: false);
  for (final part in parts) {
    b.add(part);
  }
  return b.takeBytes();
}

Uint8List _certificateMessage(int count) {
  final list = BytesBuilder(copy: false);
  for (var i = 0; i < count; i++) {
    final der = Uint8List.fromList([0x30, 0x03, 0x02, 0x01, i + 1]);
    list
      ..addByte(0)
      ..addByte(0)
      ..addByte(der.length)
      ..add(der)
      ..addByte(0)
      ..addByte(0);
  }
  final packed = list.takeBytes();
  final body = BytesBuilder(copy: false)
    ..addByte(0)
    ..addByte(0)
    ..addByte((packed.length >> 8) & 0xff)
    ..addByte(packed.length & 0xff)
    ..add(packed);
  return encodeHandshake(tlsHsCertificate, body.takeBytes());
}
