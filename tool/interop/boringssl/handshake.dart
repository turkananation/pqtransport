import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:pqforge/pqforge.dart';
import 'package:pqtransport/pqtransport_io.dart';

import 'ech_flight.dart';

/// BoringSSL 0.20261020.0 as a TLS process. X25519MLKEM768 and
/// TLS_AES_256_GCM_SHA384 only. Not SecP256r1MLKEM768. Not
/// SecP384r1MLKEM1024. Not a browser.
Future<void> main(List<String> args) async {
  if (args.length != 1) {
    stderr.writeln(
      'usage: dart run tool/interop/boringssl/handshake.dart <boringssl_peer>',
    );
    exitCode = 64;
    return;
  }
  final peer = args.single;
  if (!File(peer).existsSync()) {
    throw StateError('boringssl_peer is missing at $peer');
  }
  final minted = await Directory.systemTemp.createTemp('pq-bssl-');
  try {
    await _run(peer, ['mint', minted.path]);
    await _clientFlights(peer, minted.path);
    await _serverFlights(peer);
    await _classicalFlights(peer);
    await boringsslEchFlights(peer);
    stdout.writeln(
      'BoringSSL 0.20261020.0 handshakes complete on X25519MLKEM768, '
      'TLS_AES_256_GCM_SHA384. ML-DSA-65 X.509 chain length 1, one '
      'P-256 leaf, and ML-DSA-65 raw public key, both directions. '
      'Not SecP256r1MLKEM768. Not SecP384r1MLKEM1024. Not a browser. '
      'Not WebPKI.',
    );
  } finally {
    await minted.delete(recursive: true);
  }
}

Future<void> _clientFlights(String peer, String dir) async {
  final mldsa = await File('$dir/mldsa-ca.der').readAsBytes();
  _requireCa(mldsa, 'BoringSSL ML-DSA CA');
  await _asClient(
    peer,
    dir,
    mode: 'mldsa',
    trustAnchors: [mldsa],
    certificateTypes: const [TlsCertificateType.x509],
    serverName: 'localhost',
  );
  final p256 = await File('$dir/p256-ca.der').readAsBytes();
  _requireCa(p256, 'BoringSSL P-256 CA');
  await _asClient(
    peer,
    dir,
    mode: 'p256',
    trustAnchors: [p256],
    certificateTypes: const [TlsCertificateType.x509],
    serverName: 'localhost',
  );
  await _asClient(
    peer,
    dir,
    mode: 'rpk',
    certificateTypes: const [TlsCertificateType.rawPublicKey],
  );
  stdout.writeln(
    'PqTlsClient to BoringSSL: ML-DSA-65, P-256, and raw public key',
  );
}

Future<void> _asClient(
  String peer,
  String dir, {
  required String mode,
  List<Uint8List> trustAnchors = const [],
  required List<TlsCertificateType> certificateTypes,
  String? serverName,
  String peerGroup = 'x25519mlkem768',
  TlsNamedGroup expectGroup = TlsNamedGroup.x25519MlKem768,
  bool expectHelloRetry = false,
}) async {
  final probe = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
  final port = probe.port;
  await probe.close();
  final server = await Process.start(peer, [
    'serve',
    '$port',
    mode,
    dir,
    peerGroup,
  ]);
  final err = StringBuffer();
  final errSub = server.stderr.transform(utf8.decoder).listen(err.write);
  try {
    final ready = DateTime.now().add(const Duration(seconds: 10));
    while (!err.toString().contains('boringssl listening') &&
        DateTime.now().isBefore(ready)) {
      if (await _exited(server)) break;
      await Future<void>.delayed(const Duration(milliseconds: 20));
    }
    if (!err.toString().contains('boringssl listening')) {
      throw StateError('BoringSSL server did not listen\n$err');
    }
    final socket = await _connect(port);
    final client = PqTlsClient(
      group: HybridGroup.x25519MlKem768,
      offeredCipherSuites: const [tlsCipherAes256GcmSha384],
      certificateTypes: certificateTypes,
      trustAnchors: trustAnchors,
      serverName: serverName,
    );
    final records = _Records(socket);
    try {
      final hello = await client.startHandshake();
      if (hello.isFailure) {
        throw StateError('$mode start: ${hello.errorOrNull}\n$err');
      }
      socket.add(hello.valueOrNull!);
      await socket.flush();
      while (!client.isComplete) {
        final rec = await records.next();
        if (rec == null) {
          throw StateError('$mode closed before Finished\n$err');
        }
        final out = await client.ingest(rec);
        if (out.isFailure) {
          throw StateError('$mode ingest: ${out.errorOrNull}\n$err');
        }
        for (final flight in out.valueOrNull!) {
          socket.add(flight);
        }
        await socket.flush();
      }
      if (!client.peerAuthenticated) {
        throw StateError('$mode finished without CertificateVerify\n$err');
      }
      if (client.cipherSuite != TlsCipherSuite.aes256GcmSha384) {
        throw StateError('$mode suite ${client.cipherSuite}');
      }
      if (client.negotiatedGroup != expectGroup) {
        throw StateError(
          '$mode group ${client.negotiatedGroup?.codepoint.toRadixString(16)} '
          'wanted ${expectGroup.codepoint.toRadixString(16)}\n$err',
        );
      }
      final retries = expectHelloRetry ? 1 : 0;
      if (client.helloRetryCount != retries) {
        throw StateError(
          '$mode helloRetryCount ${client.helloRetryCount} wanted $retries\n$err',
        );
      }
    } finally {
      socket.destroy();
    }
    final deadline = DateTime.now().add(const Duration(seconds: 5));
    while (!err.toString().contains('role=server mode=$mode') &&
        DateTime.now().isBefore(deadline)) {
      await Future<void>.delayed(const Duration(milliseconds: 20));
    }
    final hex = expectGroup.codepoint.toRadixString(16).padLeft(4, '0');
    if (!err.toString().contains(
      'boringssl handshake ok group=$hex suite=1302 role=server mode=$mode',
    )) {
      throw StateError('$mode server did not confirm\n$err');
    }
  } finally {
    await errSub.cancel();
    server.kill(ProcessSignal.sigkill);
    await server.exitCode.timeout(
      const Duration(seconds: 5),
      onTimeout: () => -1,
    );
  }
}

Future<void> _serverFlights(String peer) async {
  final crypto = const PqTransportCrypto();
  final mldsa = _mintMlDsa(crypto);
  await _asServer(
    peer,
    mode: 'mldsa',
    identity: mldsa.identity,
    caPem: mldsa.caPem,
    requireOk: true,
  );
  final p256 = _mintP256();
  await _asServer(
    peer,
    mode: 'p256',
    identity: p256.identity,
    caPem: p256.caPem,
    requireOk: true,
  );
  final raw = PqTlsServerIdentity.generate(crypto);
  await _asServer(
    peer,
    mode: 'rpk',
    identity: raw,
    expectedSpki: encodeMlDsa65Spki(raw.publicKey),
    requireOk: true,
  );
  final other = _mintMlDsa(crypto);
  await _asServer(
    peer,
    mode: 'mldsa',
    identity: mldsa.identity,
    caPem: other.caPem,
    requireOk: false,
  );
  stdout.writeln(
    'BoringSSL client to PqTlsSocket: ML-DSA-65, P-256, raw public key; '
    'wrong CA rejected',
  );
}

Future<void> _asServer(
  String peer, {
  required String mode,
  required PqTlsServerIdentity identity,
  String? caPem,
  Uint8List? expectedSpki,
  required bool requireOk,
  String peerGroup = 'x25519mlkem768',
  TlsNamedGroup expectGroup = TlsNamedGroup.x25519MlKem768,
}) async {
  final dir = await Directory.systemTemp.createTemp('pq-bssl-srv-');
  try {
    if (caPem != null) {
      final name = mode == 'p256' ? 'p256-ca.pem' : 'mldsa-ca.pem';
      await File('${dir.path}/$name').writeAsString(caPem);
    }
    if (expectedSpki != null) {
      await File('${dir.path}/expected.spki').writeAsBytes(expectedSpki);
    }
    final bound = await IoTcpServer.bind(InternetAddress.loopbackIPv4, 0);
    final port = bound.port;
    final failure = _serve(
      bound: bound,
      identity: identity,
      requireOk: requireOk,
      expectGroup: expectGroup,
    );
    final result = await Process.run(peer, [
      'connect',
      '127.0.0.1',
      '$port',
      mode,
      dir.path,
      peerGroup,
    ]);
    final serveError = await failure.timeout(const Duration(seconds: 8));
    final text = '${result.stdout}\n${result.stderr}';
    final hex = expectGroup.codepoint.toRadixString(16).padLeft(4, '0');
    final ok = text.contains(
      'boringssl handshake ok group=$hex suite=1302 role=client mode=$mode',
    );
    if (requireOk && (result.exitCode != 0 || !ok || serveError != null)) {
      throw StateError(
        'BoringSSL client $mode failed (${result.exitCode}) serve=$serveError\n'
        '$text',
      );
    }
    if (!requireOk && (result.exitCode == 0 || ok)) {
      throw StateError('wrong CA was accepted\n$text');
    }
  } finally {
    await dir.delete(recursive: true);
  }
}

Future<String?> _serve({
  required IoTcpServer bound,
  required PqTlsServerIdentity identity,
  required bool requireOk,
  TlsNamedGroup expectGroup = TlsNamedGroup.x25519MlKem768,
}) async {
  try {
    final raw = await bound.connections.first.timeout(
      const Duration(seconds: 15),
    );
    final tls = PqTlsSocket.server(
      raw,
      identity: identity,
      group: HybridGroup.x25519MlKem768,
    );
    try {
      final hs = await tls.handshake(timeout: const Duration(seconds: 20));
      if (hs.isFailure && requireOk) {
        return 'PqTlsSocket handshake: ${hs.errorOrNull}';
      }
      if (requireOk && tls.negotiatedGroup != expectGroup) {
        return 'negotiated ${tls.negotiatedGroup} wanted $expectGroup';
      }
    } finally {
      await tls.close();
    }
  } on Object catch (e) {
    if (requireOk) return '$e';
  } finally {
    await bound.close();
  }
  return null;
}

Future<void> _classicalFlights(String peer) async {
  final minted = await Directory.systemTemp.createTemp('pq-bssl-classical-');
  try {
    await _run(peer, ['mint', minted.path]);
    final ca = await File('${minted.path}/mldsa-ca.der').readAsBytes();
    const rows = <(String, TlsNamedGroup, bool)>[
      ('x25519', TlsNamedGroup.x25519, false),
      ('secp256r1', TlsNamedGroup.secp256r1, true),
      ('secp384r1', TlsNamedGroup.secp384r1, true),
      ('mlkem1024', TlsNamedGroup.mlKem1024, true),
    ];
    for (final row in rows) {
      stdout.writeln('BoringSSL server ${row.$1}');
      await _asClient(
        peer,
        minted.path,
        mode: 'mldsa',
        trustAnchors: [ca],
        certificateTypes: const [TlsCertificateType.x509],
        serverName: 'localhost',
        peerGroup: row.$1,
        expectGroup: row.$2,
        expectHelloRetry: row.$3,
      );
    }
    final identity = _mintMlDsa(const PqTransportCrypto());
    for (final row in rows) {
      stdout.writeln('BoringSSL client ${row.$1}');
      await _asServer(
        peer,
        mode: 'mldsa',
        identity: identity.identity,
        caPem: identity.caPem,
        requireOk: true,
        peerGroup: row.$1,
        expectGroup: row.$2,
      );
    }
    stdout.writeln(
      'BoringSSL 0.20261020.0 classical and pure ML-KEM-1024 complete. '
      'X25519, secp256r1, secp384r1, and MLKEM1024, both directions, '
      'ML-DSA-65 chain length 1. The default client share is the hybrid '
      'plus X25519, so P-256, P-384, and ML-KEM-1024 servers send '
      'HelloRetryRequest. Not a browser. Not WebPKI.',
    );
  } finally {
    await minted.delete(recursive: true);
  }
}

void _requireCa(Uint8List der, String label) {
  final parsed = PqX509.parse(der);
  if (parsed.certificate == null) {
    throw StateError('$label did not parse: ${parsed.failure}');
  }
}

Future<bool> _exited(Process process) async {
  try {
    await process.exitCode.timeout(Duration.zero);
    return true;
  } on TimeoutException {
    return false;
  }
}

Future<void> _run(String bin, List<String> args) async {
  final result = await Process.run(bin, args);
  if (result.exitCode != 0) {
    throw StateError('$bin ${args.join(' ')} failed\n${result.stderr}');
  }
}

Future<Socket> _connect(int port) async {
  Object? last;
  for (var i = 0; i < 50; i++) {
    try {
      return await Socket.connect(InternetAddress.loopbackIPv4, port);
    } on SocketException catch (e) {
      last = e;
      await Future<void>.delayed(const Duration(milliseconds: 50));
    }
  }
  throw StateError('BoringSSL did not accept: $last');
}

final class _Minted {
  const _Minted(this.identity, this.caPem);

  final PqTlsServerIdentity identity;
  final String caPem;
}

_Minted _mintMlDsa(PqTransportCrypto crypto) {
  final now = DateTime.now().toUtc();
  final notBefore = now.subtract(const Duration(hours: 1));
  final notAfter = now.add(const Duration(days: 1));
  final rootKeys = crypto.mlDsaKeyGen();
  final rootName = PqX509Name.commonName('pqtransport-ca');
  final rootKey = PqX509MlDsaKey(PqX509Algorithm.mlDsa65, rootKeys.publicKey);
  final root = PqX509.mint(
    issuer: rootName,
    subject: rootName,
    publicKey: rootKey,
    algorithm: PqX509Algorithm.mlDsa65,
    sign: (tbs) =>
        crypto.mlDsaSign(secretKey: rootKeys.secretKey, message: tbs),
    notBefore: notBefore,
    notAfter: notAfter,
    serial: Uint8List.fromList([1]),
    ca: true,
    keyCertSign: true,
    includeEku: false,
  );
  final leafKeys = crypto.mlDsaKeyGen();
  final leafKey = PqX509MlDsaKey(PqX509Algorithm.mlDsa65, leafKeys.publicKey);
  final leaf = PqX509.mint(
    issuer: rootName,
    subject: PqX509Name.commonName('localhost'),
    publicKey: leafKey,
    algorithm: PqX509Algorithm.mlDsa65,
    sign: (tbs) =>
        crypto.mlDsaSign(secretKey: rootKeys.secretKey, message: tbs),
    notBefore: notBefore,
    notAfter: notAfter,
    serial: Uint8List.fromList([2]),
    subjectAltNames: const [PqX509DnsName('localhost')],
  );
  return _Minted(
    PqTlsServerIdentity.x509(
      leafKey: leafKey,
      sign: (content) =>
          crypto.mlDsaSign(secretKey: leafKeys.secretKey, message: content),
      chain: [leaf],
      certificateDnsName: 'localhost',
    ),
    PqX509.toPem(root),
  );
}

_Minted _mintP256() {
  final now = DateTime.now().toUtc();
  final notBefore = now.subtract(const Duration(hours: 1));
  final notAfter = now.add(const Duration(days: 1));
  final caKeys = PqEcdsaP256.generateKeyPair();
  final leafKeys = PqEcdsaP256.generateKeyPair();
  final caName = PqX509Name.commonName('pqtransport-p256');
  Uint8List signCa(Uint8List tbs) => PqX509.encodeEcdsaSignature(
    PqEcdsaP256.sign(privateKey: caKeys.secretKey, message: tbs),
  );
  final ca = PqX509.mint(
    issuer: caName,
    subject: caName,
    publicKey: PqX509EcdsaP256Key(caKeys.publicKey),
    algorithm: PqX509Algorithm.ecdsaP256Sha256,
    sign: signCa,
    notBefore: notBefore,
    notAfter: notAfter,
    serial: Uint8List.fromList([1]),
    ca: true,
    keyCertSign: true,
    includeEku: false,
  );
  final leaf = PqX509.mint(
    issuer: caName,
    subject: PqX509Name.commonName('localhost'),
    publicKey: PqX509EcdsaP256Key(leafKeys.publicKey),
    algorithm: PqX509Algorithm.ecdsaP256Sha256,
    sign: signCa,
    notBefore: notBefore,
    notAfter: notAfter,
    serial: Uint8List.fromList([2]),
    subjectAltNames: const [PqX509DnsName('localhost')],
  );
  return _Minted(
    PqTlsServerIdentity.x509(
      leafKey: PqX509EcdsaP256Key(leafKeys.publicKey),
      sign: (content) =>
          PqEcdsaP256.sign(privateKey: leafKeys.secretKey, message: content),
      chain: [leaf],
      certificateDnsName: 'localhost',
    ),
    PqX509.toPem(ca),
  );
}

final class _Records {
  _Records(this._socket);

  final Socket _socket;
  final List<int> _pending = [];
  late final StreamIterator<Uint8List> _it = StreamIterator(_socket);

  Future<void> close() => _it.cancel();

  Future<Uint8List?> next() async {
    while (true) {
      final rec = _take();
      if (rec != null) return rec;
      if (!await _it.moveNext().timeout(const Duration(seconds: 15))) {
        return null;
      }
      _pending.addAll(_it.current);
    }
  }

  Uint8List? _take() {
    if (_pending.length < tlsRecordHeaderBytes) return null;
    final len = (_pending[3] << 8) | _pending[4];
    final total = tlsRecordHeaderBytes + len;
    if (_pending.length < total) return null;
    final rec = Uint8List.fromList(_pending.sublist(0, total));
    _pending.removeRange(0, total);
    return rec;
  }
}
