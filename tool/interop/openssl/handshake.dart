import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:pqforge/pqforge.dart';
import 'package:pqtransport/pqtransport_io.dart';

Future<void> main(List<String> args) async {
  if (args.isEmpty || args.length > 2) {
    stderr.writeln(
      'usage: dart run tool/interop/openssl/handshake.dart <openssl> [x509]',
    );
    exitCode = 64;
    return;
  }
  if (args.length == 2 && args[1] == 'x509') {
    await handshakeX509(args[0]);
    exit(0);
  }
  await handshakeX25519MlKem768(args.single);
  await handshakeSecP256r1MlKem768(args.single);
  await handshakeSecP384r1MlKem1024(args.single);
  stdout.writeln(
    'OpenSSL 3.5 hybrid handshakes complete '
    '(X25519MLKEM768, SecP256r1MLKEM768, SecP384r1MLKEM1024)',
  );
  await handshakeX509(args.single);
  exit(0);
}

/// X25519MLKEM768 (`0x11EC`). ML-KEM then X25519. Balanced profile.
Future<void> handshakeX25519MlKem768(String opensslBin) =>
    _handshake(opensslBin, HybridGroup.x25519MlKem768);

/// SecP256r1MLKEM768 (`0x11EB`). ECDHE then ML-KEM. Balanced profile.
Future<void> handshakeSecP256r1MlKem768(String opensslBin) =>
    _handshake(opensslBin, HybridGroup.secP256r1MlKem768);

/// SecP384r1MLKEM1024 (`0x11ED`). ECDHE then ML-KEM. `maximum` profile.
Future<void> handshakeSecP384r1MlKem1024(String opensslBin) =>
    _handshake(opensslBin, HybridGroup.secP384r1MlKem1024);

/// X.509, not raw public key. OpenSSL mints an ML-DSA-65 CA and leaf.
/// The leaf is what `s_server` sends. The CA is the trust anchor.
/// BoringSSL 0.20261020.0 verifies that same leaf. curl, linked to this
/// OpenSSL, does one of the three groups with `--cacert`.
Future<void> handshakeX509(String opensslBin) async {
  for (final group in HybridGroup.values) {
    await _handshake(opensslBin, group, x509: true);
  }
  stdout.writeln(
    'OpenSSL 3.5 X.509 handshakes complete '
    '(X25519MLKEM768, SecP256r1MLKEM768, SecP384r1MLKEM1024)',
  );
  await _curlX509(opensslBin);
}

/// Completes one TLS 1.3 handshake with OpenSSL `s_server`.
///
/// Auth mode without [x509]: RFC 7250 raw public key, ML-DSA-65. The server
/// certificate is an ML-DSA-65 X.509 certificate; `-enable_server_rpk` makes
/// OpenSSL send the SubjectPublicKeyInfo instead of the certificate.
///
/// With [x509]: no `-enable_server_rpk`. The Certificate message is the
/// leaf. Suite is TLS_AES_256_GCM_SHA384 (`0x1302`).
Future<void> _handshake(
  String opensslBin,
  HybridGroup group, {
  bool x509 = false,
}) async {
  final dir = await Directory.systemTemp.createTemp('pq-openssl-');
  final conf = x509
      ? '${Directory.current.path}/tool/interop/openssl/openssl-x509.cnf'
      : Platform.environment['OPENSSL_CONF'] ??
            '${Directory.current.path}/tool/interop/openssl/openssl.cnf';
  final env = {
    ...Platform.environment,
    'LD_LIBRARY_PATH': _libDir(opensslBin),
    'OPENSSL_CONF': conf,
  };
  try {
    Uint8List? anchor;
    if (!x509) {
      await _run(opensslBin, env, [
        'genpkey',
        '-algorithm',
        'ML-DSA-65',
        '-out',
        '${dir.path}/key.pem',
      ]);
      await _run(opensslBin, env, [
        'req',
        '-new',
        '-x509',
        '-key',
        '${dir.path}/key.pem',
        '-config',
        conf,
        '-subj',
        '/CN=localhost',
        '-days',
        '1',
        '-out',
        '${dir.path}/cert.pem',
      ]);
      await _run(opensslBin, env, [
        'pkey',
        '-in',
        '${dir.path}/key.pem',
        '-pubout',
        '-outform',
        'DER',
        '-out',
        '${dir.path}/spki.der',
      ]);
      final spki = decodeMlDsa65Spki(
        await File('${dir.path}/spki.der').readAsBytes(),
      );
      if (spki.isFailure) {
        throw StateError('OpenSSL SPKI: ${spki.errorOrNull}');
      }
    } else {
      anchor = await _mintX509(opensslBin, env, dir, conf);
      await _boringSslLeaf(env, dir);
    }

    final probe = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
    final port = probe.port;
    await probe.close();
    final server = await Process.start(opensslBin, [
      's_server',
      '-accept',
      '127.0.0.1:$port',
      '-tls1_3',
      '-cert',
      x509 ? '${dir.path}/leaf.pem' : '${dir.path}/cert.pem',
      '-key',
      x509 ? '${dir.path}/leaf.key' : '${dir.path}/key.pem',
      if (!x509) '-enable_server_rpk',
      '-groups',
      _opensslGroup(group),
      '-ciphersuites',
      'TLS_AES_256_GCM_SHA384',
      '-naccept',
      '1',
      '-state',
    ], environment: env);
    final errBuf = StringBuffer();
    final outBuf = StringBuffer();
    final errSub = server.stderr.transform(utf8.decoder).listen(errBuf.write);
    final outSub = server.stdout.transform(utf8.decoder).listen(outBuf.write);

    final client = PqTlsClient(
      crypto: _cryptoFor(group),
      group: group,
      offeredCipherSuites: const [tlsCipherAes256GcmSha384],
      certificateTypes: x509
          ? const [TlsCertificateType.x509]
          : const [TlsCertificateType.rawPublicKey],
      trustAnchors: anchor == null ? const [] : [anchor],
      serverName: x509 ? 'localhost' : null,
    );
    Socket? socket;
    _Records? records;
    try {
      socket = await _connect(port);
    } catch (e) {
      throw StateError('$e\nstdout:\n$outBuf\nstderr:\n$errBuf');
    }
    try {
      records = _Records(socket);
      final hello = await client.startHandshake();
      if (hello.isFailure) {
        throw StateError('${_opensslGroup(group)} start: ${hello.errorOrNull}');
      }
      socket.add(hello.valueOrNull!);
      await socket.flush();

      while (!client.isComplete) {
        final rec = await records.next();
        if (rec == null) {
          throw StateError(
            '${_opensslGroup(group)} peer closed before Finished\n$errBuf',
          );
        }
        final out = await client.ingest(rec);
        if (out.isFailure) {
          throw StateError(
            '${_opensslGroup(group)} ingest: ${out.errorOrNull}\n$errBuf',
          );
        }
        for (final flight in out.valueOrNull!) {
          socket.add(flight);
        }
        await socket.flush();
      }
      if (!client.peerAuthenticated) {
        throw StateError(
          '${_opensslGroup(group)} finished without CertificateVerify',
        );
      }
      if (client.cipherSuite != TlsCipherSuite.aes256GcmSha384) {
        throw StateError('suite ${client.cipherSuite}');
      }
      final deadline = DateTime.now().add(const Duration(seconds: 5));
      while (!errBuf.toString().contains('read finished') &&
          DateTime.now().isBefore(deadline)) {
        await Future<void>.delayed(const Duration(milliseconds: 20));
      }
      if (!errBuf.toString().contains('read finished')) {
        throw StateError(
          '${_opensslGroup(group)} did not accept Finished:\n$errBuf',
        );
      }
      await socket.close();
      socket = null;
    } finally {
      await records?.close();
      await socket?.close();
      await errSub.cancel();
      await outSub.cancel();
      server.kill(ProcessSignal.sigkill);
      await server.exitCode.timeout(
        const Duration(seconds: 5),
        onTimeout: () => -1,
      );
    }
  } finally {
    await dir.delete(recursive: true);
  }
}

/// CA and leaf, both ML-DSA-65. Returns the CA as DER.
Future<Uint8List> _mintX509(
  String opensslBin,
  Map<String, String> env,
  Directory dir,
  String conf,
) async {
  await _run(opensslBin, env, [
    'genpkey',
    '-algorithm',
    'ML-DSA-65',
    '-out',
    '${dir.path}/ca.key',
  ]);
  await _run(opensslBin, env, [
    'req',
    '-new',
    '-x509',
    '-key',
    '${dir.path}/ca.key',
    '-config',
    conf,
    '-extensions',
    'ca_ext',
    '-subj',
    '/CN=pqtransport-ca',
    '-days',
    '1',
    '-out',
    '${dir.path}/ca.pem',
  ]);
  await _run(opensslBin, env, [
    'genpkey',
    '-algorithm',
    'ML-DSA-65',
    '-out',
    '${dir.path}/leaf.key',
  ]);
  await _run(opensslBin, env, [
    'req',
    '-new',
    '-key',
    '${dir.path}/leaf.key',
    '-config',
    conf,
    '-subj',
    '/CN=localhost',
    '-out',
    '${dir.path}/leaf.csr',
  ]);
  await _run(opensslBin, env, [
    'x509',
    '-req',
    '-in',
    '${dir.path}/leaf.csr',
    '-CA',
    '${dir.path}/ca.pem',
    '-CAkey',
    '${dir.path}/ca.key',
    '-CAcreateserial',
    '-days',
    '1',
    '-extfile',
    conf,
    '-extensions',
    'leaf_ext',
    '-out',
    '${dir.path}/leaf.pem',
  ]);
  await _run(opensslBin, env, [
    'x509',
    '-in',
    '${dir.path}/ca.pem',
    '-outform',
    'DER',
    '-out',
    '${dir.path}/ca.der',
  ]);
  final der = await File('${dir.path}/ca.der').readAsBytes();
  final parsed = PqX509.parse(der);
  if (parsed.certificate == null) {
    throw StateError('OpenSSL CA did not parse: ${parsed.failure}');
  }
  return der;
}

/// The leaf OpenSSL just minted, checked by the pinned BoringSSL.
/// This is the pqforge leaf check: X509_verify_cert, not a second TLS stack.
Future<void> _boringSslLeaf(Map<String, String> env, Directory dir) async {
  final built = Platform.environment['BORINGSSL_VERIFY'];
  final candidate =
      built ??
      '${Directory.current.path}/tool/interop/boringssl/.build/bin/boringssl_verify';
  if (!File(candidate).existsSync()) {
    throw StateError(
      'boringssl_verify is missing. Run tool/interop/boringssl/build.sh',
    );
  }
  await _run(candidate, env, ['${dir.path}/leaf.pem', '${dir.path}/ca.pem']);
  stdout.writeln('BoringSSL 0.20261020.0 verified the OpenSSL ML-DSA-65 leaf');
}

/// curl linked to this OpenSSL, one X25519MLKEM768 HTTPS GET, `--cacert`.
Future<void> _curlX509(String opensslBin) async {
  final curl = _curlBin(opensslBin);
  if (!File(curl).existsSync()) {
    throw StateError('curl linked to OpenSSL 3.5.9 is missing at $curl');
  }
  final dir = await Directory.systemTemp.createTemp('pq-curl-');
  final conf =
      '${Directory.current.path}/tool/interop/openssl/openssl-x509.cnf';
  final env = {
    ...Platform.environment,
    'LD_LIBRARY_PATH': _libDir(opensslBin),
    'OPENSSL_CONF': conf,
  };
  try {
    await _mintX509(opensslBin, env, dir, conf);
    final probe = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
    final port = probe.port;
    await probe.close();
    final server = await Process.start(opensslBin, [
      's_server',
      '-accept',
      '127.0.0.1:$port',
      '-tls1_3',
      '-cert',
      '${dir.path}/leaf.pem',
      '-key',
      '${dir.path}/leaf.key',
      '-groups',
      'X25519MLKEM768',
      '-ciphersuites',
      'TLS_AES_256_GCM_SHA384',
      '-www',
      '-naccept',
      '1',
    ], environment: env);
    final errBuf = StringBuffer();
    final errSub = server.stderr.transform(utf8.decoder).listen(errBuf.write);
    try {
      Object? last;
      ProcessResult? result;
      for (var i = 0; i < 50; i++) {
        result = await Process.run(curl, [
          '--cacert',
          '${dir.path}/ca.pem',
          '--curves',
          'X25519MLKEM768',
          '--tlsv1.3',
          '--tls-max',
          '1.3',
          '--tls13-ciphers',
          'TLS_AES_256_GCM_SHA384',
          '--resolve',
          'localhost:$port:127.0.0.1',
          '--max-time',
          '20',
          'https://localhost:$port/',
        ], environment: env);
        if (result.exitCode == 0) break;
        if (result.exitCode != 7) {
          throw StateError('curl --cacert failed\n${result.stderr}\n$errBuf');
        }
        last = result.stderr;
        await Future<void>.delayed(const Duration(milliseconds: 50));
      }
      if (result == null || result.exitCode != 0) {
        throw StateError('curl --cacert failed\n$last\n$errBuf');
      }
      stdout.writeln(
        'curl 8 linked to OpenSSL 3.5.9 completed X25519MLKEM768 with --cacert',
      );
    } finally {
      await errSub.cancel();
      server.kill(ProcessSignal.sigkill);
      await server.exitCode.timeout(
        const Duration(seconds: 5),
        onTimeout: () => -1,
      );
    }
  } finally {
    await dir.delete(recursive: true);
  }
}

String _curlBin(String opensslBin) {
  final built = '${File(opensslBin).parent.parent.path}/curl/bin/curl';
  if (File(built).existsSync()) return built;
  return Platform.environment['CURL_BIN'] ?? built;
}

String _opensslGroup(HybridGroup group) => switch (group) {
  HybridGroup.x25519MlKem768 => 'X25519MLKEM768',
  HybridGroup.secP256r1MlKem768 => 'SecP256r1MLKEM768',
  HybridGroup.secP384r1MlKem1024 => 'SecP384r1MLKEM1024',
};

PqTransportCrypto _cryptoFor(HybridGroup group) => switch (group) {
  HybridGroup.secP384r1MlKem1024 => const PqTransportCrypto(
    profile: PqForgeProfile.maximum,
  ),
  _ => const PqTransportCrypto(),
};

String _libDir(String bin) {
  final lib = Directory('${File(bin).parent.parent.path}/lib');
  final extra = Platform.environment['LD_LIBRARY_PATH'];
  if (!lib.existsSync()) return extra ?? '';
  return extra == null || extra.isEmpty ? lib.path : '${lib.path}:$extra';
}

Future<Socket> _connect(int port) async {
  Object? last;
  for (var i = 0; i < 50; i++) {
    try {
      return await Socket.connect(
        InternetAddress.loopbackIPv4,
        port,
        timeout: const Duration(milliseconds: 200),
      );
    } on SocketException catch (e) {
      last = e;
      await Future<void>.delayed(const Duration(milliseconds: 50));
    }
  }
  throw StateError('s_server did not accept: $last');
}

Future<void> _run(
  String bin,
  Map<String, String> env,
  List<String> args,
) async {
  final result = await Process.run(bin, args, environment: env);
  if (result.exitCode != 0) {
    throw StateError('$bin ${args.first} failed\n${result.stderr}');
  }
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
