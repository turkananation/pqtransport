import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:pqforge/pqforge.dart';
import 'package:pqtransport/pqtransport.dart';

Future<void> main(List<String> args) async {
  if (args.length != 1) {
    stderr.writeln(
      'usage: dart run tool/interop/openssl/handshake.dart <openssl>',
    );
    exitCode = 64;
    return;
  }
  await handshakeX25519MlKem768(args.single);
  await handshakeSecP256r1MlKem768(args.single);
  await handshakeSecP384r1MlKem1024(args.single);
  stdout.writeln(
    'OpenSSL 3.5 hybrid handshakes complete '
    '(X25519MLKEM768, SecP256r1MLKEM768, SecP384r1MLKEM1024)',
  );
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

/// Completes one TLS 1.3 handshake with OpenSSL `s_server`.
///
/// Auth mode: RFC 7250 raw public key, ML-DSA-65. The server certificate
/// is an ML-DSA-65 X.509 certificate; `-enable_server_rpk` makes OpenSSL
/// send the SubjectPublicKeyInfo instead of the certificate. Suite is
/// TLS_AES_256_GCM_SHA384 (`0x1302`).
Future<void> _handshake(String opensslBin, HybridGroup group) async {
  final dir = await Directory.systemTemp.createTemp('pq-openssl-');
  final conf =
      Platform.environment['OPENSSL_CONF'] ??
      '${Directory.current.path}/tool/interop/openssl/openssl.cnf';
  final env = {
    ...Platform.environment,
    'LD_LIBRARY_PATH': _libDir(opensslBin),
    'OPENSSL_CONF': conf,
  };
  try {
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

    final probe = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
    final port = probe.port;
    await probe.close();
    final server = await Process.start(opensslBin, [
      's_server',
      '-accept',
      '127.0.0.1:$port',
      '-tls1_3',
      '-cert',
      '${dir.path}/cert.pem',
      '-key',
      '${dir.path}/key.pem',
      '-enable_server_rpk',
      '-groups',
      _opensslGroup(group),
      '-ciphersuites',
      'TLS_AES_256_GCM_SHA384',
      '-naccept',
      '1',
      '-state',
    ], environment: env);
    final errBuf = StringBuffer();
    final errSub = server.stderr.transform(utf8.decoder).listen(errBuf.write);
    final outSub = server.stdout.listen((_) {});

    final client = PqTlsClient(
      crypto: _cryptoFor(group),
      group: group,
      offeredCipherSuites: const [tlsCipherAes256GcmSha384],
    );
    Socket? socket;
    _Records? records;
    try {
      socket = await _connect(port);
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
