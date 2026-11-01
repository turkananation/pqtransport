import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:pqforge/pqforge.dart';
import 'package:pqtransport/pqtransport_io.dart';

Future<void> main(List<String> args) async {
  if (args.length != 1) {
    stderr.writeln(
      'usage: dart run tool/interop/openssl/fallback_flight.dart <openssl>',
    );
    exitCode = 64;
    return;
  }
  await handshakeClassicalFallback(args.single);
  exit(0);
}

/// Groups a peer can force when it will not speak the hybrid.
///
/// The default client still sends X25519MLKEM768 and then X25519.
/// `x25519:secp256r1` therefore finishes on X25519 with no retry.
/// A server that allows only P-256, P-384, or MLKEM1024 must
/// HelloRetryRequest, because those shares are advertised and not sent.
/// The reverse rows are `s_client -groups` against [PqTlsSocket].
/// Auth is ML-DSA-65, chain length 1, caller CA. Not a browser.
Future<void> handshakeClassicalFallback(String opensslBin) async {
  final env = <String, String>{
    ...Platform.environment,
    'LD_LIBRARY_PATH': _libDir(opensslBin),
    'OPENSSL_CONF':
        '${Directory.current.path}/tool/interop/openssl/openssl-x509.cnf',
  };
  await _client(
    opensslBin,
    env,
    groups: 'x25519:secp256r1',
    expect: TlsNamedGroup.x25519,
    helloRetry: false,
  );
  await _client(
    opensslBin,
    env,
    groups: 'secp256r1',
    expect: TlsNamedGroup.secp256r1,
    helloRetry: true,
  );
  await _client(
    opensslBin,
    env,
    groups: 'secp384r1',
    expect: TlsNamedGroup.secp384r1,
    helloRetry: true,
  );
  await _client(
    opensslBin,
    env,
    groups: 'MLKEM1024',
    expect: TlsNamedGroup.mlKem1024,
    helloRetry: true,
  );
  await _server(
    opensslBin,
    env,
    groups: 'x25519:secp256r1',
    expect: TlsNamedGroup.x25519,
  );
  await _server(
    opensslBin,
    env,
    groups: 'secp256r1',
    expect: TlsNamedGroup.secp256r1,
  );
  await _server(
    opensslBin,
    env,
    groups: 'secp384r1',
    expect: TlsNamedGroup.secp384r1,
  );
  await _server(
    opensslBin,
    env,
    groups: 'MLKEM1024',
    expect: TlsNamedGroup.mlKem1024,
  );
  stdout.writeln(
    'OpenSSL 3.5.9 classical and pure ML-KEM-1024 complete. '
    'X25519, secp256r1, secp384r1, and MLKEM1024, both directions, '
    'ML-DSA-65 chain length 1. Hybrid stayed first: the default client '
    'finished X25519 only when the peer disabled the hybrid. '
    'Not TLS 1.2. Not MLKEM512. Not MLKEM768. Not a browser. Not WebPKI.',
  );
}

Future<void> _client(
  String opensslBin,
  Map<String, String> env, {
  required String groups,
  required TlsNamedGroup expect,
  required bool helloRetry,
}) async {
  stdout.writeln('s_server -groups $groups');
  final dir = await Directory.systemTemp.createTemp('pq-fallback-');
  final conf = env['OPENSSL_CONF']!;
  try {
    final anchor = await _mintLeaf(opensslBin, env, dir, conf);
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
      groups,
      '-ciphersuites',
      'TLS_AES_256_GCM_SHA384',
      '-state',
    ], environment: env);
    final errBuf = StringBuffer();
    final outBuf = StringBuffer();
    final errSub = server.stderr.transform(utf8.decoder).listen(errBuf.write);
    final outSub = server.stdout.transform(utf8.decoder).listen(outBuf.write);
    Socket? socket;
    _Records? records;
    try {
      socket = await _connect(port);
      records = _Records(socket);
      final client = PqTlsClient(
        group: HybridGroup.x25519MlKem768,
        offeredCipherSuites: const [tlsCipherAes256GcmSha384],
        certificateTypes: const [TlsCertificateType.x509],
        trustAnchors: [anchor],
        serverName: 'localhost',
      );
      final hello = await client.startHandshake();
      if (hello.isFailure) {
        throw StateError('$groups start: ${hello.errorOrNull}\n$errBuf');
      }
      socket.add(hello.valueOrNull!);
      await socket.flush();
      while (!client.isComplete) {
        final rec = await records.next();
        if (rec == null) {
          throw StateError('$groups closed before Finished\n$errBuf');
        }
        final out = await client.ingest(rec);
        if (out.isFailure) {
          throw StateError('$groups ingest: ${out.errorOrNull}\n$errBuf');
        }
        for (final flight in out.valueOrNull!) {
          socket.add(flight);
        }
        await socket.flush();
      }
      if (!client.peerAuthenticated) {
        throw StateError('$groups finished without CertificateVerify\n$errBuf');
      }
      if (client.negotiatedGroup != expect) {
        throw StateError(
          '$groups negotiated ${client.negotiatedGroup} wanted $expect\n$errBuf',
        );
      }
      final retries = helloRetry ? 1 : 0;
      if (client.helloRetryCount != retries) {
        throw StateError(
          '$groups helloRetryCount ${client.helloRetryCount} '
          'wanted $retries\n$errBuf',
        );
      }
      if (client.cipherSuite != TlsCipherSuite.aes256GcmSha384) {
        throw StateError('$groups suite ${client.cipherSuite}');
      }
      final deadline = DateTime.now().add(const Duration(seconds: 5));
      while (!errBuf.toString().contains('read finished') &&
          DateTime.now().isBefore(deadline)) {
        await Future<void>.delayed(const Duration(milliseconds: 20));
      }
      if (!errBuf.toString().contains('read finished')) {
        throw StateError('$groups did not accept Finished:\n$errBuf');
      }
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

Future<void> _server(
  String opensslBin,
  Map<String, String> env, {
  required String groups,
  required TlsNamedGroup expect,
}) async {
  stdout.writeln('s_client -groups $groups');
  final minted = _mintMlDsa(const PqTransportCrypto());
  final dir = await Directory.systemTemp.createTemp('pq-fallback-sclient-');
  try {
    final caPath = '${dir.path}/ca.pem';
    await File(caPath).writeAsString(minted.caPem);
    final bound = await IoTcpServer.bind(InternetAddress.loopbackIPv4, 0);
    final port = bound.port;
    TlsNamedGroup? got;
    Object? serveError;
    final serve =
        () async {
          final raw = await bound.connections.first.timeout(
            const Duration(seconds: 15),
          );
          final tls = PqTlsSocket.server(
            raw,
            identity: minted.identity,
            group: HybridGroup.x25519MlKem768,
            alpnProtocols: const [httpAlpnH1],
          );
          try {
            final hs = await tls.handshake(
              timeout: const Duration(seconds: 20),
            );
            got = tls.negotiatedGroup;
            if (hs.isFailure) {
              throw StateError('PqTlsSocket: ${hs.errorOrNull}');
            }
          } finally {
            await tls.close();
            await bound.close();
          }
        }().catchError((Object e) {
          serveError = e;
        });
    final result = await Process.run(opensslBin, [
      's_client',
      '-connect',
      '127.0.0.1:$port',
      '-servername',
      'localhost',
      '-verify_hostname',
      'localhost',
      '-tls1_3',
      '-CAfile',
      caPath,
      '-no-CAfile',
      '-no-CApath',
      '-verify',
      '1',
      '-verify_return_error',
      '-ciphersuites',
      'TLS_AES_256_GCM_SHA384',
      '-sigalgs',
      'mldsa65',
      '-groups',
      groups,
      '-ign_eof',
    ], environment: env);
    try {
      await serve.timeout(const Duration(seconds: 8));
    } on Object catch (e) {
      serveError ??= e;
    }
    final text = '${result.stdout}\n${result.stderr}';
    if (result.exitCode != 0 || serveError != null) {
      throw StateError(
        '$groups s_client failed (${result.exitCode}) serve=$serveError\n$text',
      );
    }
    if (!text.contains('Verify return code: 0')) {
      throw StateError('$groups verify failed\n$text');
    }
    if (got != expect) {
      throw StateError('$groups negotiated $got wanted $expect\n$text');
    }
    final temp = RegExp(r'Peer Temp Key:\s*([^\n]+)').firstMatch(text);
    final negotiated = RegExp(
      r'Negotiated TLS1\.3 group:\s*(\S+)',
    ).firstMatch(text);
    final shown = '${temp?.group(1) ?? ''} ${negotiated?.group(1) ?? ''}'
        .toLowerCase();
    final peerOk = switch (expect) {
      TlsNamedGroup.x25519 =>
        shown.contains('x25519') && !shown.contains('mlkem'),
      TlsNamedGroup.secp256r1 =>
        shown.contains('prime256v1') || shown.contains('secp256r1'),
      TlsNamedGroup.secp384r1 => shown.contains('secp384r1'),
      TlsNamedGroup.mlKem1024 => shown.contains('mlkem1024'),
      _ => false,
    };
    if (!peerOk) {
      throw StateError('$groups peer temp key "$shown" wanted $expect\n$text');
    }
  } finally {
    await dir.delete(recursive: true);
  }
}

Future<Uint8List> _mintLeaf(
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
  return File('${dir.path}/ca.der').readAsBytes();
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
  final root = PqX509.mint(
    issuer: rootName,
    subject: rootName,
    publicKey: PqX509MlDsaKey(PqX509Algorithm.mlDsa65, rootKeys.publicKey),
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
  final leaf = PqX509.mint(
    issuer: rootName,
    subject: PqX509Name.commonName('localhost'),
    publicKey: PqX509MlDsaKey(PqX509Algorithm.mlDsa65, leafKeys.publicKey),
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
      leafKey: PqX509MlDsaKey(PqX509Algorithm.mlDsa65, leafKeys.publicKey),
      sign: (content) =>
          crypto.mlDsaSign(secretKey: leafKeys.secretKey, message: content),
      chain: [leaf],
      certificateDnsName: 'localhost',
    ),
    PqX509.toPem(root),
  );
}

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
      if (!await _it.moveNext().timeout(const Duration(seconds: 20))) {
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
