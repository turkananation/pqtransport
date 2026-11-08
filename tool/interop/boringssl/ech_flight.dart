import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:pqforge/pqforge.dart';
import 'package:pqtransport/pqtransport_io.dart';

/// BoringSSL 0.20261020.0 ECH, both directions, on X25519MLKEM768.
/// Not OpenSSL. Not a browser. Not DNS. Rejection sends ech_required
/// and no second ClientHello.
Future<void> boringsslEchFlights(String peer) async {
  final bssl = '${File(peer).parent.path}/bssl';
  if (!File(bssl).existsSync()) {
    throw StateError('bssl is missing at $bssl');
  }
  final dir = await Directory.systemTemp.createTemp('pq-bssl-ech-');
  try {
    await _run(peer, ['mint', dir.path]);
    await _run(bssl, [
      'generate-ech',
      '-out-ech-config-list',
      '${dir.path}/ech-list.bin',
      '-out-ech-config',
      '${dir.path}/ech-config.bin',
      '-out-private-key',
      '${dir.path}/ech.key',
      '-public-name',
      'public.example',
      '-config-id',
      '1',
      '-max-name-length',
      '64',
    ]);
    final configBytes = await File('${dir.path}/ech-config.bin').readAsBytes();
    final parsed = EchConfig.parse(configBytes);
    if (parsed.isFailure) {
      throw StateError('ech config: ${parsed.errorOrNull}');
    }
    final config = parsed.valueOrNull!;
    if (config.publicName != 'public.example') {
      throw StateError('public name ${config.publicName}');
    }
    final ca = await File('${dir.path}/mldsa-ca.der').readAsBytes();
    await _clientAccepts(bssl, dir.path, config: config, trustAnchors: [ca]);
    await _clientRejects(bssl, dir.path, config: config, trustAnchors: [ca]);
    await _serverAccepts(bssl, dir.path);
    stdout.writeln(
      'BoringSSL 0.20261020.0 ECH complete, both directions, '
      'X25519MLKEM768, TLS_AES_256_GCM_SHA384, ML-DSA-65 chain length 1. '
      'Inner name localhost. Public name public.example. '
      'A server without the key gets ech_required and no second '
      'ClientHello. Not OpenSSL. Not a browser. Not DNS. Not WebPKI.',
    );
  } finally {
    try {
      await dir.delete(recursive: true).timeout(const Duration(seconds: 5));
    } on Object {
      // The flight already finished. A stuck temp dir must not hang CI.
    }
  }
}

Future<void> _clientAccepts(
  String bssl,
  String dir, {
  required EchConfig config,
  required List<Uint8List> trustAnchors,
}) async {
  final text = await _withServer(
    bssl,
    dir,
    ech: true,
    body: (socket) async {
      final client = _client(config: config, trustAnchors: trustAnchors);
      final records = _Records(socket);
      try {
        final hello = await client.startHandshake();
        if (hello.isFailure) {
          throw StateError('start: ${hello.errorOrNull}');
        }
        final wire = hello.valueOrNull!;
        if (!latin1
            .decode(wire, allowInvalid: true)
            .contains('public.example')) {
          throw StateError('outer hello has no public name');
        }
        if (latin1.decode(wire, allowInvalid: true).contains('localhost')) {
          throw StateError('inner name is on the wire');
        }
        socket.add(wire);
        await socket.flush();
        while (!client.isComplete) {
          final rec = await records.next();
          if (rec == null) throw StateError('closed before Finished');
          final out = await client.ingest(rec);
          if (out.isFailure) throw StateError('ingest: ${out.errorOrNull}');
          for (final flight in out.valueOrNull!) {
            if (_isClientHello(flight)) {
              throw StateError('second ClientHello');
            }
            socket.add(flight);
          }
          await socket.flush();
        }
        if (!client.peerAuthenticated) {
          throw StateError('finished without CertificateVerify');
        }
        if (client.negotiatedGroup != TlsNamedGroup.x25519MlKem768) {
          throw StateError('group ${client.negotiatedGroup}');
        }
        if (client.helloRetryCount != 0) {
          throw StateError('hello retry under ech');
        }
      } finally {
        await records.close();
      }
    },
  );
  if (!text.contains('Encrypted ClientHello: yes')) {
    throw StateError('BoringSSL did not accept ECH\n$text');
  }
  if (!text.contains('Client sent SNI: localhost')) {
    throw StateError('BoringSSL did not see the inner name\n$text');
  }
  if (text.contains('Client sent SNI: public.example')) {
    throw StateError('BoringSSL accepted the public name\n$text');
  }
}

Future<void> _clientRejects(
  String bssl,
  String dir, {
  required EchConfig config,
  required List<Uint8List> trustAnchors,
}) async {
  final wrong = await EchServerConfig.generate(
    const PqTransportCrypto(),
    publicName: 'public.example',
    configId: config.configId,
    maximumNameLength: config.maximumNameLength,
  );
  await _withServer(
    bssl,
    dir,
    ech: false,
    body: (socket) async {
      final client = _client(config: wrong.config, trustAnchors: trustAnchors);
      final records = _Records(socket);
      try {
        final hello = await client.startHandshake();
        if (hello.isFailure) throw StateError('start: ${hello.errorOrNull}');
        final sent = <Uint8List>[hello.valueOrNull!];
        socket.add(sent.single);
        await socket.flush();
        while (true) {
          final rec = await records.next();
          if (rec == null) break;
          final out = await client.ingest(rec);
          if (out.isFailure) {
            final error = out.errorOrNull!;
            if (error.alert != tlsAlertEchRequired) {
              throw StateError('reject alert ${error.alert}: $error');
            }
            final alert = client.certificateAlert(error);
            if (alert == null) throw StateError('no ech_required alert');
            sent.add(alert);
            socket.add(alert);
            await socket.flush();
            break;
          }
          for (final flight in out.valueOrNull!) {
            sent.add(flight);
            socket.add(flight);
          }
          await socket.flush();
          if (client.isComplete) break;
        }
        if (client.isComplete || client.peerAuthenticated) {
          throw StateError('rejection completed the handshake');
        }
        if (client.state != TlsState.failed) {
          throw StateError('state ${client.state}');
        }
        final hellos = sent.where(_isClientHello).length;
        if (hellos != 1) throw StateError('$hellos ClientHellos');
      } finally {
        await records.close();
      }
    },
  );
}

Future<void> _serverAccepts(String bssl, String dir) async {
  final crypto = const PqTransportCrypto();
  final ech = await EchServerConfig.generate(
    crypto,
    publicName: 'public.example',
    maximumNameLength: 64,
  );
  await File('$dir/our-ech-list.bin').writeAsBytes(ech.config.encodeList());
  final minted = _mintMlDsa(crypto);
  await File('$dir/our-ca.pem').writeAsString(minted.caPem);
  final bound = await IoTcpServer.bind(InternetAddress.loopbackIPv4, 0);
  final port = bound.port;
  final serveError = _serve(bound, minted.identity, ech);
  final result = await Process.run(bssl, [
    's_client',
    '-connect',
    '127.0.0.1:$port',
    '-server-name',
    'localhost',
    '-ech-config-list',
    '$dir/our-ech-list.bin',
    '-root-certs',
    '$dir/our-ca.pem',
    '-curves',
    'X25519MLKEM768',
    '-sigalgs',
    'mldsa65',
    '-alpn-protos',
    'http/1.1',
  ]);
  final failure = await serveError.timeout(const Duration(seconds: 20));
  final text = '${result.stdout}\n${result.stderr}\n$failure';
  if (result.exitCode != 0 || failure != null) {
    throw StateError(
      'BoringSSL client ECH failed (${result.exitCode}) $failure\n$text',
    );
  }
  if (!text.contains('Encrypted ClientHello: yes')) {
    throw StateError('BoringSSL client did not accept ECH\n$text');
  }
}

PqTlsClient _client({
  required EchConfig config,
  required List<Uint8List> trustAnchors,
}) {
  return PqTlsClient(
    onlyShares: const [TlsNamedGroup.x25519MlKem768],
    offeredCipherSuites: const [tlsCipherAes256GcmSha384],
    certificateTypes: const [TlsCertificateType.x509],
    trustAnchors: trustAnchors,
    serverName: 'localhost',
    ech: config,
  );
}

Future<String> _withServer(
  String bssl,
  String dir, {
  required bool ech,
  required Future<void> Function(Socket socket) body,
}) async {
  final probe = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
  final port = probe.port;
  await probe.close();
  final args = [
    's_server',
    '-accept',
    '$port',
    '-cert',
    '$dir/mldsa-leaf.pem',
    '-key',
    '$dir/mldsa-leaf.key',
    '-curves',
    'X25519MLKEM768',
  ];
  if (ech) {
    args.addAll([
      '-ech-config',
      '$dir/ech-config.bin',
      '-ech-key',
      '$dir/ech.key',
    ]);
  }
  final server = await Process.start(bssl, args);
  final err = StringBuffer();
  final out = StringBuffer();
  final errSub = server.stderr.transform(utf8.decoder).listen(err.write);
  final outSub = server.stdout.transform(utf8.decoder).listen(out.write);
  try {
    final socket = await _connect(port, () => '$out\n$err');
    try {
      await body(socket);
    } finally {
      socket.destroy();
    }
    await server.exitCode.timeout(const Duration(seconds: 5));
    await Future<void>.delayed(const Duration(milliseconds: 20));
    return '$out\n$err';
  } finally {
    await errSub.cancel();
    await outSub.cancel();
    server.kill(ProcessSignal.sigkill);
    await server.exitCode.timeout(
      const Duration(seconds: 5),
      onTimeout: () => -1,
    );
  }
}

Future<String?> _serve(
  IoTcpServer bound,
  PqTlsServerIdentity identity,
  EchServerConfig ech,
) async {
  try {
    final raw = await bound.connections.first.timeout(
      const Duration(seconds: 15),
    );
    final tls = PqTlsSocket.server(raw, identity: identity, ech: ech);
    try {
      final hs = await tls.handshake(timeout: const Duration(seconds: 20));
      if (hs.isFailure) return 'PqTlsSocket: ${hs.errorOrNull}';
      if (tls.negotiatedGroup != TlsNamedGroup.x25519MlKem768) {
        return 'negotiated ${tls.negotiatedGroup}';
      }
    } finally {
      await tls.close();
    }
  } on Object catch (e) {
    return '$e';
  } finally {
    await bound.close();
  }
  return null;
}

bool _isClientHello(Uint8List record) {
  if (record.length < tlsRecordHeaderBytes + 4) return false;
  if (record[0] != tlsContentHandshake) return false;
  return record[tlsRecordHeaderBytes] == tlsHsClientHello;
}

Future<void> _run(String bin, List<String> args) async {
  final result = await Process.run(bin, args);
  if (result.exitCode != 0) {
    throw StateError('$bin ${args.join(' ')} failed\n${result.stderr}');
  }
}

Future<Socket> _connect(int port, [String Function()? detail]) async {
  Object? last;
  for (var i = 0; i < 50; i++) {
    try {
      return await Socket.connect(InternetAddress.loopbackIPv4, port);
    } on SocketException catch (e) {
      last = e;
      await Future<void>.delayed(const Duration(milliseconds: 50));
    }
  }
  final extra = detail == null ? '' : '\n${detail()}';
  throw StateError('BoringSSL did not accept: $last$extra');
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
