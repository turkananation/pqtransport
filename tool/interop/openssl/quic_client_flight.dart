import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

import 'package:pqforge/pqforge.dart';
import 'package:pqtransport/pqtransport_io.dart';

/// [PqQuicConn.client] against OpenSSL `demos/quic/server`.
///
/// That demo is not `s_server` (`s_server` has no `-quic`). Its ALPN is
/// `ossltest`. The certificate is an ML-DSA-65 leaf for DNS `localhost`,
/// minted by this OpenSSL binary and checked. Not HTTP/3.
Future<void> main(List<String> args) async {
  if (args.length != 2) {
    stderr.writeln(
      'usage: dart run tool/interop/openssl/quic_client_flight.dart '
      '<openssl> <demos/quic/server>',
    );
    exitCode = 64;
    return;
  }
  final openssl = args[0];
  final serverBin = args[1];
  final env = _env(openssl);
  final dir = await Directory.systemTemp.createTemp('pq-quic-client-');
  final port = await _freePort();
  Process? server;
  IoDatagramChannel? channel;
  StreamSubscription<PqDatagramIn>? sub;
  QuicLossSubscription? loss;
  try {
    await _mint(openssl, dir.path, env);
    final caDer = await File('${dir.path}/ca.der').readAsBytes();
    if (!_trusts(caDer, dir.path)) {
      exitCode = 1;
      return;
    }
    server = await Process.start(serverBin, [
      '$port',
      '${dir.path}/leaf.pem',
      '${dir.path}/leaf.key',
    ], environment: env);
    server.stdout.listen((bytes) => stderr.write(String.fromCharCodes(bytes)));
    server.stderr.listen((bytes) => stderr.write(String.fromCharCodes(bytes)));
    final serverExit = server.exitCode;
    unawaited(
      serverExit.then((code) {
        stderr.writeln('openssl-quic-server exit $code');
      }),
    );
    await Future<void>.delayed(const Duration(milliseconds: 200));
    channel = await IoDatagramChannel.bind(InternetAddress.loopbackIPv4, 0);
    final peer = PqEndpoint('127.0.0.1', port);
    final conn = PqQuicConn.client(
      alpnProtocols: const ['ossltest'],
      certificateTypes: const [TlsCertificateType.x509],
      trustAnchors: [caDer],
      serverName: 'localhost',
      deliver: (packet) {
        final first = packet.isEmpty ? 0 : packet[0];
        stderr.writeln(
          'send ${packet.length} first=0x${first.toRadixString(16)} '
          'head=${_hex(packet, 24)}',
        );
        return channel!.send(packet, peer);
      },
    );
    loss = conn.bindLossTimer();
    sub = channel.incoming.listen((datagram) {
      final wire = datagram.data;
      final first = wire.isEmpty ? 0 : wire[0];
      stderr.writeln(
        'udp ${wire.length} first=0x${first.toRadixString(16)} '
        'from ${datagram.peer.port} head=${_hex(wire, 24)}',
      );
      unawaited(() async {
        final got = await conn.ingestDatagram(wire);
        stderr.writeln(
          got.isFailure
              ? 'ingest ${got.errorOrNull}'
              : 'ingest ok complete=${conn.isComplete} ${conn.connectionState}',
        );
      }());
    });
    final started = await conn.start();
    if (started.isFailure) {
      stderr.writeln('start ${started.errorOrNull}');
      exitCode = 1;
      return;
    }
    final deadline = DateTime.now().add(const Duration(seconds: 20));
    while (!conn.isComplete && DateTime.now().isBefore(deadline)) {
      await Future<void>.delayed(const Duration(milliseconds: 50));
    }
    if (conn.isComplete) {
      await Future<void>.delayed(const Duration(seconds: 2));
    }
    final handshakeOk = conn.isComplete;
    stderr.writeln(
      'client complete=${conn.isComplete} ${conn.connectionState} '
      'alpn=${conn.alpn}',
    );
    if (!handshakeOk) exitCode = 1;
  } finally {
    await sub?.cancel();
    loss?.cancel();
    await channel?.close();
    server?.kill();
    await dir.delete(recursive: true);
  }
}

bool _trusts(Uint8List caDer, String dir) {
  final pem = File('$dir/leaf.pem').readAsStringSync();
  final blocks = PqX509.pemBlocks(pem);
  if (blocks.isEmpty) {
    stderr.writeln('leaf pem has no certificate');
    return false;
  }
  final leaf = PqX509.parse(blocks.first.der);
  final certificate = leaf.certificate;
  if (certificate == null) {
    stderr.writeln('leaf parse ${leaf.failure}');
    return false;
  }
  final path = PqX509.validate(
    chain: [blocks.first.der],
    anchors: [caDer],
    now: DateTime.now().toUtc(),
  );
  stderr.writeln(
    'leaf ${certificate.algorithm.name} '
    'ku=${certificate.keyUsageBits} ca=${certificate.ca} '
    'san=${certificate.subjectAltNames.length} '
    'trusted=${path.trusted} ${path.failure ?? ''}',
  );
  return path.trusted &&
      certificate.algorithm == PqX509Algorithm.mlDsa65 &&
      certificate.subjectAltNames.any(
        (name) =>
            name is PqX509DnsName && name.ascii.toLowerCase() == 'localhost',
      );
}

Future<void> _mint(String openssl, String dir, Map<String, String> env) async {
  await _openssl(openssl, [
    'req',
    '-x509',
    '-newkey',
    'ML-DSA-65',
    '-keyout',
    '$dir/ca.key',
    '-out',
    '$dir/ca.pem',
    '-days',
    '2',
    '-nodes',
    '-subj',
    '/CN=pqtransport-ca',
    '-addext',
    'basicConstraints=critical,CA:TRUE',
    '-addext',
    'keyUsage=critical,keyCertSign,cRLSign',
  ], env);
  await _openssl(openssl, [
    'req',
    '-newkey',
    'ML-DSA-65',
    '-keyout',
    '$dir/leaf.key',
    '-out',
    '$dir/leaf.csr',
    '-nodes',
    '-subj',
    '/CN=localhost',
    '-addext',
    'subjectAltName=DNS:localhost',
    '-addext',
    'keyUsage=critical,digitalSignature',
    '-addext',
    'extendedKeyUsage=serverAuth',
    '-addext',
    'basicConstraints=CA:FALSE',
  ], env);
  await _openssl(openssl, [
    'x509',
    '-req',
    '-in',
    '$dir/leaf.csr',
    '-CA',
    '$dir/ca.pem',
    '-CAkey',
    '$dir/ca.key',
    '-CAcreateserial',
    '-out',
    '$dir/leaf.pem',
    '-days',
    '2',
    '-copy_extensions',
    'copy',
  ], env);
  await _openssl(openssl, [
    'x509',
    '-in',
    '$dir/ca.pem',
    '-outform',
    'DER',
    '-out',
    '$dir/ca.der',
  ], env);
}

Future<void> _openssl(
  String openssl,
  List<String> args,
  Map<String, String> env,
) async {
  final result = await Process.run(openssl, args, environment: env);
  if (result.exitCode != 0) {
    stderr.writeln(result.stdout);
    stderr.writeln(result.stderr);
    throw StateError('openssl ${args.first} exit ${result.exitCode}');
  }
}

Future<int> _freePort() async {
  final socket = await RawDatagramSocket.bind(InternetAddress.loopbackIPv4, 0);
  final port = socket.port;
  socket.close();
  return port;
}

Map<String, String> _env(String openssl) {
  final conf = File.fromUri(
    Platform.script.resolve('openssl.cnf'),
  ).absolute.path;
  return {
    ...Platform.environment,
    'LD_LIBRARY_PATH': _libDir(openssl),
    'OPENSSL_CONF': conf,
  };
}

String _libDir(String opensslBin) {
  final bin = File(opensslBin).absolute.path;
  return '${bin.substring(0, bin.lastIndexOf('/bin/'))}/lib';
}

String _hex(Uint8List bytes, int n) {
  final end = bytes.length < n ? bytes.length : n;
  return [
    for (var i = 0; i < end; i++) bytes[i].toRadixString(16).padLeft(2, '0'),
  ].join();
}
