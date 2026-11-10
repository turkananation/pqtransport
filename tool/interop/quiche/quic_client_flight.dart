import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

import 'package:pqforge/pqforge.dart';
import 'package:pqtransport/pqtransport_io.dart';

/// [PqQuicConn.client] against a quiche server.
///
/// The leaf is minted by the pinned BoringSSL, which is also the
/// library quiche is linked to. ML-DSA-65, DNS `localhost`, checked
/// before the flight. Group X25519MLKEM768. ALPN `h3`. Not HTTP/3.
Future<void> main(List<String> args) async {
  if (args.length != 2) {
    stderr.writeln(
      'usage: dart run tool/interop/quiche/quic_client_flight.dart '
      '<boringssl_peer> <quiche_peer>',
    );
    exitCode = 64;
    return;
  }
  final boringPeer = args[0];
  final quichePeer = args[1];
  final dir = await Directory.systemTemp.createTemp('pq-quiche-client-');
  final port = await _freePort();
  Process? server;
  IoDatagramChannel? channel;
  StreamSubscription<PqDatagramIn>? sub;
  QuicLossSubscription? loss;
  try {
    final minted = await Process.run(boringPeer, ['mint', dir.path]);
    if (minted.exitCode != 0) {
      stderr.writeln(minted.stdout);
      stderr.writeln(minted.stderr);
      exitCode = 1;
      return;
    }
    final caDer = await File('${dir.path}/mldsa-ca.der').readAsBytes();
    if (!_trusts(caDer, dir.path)) {
      exitCode = 1;
      return;
    }
    server = await Process.start(quichePeer, [
      'server',
      '$port',
      '${dir.path}/mldsa-leaf.pem',
      '${dir.path}/mldsa-leaf.key',
    ]);
    var listening = false;
    var established = false;
    void note(List<int> bytes) {
      final text = String.fromCharCodes(bytes);
      stderr.write(text);
      if (text.contains('listening')) listening = true;
      if (text.contains('established')) established = true;
    }

    server.stdout.listen(note);
    server.stderr.listen(note);
    final readyAt = DateTime.now().add(const Duration(seconds: 5));
    while (!listening && DateTime.now().isBefore(readyAt)) {
      await Future<void>.delayed(const Duration(milliseconds: 20));
    }
    if (!listening) {
      stderr.writeln('quiche server did not listen');
      exitCode = 1;
      return;
    }
    channel = await IoDatagramChannel.bind(InternetAddress.loopbackIPv4, 0);
    final peer = PqEndpoint('127.0.0.1', port);
    final conn = PqQuicConn.client(
      alpnProtocols: const ['h3'],
      certificateTypes: const [TlsCertificateType.x509],
      trustAnchors: [caDer],
      serverName: 'localhost',
      deliver: (packet) => channel!.send(packet, peer),
    );
    loss = conn.bindLossTimer();
    sub = channel.incoming.listen((datagram) {
      unawaited(() async {
        final got = await conn.ingestDatagram(datagram.data);
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
    while ((!conn.isComplete || !established) &&
        DateTime.now().isBefore(deadline)) {
      await Future<void>.delayed(const Duration(milliseconds: 50));
    }
    stderr.writeln(
      'client complete=${conn.isComplete} ${conn.connectionState} '
      'alpn=${conn.alpn} quiche=$established',
    );
    if (!conn.isComplete || !established) exitCode = 1;
  } finally {
    await sub?.cancel();
    loss?.cancel();
    await channel?.close();
    server?.kill();
    await dir.delete(recursive: true);
  }
}

bool _trusts(Uint8List caDer, String dir) {
  final pem = File('$dir/mldsa-leaf.pem').readAsStringSync();
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

Future<int> _freePort() async {
  final socket = await RawDatagramSocket.bind(InternetAddress.loopbackIPv4, 0);
  final port = socket.port;
  socket.close();
  return port;
}
