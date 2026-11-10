import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

import 'package:pqforge/pqforge.dart';
import 'package:pqtransport/pqtransport_io.dart';
import 'package:swissarmyknife/swissarmyknife.dart';

/// [PqHttp3Session] client against a quiche HTTP/3 server.
///
/// The server is quiche 0.30 with extended CONNECT and QUIC DATAGRAM
/// enabled. This side sends the CONNECT, the PRIORITY_UPDATE, and
/// one HTTP datagram. A second datagram is dropped and must not
/// arrive: QUIC DATAGRAM frames are not retransmitted.
Future<void> main(List<String> args) async {
  if (args.length != 2) {
    stderr.writeln(
      'usage: dart run tool/interop/quiche/h3_ext_client_flight.dart '
      '<boringssl_peer> <quiche_peer>',
    );
    exitCode = 64;
    return;
  }
  final boringPeer = args[0];
  final quichePeer = args[1];
  final dir = await Directory.systemTemp.createTemp('pq-quiche-h3-ext-client-');
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
      'h3-ext-server',
      '$port',
      '${dir.path}/mldsa-leaf.pem',
      '${dir.path}/mldsa-leaf.key',
    ]);
    final output = StringBuffer();
    var listening = false;
    void note(List<int> bytes) {
      final text = String.fromCharCodes(bytes);
      stderr.write(text);
      output.write(text);
      if (text.contains('listening')) listening = true;
    }

    server.stdout.listen(note);
    server.stderr.listen(note);
    final readyAt = DateTime.now().add(const Duration(seconds: 5));
    while (!listening && DateTime.now().isBefore(readyAt)) {
      await Future<void>.delayed(const Duration(milliseconds: 20));
    }
    if (!listening) {
      stderr.writeln('quiche h3-ext server did not listen');
      exitCode = 1;
      return;
    }
    channel = await IoDatagramChannel.bind(InternetAddress.loopbackIPv4, 0);
    final peer = PqEndpoint('127.0.0.1', port);
    final drop = [false];
    final conn = PqQuicConn.client(
      alpnProtocols: const ['h3'],
      certificateTypes: const [TlsCertificateType.x509],
      trustAnchors: [caDer],
      serverName: 'localhost',
      deliver: (packet) {
        if (drop[0]) return Future.value(const Result.success(null));
        return channel!.send(packet, peer);
      },
    );
    loss = conn.bindLossTimer();
    sub = channel.incoming.listen((datagram) {
      unawaited(conn.ingestDatagram(datagram.data));
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
    if (!conn.isComplete) {
      stderr.writeln('client handshake failed ${conn.connectionState}');
      exitCode = 1;
      return;
    }
    final session = PqHttp3Session.client(conn);
    final opened = await session.beginRequest(
      PqHttpRequest(
        method: 'CONNECT',
        uri: Uri.parse('https://localhost/pq'),
        protocol: 'websocket',
      ),
      fin: false,
    );
    if (opened.isFailure) {
      stderr.writeln('connect ${opened.errorOrNull}');
      exitCode = 1;
      return;
    }
    final id = opened.valueOrNull!;
    if (!session.peerExtendedConnect || !session.peerHttpDatagrams) {
      stderr.writeln(
        'settings connect=${session.peerExtendedConnect} '
        'datagram=${session.peerHttpDatagrams}',
      );
      exitCode = 1;
      return;
    }
    final priority = await session.updatePriority(
      id,
      urgency: 1,
      incremental: true,
    );
    if (priority.isFailure) {
      stderr.writeln('priority ${priority.errorOrNull}');
      exitCode = 1;
      return;
    }
    final datagram = await session.sendHttpDatagram(
      id,
      Uint8List.fromList('qd-pq'.codeUnits),
    );
    if (datagram.isFailure) {
      stderr.writeln('datagram ${datagram.errorOrNull}');
      exitCode = 1;
      return;
    }
    final response = await session.readResponse(
      id,
      untilFin: false,
      timeout: const Duration(seconds: 10),
    );
    final wait = DateTime.now().add(const Duration(seconds: 10));
    var echo = false;
    while (DateTime.now().isBefore(wait)) {
      final pumped = await session.receive();
      if (pumped.isFailure) {
        stderr.writeln('receive ${pumped.errorOrNull}');
        exitCode = 1;
        return;
      }
      for (final (stream, payload) in session.takeHttpDatagrams()) {
        if (stream == id && String.fromCharCodes(payload) == 'qd-quiche') {
          echo = true;
        }
      }
      if (echo && response.isSuccess) break;
      await Future<void>.delayed(const Duration(milliseconds: 20));
    }
    drop[0] = true;
    final lost = await session.sendHttpDatagram(
      id,
      Uint8List.fromList('qd-lost'.codeUnits),
    );
    drop[0] = false;
    if (lost.isFailure) {
      stderr.writeln('dropped datagram ${lost.errorOrNull}');
      exitCode = 1;
      return;
    }
    final code = await server.exitCode.timeout(
      const Duration(seconds: 15),
      onTimeout: () => -1,
    );
    final text = output.toString();
    final sawRequest = text.contains(
      'h3-ext request method=CONNECT protocol=websocket path=/pq',
    );
    final sawPriority = text.contains('priority=u=1, i');
    final sawDatagram = text.contains('dgram=qd-pq');
    final retransmitted = text.contains('qd-lost');
    stderr.writeln(
      'h3-ext ${response.isSuccess ? response.valueOrNull!.status : response.errorOrNull} '
      'echo=$echo quiche=$code request=$sawRequest priority=$sawPriority '
      'dgram=$sawDatagram retransmitted=$retransmitted',
    );
    if (response.isFailure ||
        response.valueOrNull!.status != 200 ||
        !echo ||
        code != 0 ||
        !sawRequest ||
        !sawPriority ||
        !sawDatagram ||
        retransmitted) {
      exitCode = 1;
    }
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
