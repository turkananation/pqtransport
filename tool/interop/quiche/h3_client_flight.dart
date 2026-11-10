import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

import 'package:pqforge/pqforge.dart';
import 'package:pqtransport/pqtransport_io.dart';

/// [PqHttp3Session] client against a quiche HTTP/3 server.
///
/// The leaf is minted by the pinned BoringSSL. ML-DSA-65, DNS
/// `localhost`, checked before the flight and by the QUIC client.
/// The response body is `quiche-h3`.
Future<void> main(List<String> args) async {
  if (args.length != 2) {
    stderr.writeln(
      'usage: dart run tool/interop/quiche/h3_client_flight.dart '
      '<boringssl_peer> <quiche_peer>',
    );
    exitCode = 64;
    return;
  }
  final boringPeer = args[0];
  final quichePeer = args[1];
  final dir = await Directory.systemTemp.createTemp('pq-quiche-h3-client-');
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
      'h3-server',
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
      stderr.writeln('quiche h3 server did not listen');
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
    final response = await session.request(
      PqHttpRequest(
        method: 'GET',
        uri: Uri.parse('https://localhost/pq'),
        headers: const {'x-pq': 'interop'},
      ),
    );
    final body = response.valueOrNull == null
        ? ''
        : String.fromCharCodes(response.valueOrNull!.body);
    final sawRequest = output.toString().contains(
      'h3 request method=GET path=/pq',
    );
    stderr.writeln(
      'h3 ${response.isSuccess ? response.valueOrNull!.status : response.errorOrNull} '
      'body=$body quiche=$sawRequest',
    );
    if (response.isFailure ||
        response.valueOrNull!.status != 200 ||
        body != 'quiche-h3' ||
        !sawRequest) {
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
