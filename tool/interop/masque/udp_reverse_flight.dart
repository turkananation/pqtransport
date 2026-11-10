import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:pqtransport/pqtransport_io.dart';

import 'openssl_leaf.dart';

/// [PqConnectUdpTunnel] against a masque-go v0.6.0 proxy.
///
/// The proxy checks nothing about us. We check the ML-DSA-65 leaf and
/// that one context-ID-0 payload comes back from the proxy's UDP dial.
Future<void> main(List<String> args) async {
  if (args.length != 1) {
    stderr.writeln(
      'usage: dart run tool/interop/masque/udp_reverse_flight.dart <udp-proxy>',
    );
    exitCode = 64;
    return;
  }
  final proxyBin = args.single;
  const openssl = 'tool/interop/openssl/.build/bin/openssl';
  const conf = 'tool/interop/openssl/openssl.cnf';
  const lib = 'tool/interop/openssl/.build/lib';
  final leaf = await mintOpensslLeaf(openssl: openssl, conf: conf, lib: lib);
  final echo = await RawDatagramSocket.bind(InternetAddress.loopbackIPv4, 0);
  echo.listen((event) {
    if (event != RawSocketEvent.read) return;
    final packet = echo.receive();
    if (packet == null) return;
    echo.send(packet.data, packet.address, packet.port);
  });
  final process = await Process.start(proxyBin, [
    '-b',
    '127.0.0.1:0',
    '-c',
    leaf.certPath,
    '-k',
    leaf.keyPath,
  ]);
  final output = StringBuffer();
  final listening = Completer<int>();
  void note(List<int> bytes) {
    final text = utf8.decode(bytes, allowMalformed: true);
    stderr.write(text);
    output.write(text);
    if (!listening.isCompleted) {
      final match = RegExp(r'listening \S+:(\d+)').firstMatch(text);
      if (match != null) listening.complete(int.parse(match.group(1)!));
    }
  }

  process.stdout.listen(note);
  process.stderr.listen(note);
  IoDatagramChannel? channel;
  StreamSubscription<PqDatagramIn>? sub;
  QuicLossSubscription? loss;
  var ok = false;
  try {
    final port = await listening.future.timeout(const Duration(seconds: 10));
    channel = await IoDatagramChannel.bind(InternetAddress.loopbackIPv4, 0);
    final peer = PqEndpoint('127.0.0.1', port);
    final conn = PqQuicConn.client(
      alpnProtocols: const ['h3'],
      certificateTypes: const [TlsCertificateType.x509],
      trustAnchors: [leaf.caDer],
      serverName: 'localhost',
      signatureSchemes: const [tlsSignatureMldsa65],
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
    final deadline = DateTime.now().add(const Duration(seconds: 15));
    while (!conn.isComplete && DateTime.now().isBefore(deadline)) {
      await Future<void>.delayed(const Duration(milliseconds: 20));
    }
    if (!conn.isComplete ||
        !conn.peerAuthenticated ||
        conn.peerLeafAlgorithm != 'mlDsa65') {
      stderr.writeln(
        'handshake complete=${conn.isComplete} '
        'auth=${conn.peerAuthenticated} leaf=${conn.peerLeafAlgorithm} '
        'group=${conn.negotiatedGroupName} ${conn.connectionState}',
      );
      exitCode = 1;
      return;
    }
    final session = PqHttp3Session.client(conn);
    final request = connectUdpRequest(
      proxyHost: '127.0.0.1',
      proxyPort: port,
      targetHost: '127.0.0.1',
      targetPort: echo.port,
    );
    if (request.isFailure) {
      stderr.writeln('request ${request.errorOrNull}');
      exitCode = 1;
      return;
    }
    final opened = await session.beginRequest(
      request.valueOrNull!,
      fin: false,
    );
    if (opened.isFailure) {
      stderr.writeln('begin ${opened.errorOrNull}');
      exitCode = 1;
      return;
    }
    final id = opened.valueOrNull!;
    final response = await session.readResponse(id, untilFin: false);
    if (response.isFailure || response.valueOrNull!.status != 200) {
      stderr.writeln(
        'status ${response.isSuccess ? response.valueOrNull!.status : response.errorOrNull}',
      );
      exitCode = 1;
      return;
    }
    if (response.valueOrNull!.headers['capsule-protocol'] != '?1') {
      // masque-go v0.6.0 calls HTTPStream (which flushes the field
      // section) before Header.Set("Capsule-Protocol"). The header is
      // not on the wire. The tunnel is still the thing under test.
      stderr.writeln(
        'capsule-protocol absent on the wire ${response.valueOrNull!.headers}',
      );
    }
    final tunnel = PqConnectUdpTunnel(session, id);
    final sent = await tunnel.send(Uint8List.fromList('ping-reverse'.codeUnits));
    if (sent.isFailure) {
      stderr.writeln('send ${sent.errorOrNull}');
      exitCode = 1;
      return;
    }
    final until = DateTime.now().add(const Duration(seconds: 10));
    var echoed = false;
    while (DateTime.now().isBefore(until)) {
      final pumped = await session.receive();
      if (pumped.isFailure) {
        stderr.writeln('receive ${pumped.errorOrNull}');
        break;
      }
      for (final payload in tunnel.take()) {
        if (utf8.decode(payload) == 'ping-reverse') echoed = true;
      }
      if (echoed) break;
      await Future<void>.delayed(const Duration(milliseconds: 20));
    }
    final group = conn.negotiatedGroupName;
    stderr.writeln(
      'reverse-udp leaf=${conn.peerLeafAlgorithm} group=$group '
      'echoed=$echoed quicDatagrams=${session.quicHttpDatagrams}',
    );
    ok = echoed &&
        group == 'x25519MlKem768' &&
        session.quicHttpDatagrams &&
        output.toString().contains('connect-udp target=127.0.0.1:${echo.port}');
    if (!ok) exitCode = 1;
  } finally {
    process.kill();
    await sub?.cancel();
    loss?.cancel();
    await channel?.close();
    echo.close();
    await leaf.directory.delete(recursive: true);
  }
}
