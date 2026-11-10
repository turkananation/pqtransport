import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

import 'package:pqforge/pqforge.dart';
import 'package:pqtransport/pqtransport_io.dart';
import 'package:swissarmyknife/swissarmyknife.dart';

/// quiche HTTP/3 client against [PqHttp3Session] on [PqQuicConn.server].
///
/// Extended CONNECT (RFC 9220), PRIORITY_UPDATE (RFC 9218), and one
/// HTTP datagram (RFC 9297) in a QUIC DATAGRAM frame (RFC 9221).
/// A second datagram is dropped. quiche must not see it after a PTO:
/// the frame is ack-eliciting and is not retransmitted.
Future<void> main(List<String> args) async {
  if (args.length != 1) {
    stderr.writeln(
      'usage: dart run tool/interop/quiche/h3_ext_flight.dart <quiche_peer>',
    );
    exitCode = 64;
    return;
  }
  final peerBin = args.single;
  final crypto = const PqTransportCrypto();
  final minted = _mint(crypto);
  final dir = await Directory.systemTemp.createTemp('pq-quiche-h3-ext-');
  final caPath = '${dir.path}/ca.pem';
  await File(caPath).writeAsString(minted.caPem);
  final channel = await IoDatagramChannel.bind(InternetAddress.loopbackIPv4, 0);
  PqEndpoint? peer;
  final drop = [false];
  final conn = PqQuicConn.server(
    crypto: crypto,
    identity: minted.identity,
    alpnProtocols: const ['h3'],
    deliver: (packet) {
      if (drop[0]) return Future.value(const Result.success(null));
      final to = peer;
      if (to == null) {
        return Future.value(Result.failure(PqTransportError.closed('quic')));
      }
      return channel.send(packet, to);
    },
  );
  final loss = conn.bindLossTimer();
  final sub = channel.incoming.listen((datagram) {
    peer = datagram.peer;
    unawaited(() async {
      final got = await conn.ingestDatagram(datagram.data);
      if (got.isFailure) stderr.writeln('ingest ${got.errorOrNull}');
    }());
  });
  final served = _serve(conn, drop);
  final process = await Process.start(peerBin, [
    'h3-ext-client',
    '127.0.0.1:${channel.port}',
    caPath,
  ]);
  final output = StringBuffer();
  void note(List<int> bytes) {
    final text = String.fromCharCodes(bytes);
    stderr.write(text);
    output.write(text);
  }

  process.stdout.listen(note);
  process.stderr.listen(note);
  final timer = Timer(const Duration(seconds: 25), process.kill);
  final code = await process.exitCode;
  timer.cancel();
  final request = await served;
  loss.cancel();
  await sub.cancel();
  await channel.close();
  await dir.delete(recursive: true);
  final text = output.toString();
  final line = text.contains(
    'h3-ext status=200 protocol=websocket dgram=qd-pq lost=0 peer_cert=',
  );
  final retransmitted = text.contains('qd-lost');
  stderr.writeln(
    'quiche h3-ext exit $code request=$request line=$line '
    'retransmitted=$retransmitted complete=${conn.isComplete}',
  );
  if (code != 0 || !request || !line || retransmitted || !conn.isComplete) {
    exitCode = 1;
  }
}

Future<bool> _serve(PqQuicConn conn, List<bool> drop) async {
  final deadline = DateTime.now().add(const Duration(seconds: 20));
  while (!conn.isComplete && DateTime.now().isBefore(deadline)) {
    await Future<void>.delayed(const Duration(milliseconds: 20));
  }
  if (!conn.isComplete) return false;
  final session = PqHttp3Session.server(conn);
  final accepted = await session.accept(
    untilFin: false,
    timeout: const Duration(seconds: 15),
  );
  if (accepted.isFailure) {
    stderr.writeln('accept ${accepted.errorOrNull}');
    return false;
  }
  final (id, request) = accepted.valueOrNull!;
  if (request.method != 'CONNECT' ||
      request.protocol != 'websocket' ||
      request.uri.scheme != 'https' ||
      request.uri.host != 'localhost' ||
      request.uri.path != '/pq') {
    stderr.writeln(
      'unexpected ${request.method} ${request.protocol} ${request.uri}',
    );
    return false;
  }
  final wait = DateTime.now().add(const Duration(seconds: 10));
  var priorityOk = false;
  var datagramOk = false;
  while (DateTime.now().isBefore(wait)) {
    final pumped = await session.receive();
    if (pumped.isFailure) {
      stderr.writeln('receive ${pumped.errorOrNull}');
      return false;
    }
    final priority = session.priorities[id];
    priorityOk =
        priority != null && priority.urgency == 1 && priority.incremental;
    for (final (stream, payload) in session.takeHttpDatagrams()) {
      if (stream == id && String.fromCharCodes(payload) == 'qd-quiche') {
        datagramOk = true;
      }
    }
    if (priorityOk && datagramOk) break;
    await Future<void>.delayed(const Duration(milliseconds: 20));
  }
  if (!priorityOk || !datagramOk) {
    stderr.writeln('priority=$priorityOk datagram=$datagramOk');
    return false;
  }
  final sent = await session.respond(
    id,
    PqHttpResponse(
      status: 200,
      headers: const {},
      body: Uint8List(0),
      version: HttpVersion.h3,
    ),
    fin: false,
  );
  if (sent.isFailure) {
    stderr.writeln('respond ${sent.errorOrNull}');
    return false;
  }
  final echo = await session.sendHttpDatagram(
    id,
    Uint8List.fromList('qd-pq'.codeUnits),
  );
  if (echo.isFailure) {
    stderr.writeln('datagram ${echo.errorOrNull}');
    return false;
  }
  drop[0] = true;
  final lost = await session.sendHttpDatagram(
    id,
    Uint8List.fromList('qd-lost'.codeUnits),
  );
  drop[0] = false;
  if (lost.isFailure) {
    stderr.writeln('dropped datagram ${lost.errorOrNull}');
    return false;
  }
  return true;
}

({PqTlsServerIdentity identity, String caPem}) _mint(PqTransportCrypto crypto) {
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
  return (
    identity: PqTlsServerIdentity.x509(
      leafKey: leafKey,
      sign: (content) =>
          crypto.mlDsaSign(secretKey: leafKeys.secretKey, message: content),
      chain: [leaf],
      certificateDnsName: 'localhost',
    ),
    caPem: PqX509.toPem(root),
  );
}
