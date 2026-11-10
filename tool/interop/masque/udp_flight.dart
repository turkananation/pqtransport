import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

import 'package:pqforge/pqforge.dart';
import 'package:pqtransport/pqtransport.dart';
import 'package:pqtransport/pqtransport_io.dart';
import 'package:swissarmyknife/swissarmyknife.dart';

/// masque-go CONNECT-UDP client against [PqHttp3Session].
///
/// The proxy forwards one context-ID-0 UDP payload to a local echo
/// and returns the echo. masque-go checks the ML-DSA-65 leaf.
Future<void> main(List<String> args) async {
  if (args.length != 1) {
    stderr.writeln(
      'usage: dart run tool/interop/masque/udp_flight.dart <udp-client>',
    );
    exitCode = 64;
    return;
  }
  final clientBin = args.single;
  final crypto = const PqTransportCrypto();
  final minted = _mint(crypto);
  final dir = await Directory.systemTemp.createTemp('pq-masque-udp-');
  final caPath = '${dir.path}/ca.pem';
  await File(caPath).writeAsString(minted.caPem);
  final echo = await RawDatagramSocket.bind(InternetAddress.loopbackIPv4, 0);
  echo.listen((event) {
    if (event != RawSocketEvent.read) return;
    final packet = echo.receive();
    if (packet == null) return;
    echo.send(packet.data, packet.address, packet.port);
  });
  final channel = await IoDatagramChannel.bind(InternetAddress.loopbackIPv4, 0);
  PqEndpoint? peer;
  final conn = PqQuicConn.server(
    crypto: crypto,
    identity: minted.identity,
    alpnProtocols: const ['h3'],
    deliver: (packet) {
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
  final served = _serve(conn, echo.port);
  final process = await Process.start(clientBin, [
    '-proxy',
    '127.0.0.1:${channel.port}',
    '-ca',
    caPath,
    '-target',
    '127.0.0.1:${echo.port}',
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
  final forwarded = await served;
  loss.cancel();
  await sub.cancel();
  await channel.close();
  echo.close();
  await dir.delete(recursive: true);
  final text = output.toString();
  final line = text.contains(
    'connect-udp status=200 payload=ping-masque peer=ML-DSA-65',
  );
  stderr.writeln(
    'masque-go connect-udp exit $code forwarded=$forwarded line=$line '
    'complete=${conn.isComplete}',
  );
  if (code != 0 || !forwarded || !line || !conn.isComplete) exitCode = 1;
}

Future<bool> _serve(PqQuicConn conn, int echoPort) async {
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
      request.protocol != 'connect-udp' ||
      !request.uri.path.startsWith('/.well-known/masque/udp/')) {
    stderr.writeln(
      'unexpected ${request.method} ${request.protocol} ${request.uri}',
    );
    return false;
  }
  if (request.headers['capsule-protocol'] != '?1') {
    stderr.writeln('capsule-protocol ${request.headers}');
    return false;
  }
  final sent = await session.respond(
    id,
    PqHttpResponse(
      status: 200,
      headers: const {'capsule-protocol': '?1'},
      body: Uint8List(0),
      version: HttpVersion.h3,
    ),
    fin: false,
  );
  if (sent.isFailure) {
    stderr.writeln('respond ${sent.errorOrNull}');
    return false;
  }
  final udp = await RawDatagramSocket.bind(InternetAddress.loopbackIPv4, 0);
  final until = DateTime.now().add(const Duration(seconds: 10));
  while (DateTime.now().isBefore(until)) {
    final pumped = await session.receive();
    if (pumped.isFailure) {
      stderr.writeln('receive ${pumped.errorOrNull}');
      udp.close();
      return false;
    }
    for (final payload in session.takeStreamDatagrams(id)) {
      final parsed = decodeProxyDatagram(payload);
      if (parsed == null || parsed.contextId != 0) continue;
      udp.send(parsed.payload, InternetAddress.loopbackIPv4, echoPort);
    }
    final reply = udp.receive();
    if (reply == null) {
      await Future<void>.delayed(const Duration(milliseconds: 10));
      continue;
    }
    final back = await session.sendHttpDatagram(
      id,
      encodeProxyDatagram(0, Uint8List.fromList(reply.data)),
    );
    udp.close();
    if (back.isFailure) {
      stderr.writeln('echo ${back.errorOrNull}');
      return false;
    }
    return true;
  }
  udp.close();
  stderr.writeln('no connect-udp payload');
  return false;
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
