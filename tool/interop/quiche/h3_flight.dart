import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

import 'package:pqforge/pqforge.dart';
import 'package:pqtransport/pqtransport_io.dart';
import 'package:swissarmyknife/swissarmyknife.dart';

/// quiche HTTP/3 client against [PqHttp3Session] on [PqQuicConn.server].
///
/// quiche verifies the ML-DSA-65 localhost certificate. The request is
/// GET /pq with `x-pq: interop`. The response body is `pq-h3`.
Future<void> main(List<String> args) async {
  if (args.length != 1) {
    stderr.writeln(
      'usage: dart run tool/interop/quiche/h3_flight.dart <quiche_peer>',
    );
    exitCode = 64;
    return;
  }
  final peerBin = args.single;
  final crypto = const PqTransportCrypto();
  final minted = _mint(crypto);
  final dir = await Directory.systemTemp.createTemp('pq-quiche-h3-');
  final caPath = '${dir.path}/ca.pem';
  await File(caPath).writeAsString(minted.caPem);
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
  final served = _serve(conn);
  final process = await Process.start(peerBin, [
    'h3-client',
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
  final line = output.toString().contains(
    'h3 status=200 body=pq-h3 peer_cert=',
  );
  stderr.writeln(
    'quiche h3 exit $code request=$request line=$line '
    'complete=${conn.isComplete}',
  );
  if (code != 0 || !request || !line || !conn.isComplete) exitCode = 1;
}

Future<bool> _serve(PqQuicConn conn) async {
  final deadline = DateTime.now().add(const Duration(seconds: 20));
  while (!conn.isComplete && DateTime.now().isBefore(deadline)) {
    await Future<void>.delayed(const Duration(milliseconds: 20));
  }
  if (!conn.isComplete) return false;
  final session = PqHttp3Session.server(conn);
  final accepted = await session.accept(timeout: const Duration(seconds: 15));
  if (accepted.isFailure) {
    stderr.writeln('accept ${accepted.errorOrNull}');
    return false;
  }
  final (id, request) = accepted.valueOrNull!;
  if (request.method != 'GET' ||
      request.uri.path != '/pq' ||
      request.headers['x-pq'] != 'interop') {
    stderr.writeln(
      'unexpected ${request.method} ${request.uri} ${request.headers}',
    );
    return false;
  }
  final sent = await session.respond(
    id,
    PqHttpResponse(
      status: 200,
      headers: const {'content-type': 'text/plain'},
      body: Uint8List.fromList('pq-h3'.codeUnits),
      version: HttpVersion.h3,
    ),
  );
  if (sent.isFailure) {
    stderr.writeln('respond ${sent.errorOrNull}');
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
