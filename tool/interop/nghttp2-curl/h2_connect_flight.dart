import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

import 'package:pqforge/pqforge.dart';
import 'package:pqtransport/pqtransport_io.dart';

/// libnghttp2 extended CONNECT against [PqHttp2Session].
///
/// curl 8.23 `wss://` is HTTP/1.1 Upgrade and does not send
/// `:protocol`. This peer is the nghttp2 library curl is linked to.
/// It offers only `h2`, checks ML-DSA-65 and X25519MLKEM768, and
/// requires a 200 that does not end the stream.
Future<void> main(List<String> args) async {
  if (args.length != 1) {
    stderr.writeln(
      'usage: dart run tool/interop/nghttp2-curl/h2_connect_flight.dart '
      '<h2connect>',
    );
    exitCode = 64;
    return;
  }
  final client = args.single;
  final crypto = const PqTransportCrypto();
  final minted = _mint(crypto);
  final dir = await Directory.systemTemp.createTemp('pq-h2-connect-');
  final caPath = '${dir.path}/ca.pem';
  await File(caPath).writeAsString(minted.caPem);
  final bound = await IoTcpServer.bind(InternetAddress.loopbackIPv4, 0);
  final served = _serve(bound, minted.identity, crypto);
  final result = await Process.run(client, [
    '127.0.0.1',
    '${bound.port}',
    caPath,
  ], environment: Platform.environment);
  stderr.write(result.stdout);
  stderr.write(result.stderr);
  _Saw saw = _Saw();
  try {
    saw = await served;
  } on Object catch (error) {
    stderr.writeln('serve finished $error');
  }
  final text = '${result.stdout}\n${result.stderr}';
  stderr.writeln(
    'nghttp2 exit=${result.exitCode} connect=${saw.connect} '
    'protocol=${saw.protocol} status=${saw.status}',
  );
  await dir.delete(recursive: true);
  if (result.exitCode != 0 ||
      !text.contains(
        'nghttp2-connect status=200 end_stream=0 alpn=h2 '
        'group=X25519MLKEM768 sig=id-ml-dsa-65',
      ) ||
      !saw.connect ||
      saw.protocol != 'websocket' ||
      saw.status != 200) {
    exitCode = 1;
  }
}

class _Saw {
  var connect = false;
  String? protocol;
  var status = 0;
}

Future<_Saw> _serve(
  IoTcpServer bound,
  PqTlsServerIdentity identity,
  PqTransportCrypto crypto,
) async {
  final saw = _Saw();
  try {
    final raw = await bound.connections.first.timeout(
      const Duration(seconds: 15),
    );
    final tls = PqTlsSocket.server(
      raw,
      crypto: crypto,
      identity: identity,
      alpnProtocols: const [httpAlpnH2],
    );
    final hs = await tls.handshake(timeout: const Duration(seconds: 15));
    if (hs.isFailure) {
      stderr.writeln('handshake ${hs.errorOrNull}');
      await tls.close();
      return saw;
    }
    if (tls.alpn != httpAlpnH2) {
      stderr.writeln('alpn ${tls.alpn}');
      await tls.close();
      return saw;
    }
    final session = PqHttp2Session.server(tls);
    final accepted = await session.accept(
      untilFin: false,
      timeout: const Duration(seconds: 10),
    );
    if (accepted.isFailure) {
      stderr.writeln('accept ${accepted.errorOrNull} ${session.error}');
      await tls.close();
      return saw;
    }
    final (id, request) = accepted.valueOrNull!;
    saw.connect = request.method == 'CONNECT';
    saw.protocol = request.protocol;
    stderr.writeln(
      'h2 ${request.method} protocol=${request.protocol} path=${request.uri.path}',
    );
    if (!saw.connect || saw.protocol != 'websocket') {
      await tls.close();
      return saw;
    }
    final sent = await session.respond(
      id,
      PqHttpResponse(
        status: 200,
        headers: const {},
        body: Uint8List(0),
        version: HttpVersion.h2,
      ),
      fin: false,
    );
    if (sent.isFailure) {
      stderr.writeln('respond ${sent.errorOrNull}');
      await tls.close();
      return saw;
    }
    saw.status = 200;
    await Future<void>.delayed(const Duration(seconds: 2));
    await session.close();
    await tls.close();
  } on Object catch (error) {
    stderr.writeln('serve $error');
  } finally {
    await bound.close();
  }
  return saw;
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
