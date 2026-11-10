import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

import 'package:pqforge/pqforge.dart';
import 'package:pqtransport/pqtransport.dart';
import 'package:pqtransport/pqtransport_io.dart';
import 'package:swissarmyknife/swissarmyknife.dart';

/// curl 8.23.0 linked to nghttp2 1.66.0 and OpenSSL 3.5.9.
///
/// One HTTP/2 GET. curl checks the ML-DSA-65 leaf and is forced onto
/// X25519MLKEM768. `wss://` on this curl is HTTP/1.1 Upgrade, so this
/// flight is not extended CONNECT. That peer is h2connect.c.
Future<void> main(List<String> args) async {
  if (args.length != 1) {
    stderr.writeln(
      'usage: dart run tool/interop/nghttp2-curl/h2_get_flight.dart <curl>',
    );
    exitCode = 64;
    return;
  }
  final curl = args.single;
  final crypto = const PqTransportCrypto();
  final minted = _mint(crypto);
  final dir = await Directory.systemTemp.createTemp('pq-h2-get-');
  final caPath = '${dir.path}/ca.pem';
  await File(caPath).writeAsString(minted.caPem);
  final bound = await IoTcpServer.bind(InternetAddress.loopbackIPv4, 0);
  final served = _serve(bound, minted.identity, crypto);
  final result = await Process.run(curl, [
    '--http2',
    '-v',
    '--cacert',
    caPath,
    '--curves',
    'X25519MLKEM768',
    '--tlsv1.3',
    '--tls-max',
    '1.3',
    '--tls13-ciphers',
    'TLS_AES_256_GCM_SHA384',
    '--resolve',
    'localhost:${bound.port}:127.0.0.1',
    '--max-time',
    '15',
    'https://localhost:${bound.port}/pq',
  ], environment: Platform.environment);
  final saw = await served;
  stderr.write(result.stderr);
  final text = '${result.stdout}\n${result.stderr}';
  stderr.writeln(
    'curl-h2 exit=${result.exitCode} body=${result.stdout} '
    'method=${saw.method} status=${saw.status}',
  );
  await dir.delete(recursive: true);
  if (result.exitCode != 0 ||
      result.stdout.toString() != 'pq-h2' ||
      !text.contains('using HTTP/2') ||
      !text.contains('HTTP/2 200') ||
      !text.contains('X25519MLKEM768') ||
      !text.contains('ML-DSA-65') ||
      !text.contains('SSL certificate verified via OpenSSL') ||
      saw.method != 'GET' ||
      saw.status != 200) {
    exitCode = 1;
  }
}

class _Saw {
  String? method;
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
      alpnProtocols: const [httpAlpnH2, httpAlpnH1],
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
    final accepted = await session.accept(timeout: const Duration(seconds: 10));
    if (accepted.isFailure) {
      stderr.writeln('accept ${accepted.errorOrNull} ${session.error}');
      await tls.close();
      return saw;
    }
    final (id, request) = accepted.valueOrNull!;
    saw.method = request.method;
    if (request.method != 'GET' || request.uri.path != '/pq') {
      stderr.writeln('unexpected ${request.method} ${request.uri}');
      await tls.close();
      return saw;
    }
    final sent = await session.respond(
      id,
      PqHttpResponse(
        status: 200,
        headers: const {},
        body: Uint8List.fromList('pq-h2'.codeUnits),
        version: HttpVersion.h2,
      ),
    );
    if (sent.isFailure) {
      stderr.writeln('respond ${sent.errorOrNull}');
      await tls.close();
      return saw;
    }
    saw.status = 200;
    await Future<void>.delayed(const Duration(milliseconds: 300));
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
