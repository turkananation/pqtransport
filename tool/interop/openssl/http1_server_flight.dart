import 'dart:io';
import 'dart:typed_data';

import 'package:pqforge/pqforge.dart';
import 'package:pqtransport/pqtransport_io.dart';

/// curl --http1.1 against [PqHttpServer], chunked body.
///
/// The certificate is an ML-DSA-65 leaf for localhost. curl is the
/// one linked to OpenSSL 3.5.9 and verifies it with `--cacert`.
Future<void> main(List<String> args) async {
  if (args.length != 1) {
    stderr.writeln(
      'usage: dart run tool/interop/openssl/http1_server_flight.dart <curl>',
    );
    exitCode = 64;
    return;
  }
  final curl = args.single;
  final crypto = const PqTransportCrypto();
  final minted = _mint(crypto);
  final dir = await Directory.systemTemp.createTemp('pq-h1-curl-');
  PqHttpServer? server;
  try {
    final caPath = '${dir.path}/ca.pem';
    await File(caPath).writeAsString(minted.caPem);
    server = await PqHttpServer.bind(
      InternetAddress.loopbackIPv4,
      0,
      identity: minted.identity,
      crypto: crypto,
    );
    server.mount((request) async {
      if (request.method != 'GET' || request.uri.path != '/pq') {
        return PqHttpResponse(
          status: 404,
          headers: const {'connection': 'close'},
          body: Uint8List(0),
          version: HttpVersion.h1,
        );
      }
      return PqHttpResponse(
        status: 200,
        headers: const {'transfer-encoding': 'chunked'},
        body: Uint8List.fromList('pq-h1'.codeUnits),
        version: HttpVersion.h1,
        trailers: const {'x-trail': 'yes'},
      );
    });
    final port = server.port;
    final result = await Process.run(curl, [
      '--http1.1',
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
      'localhost:$port:127.0.0.1',
      '--max-time',
      '20',
      'https://localhost:$port/pq',
    ], environment: Platform.environment);
    stdout.writeln(result.stdout);
    if (result.exitCode != 0 || result.stdout.toString() != 'pq-h1') {
      stderr.writeln(result.stderr);
      stderr.writeln('curl exit ${result.exitCode}');
      exitCode = 1;
      return;
    }
    stdout.writeln('curl --http1.1 decoded a chunked body from PqHttpServer');
  } finally {
    await server?.close();
    await dir.delete(recursive: true);
  }
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
