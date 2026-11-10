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
      if (request.method != 'GET') {
        return PqHttpResponse(
          status: 404,
          headers: const {'connection': 'close'},
          body: Uint8List(0),
          version: HttpVersion.h1,
        );
      }
      switch (request.uri.path) {
        case '/pq':
          return PqHttpResponse(
            status: 200,
            headers: const {'transfer-encoding': 'chunked'},
            body: Uint8List.fromList('pq-h1'.codeUnits),
            version: HttpVersion.h1,
            trailers: const {'x-trail': 'yes'},
          );
        case '/next':
          return PqHttpResponse(
            status: 200,
            headers: const {},
            body: Uint8List.fromList('pq-h1b'.codeUnits),
            version: HttpVersion.h1,
          );
        case '/bye':
          return PqHttpResponse(
            status: 200,
            headers: const {'connection': 'close'},
            body: Uint8List.fromList('pq-bye'.codeUnits),
            version: HttpVersion.h1,
          );
        default:
          return PqHttpResponse(
            status: 404,
            headers: const {'connection': 'close'},
            body: Uint8List(0),
            version: HttpVersion.h1,
          );
      }
    });
    final port = server.port;
    Future<ProcessResult> runCurl(List<String> urls, {bool verbose = false}) {
      return Process.run(curl, [
        '--http1.1',
        if (verbose) '-v',
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
        ...urls,
      ], environment: Platform.environment);
    }

    final once = await runCurl(['https://localhost:$port/pq']);
    stdout.writeln(once.stdout);
    if (once.exitCode != 0 || once.stdout.toString() != 'pq-h1') {
      stderr.writeln(once.stderr);
      stderr.writeln('curl exit ${once.exitCode}');
      exitCode = 1;
      return;
    }
    stdout.writeln('curl --http1.1 decoded a chunked body from PqHttpServer');
    final kept = await runCurl([
      'https://localhost:$port/pq',
      'https://localhost:$port/next',
    ], verbose: true);
    if (kept.exitCode != 0 || kept.stdout.toString() != 'pq-h1pq-h1b') {
      stderr.writeln(kept.stderr);
      stderr.writeln('curl keep-alive exit ${kept.exitCode}');
      exitCode = 1;
      return;
    }
    if (!kept.stderr.toString().contains(
      'Reusing existing https: connection',
    )) {
      stderr.writeln(kept.stderr);
      stderr.writeln('curl did not reuse the HTTP/1.1 connection');
      exitCode = 1;
      return;
    }
    stdout.writeln('curl --http1.1 reused one connection for two responses');
    final closed = await runCurl([
      'https://localhost:$port/bye',
      'https://localhost:$port/next',
    ], verbose: true);
    final closedErr = closed.stderr.toString();
    if (closed.exitCode != 0 || closed.stdout.toString() != 'pq-byepq-h1b') {
      stderr.writeln(closedErr);
      stderr.writeln('curl close exit ${closed.exitCode}');
      exitCode = 1;
      return;
    }
    if (closedErr.contains('Reusing existing https: connection') ||
        'Established connection to localhost'.allMatches(closedErr).length <
            2) {
      stderr.writeln(closedErr);
      stderr.writeln('curl reused a connection after Connection: close');
      exitCode = 1;
      return;
    }
    stdout.writeln(
      'curl --http1.1 opened a new connection after Connection: close',
    );
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
