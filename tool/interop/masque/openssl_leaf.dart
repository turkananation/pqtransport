import 'dart:io';
import 'dart:typed_data';

import 'package:pqforge/pqforge.dart';

/// OpenSSL 3.5.9 ML-DSA-65 leaf, seed-only PKCS#8.
/// Go 1.27 loads that key. pqtransport checks the same leaf.
class OpensslLeaf {
  OpensslLeaf({
    required this.directory,
    required this.caDer,
    required this.certPath,
    required this.keyPath,
  });

  final Directory directory;
  final Uint8List caDer;
  final String certPath;
  final String keyPath;
}

Future<OpensslLeaf> mintOpensslLeaf({
  required String openssl,
  required String conf,
  required String lib,
}) async {
  final dir = await Directory.systemTemp.createTemp('pq-openssl-leaf-');
  final env = {
    ...Platform.environment,
    'OPENSSL_CONF': conf,
    'LD_LIBRARY_PATH': lib,
  };
  Future<void> run(List<String> args) async {
    final result = await Process.run(openssl, args, environment: env);
    if (result.exitCode != 0) {
      stderr.writeln(result.stdout);
      stderr.writeln(result.stderr);
      throw StateError('openssl ${args.first} exit ${result.exitCode}');
    }
  }

  await run([
    'req',
    '-x509',
    '-newkey',
    'ML-DSA-65',
    '-keyout',
    '${dir.path}/ca.key',
    '-out',
    '${dir.path}/ca.pem',
    '-days',
    '2',
    '-nodes',
    '-subj',
    '/CN=pqtransport-ca',
    '-addext',
    'basicConstraints=critical,CA:TRUE',
    '-addext',
    'keyUsage=critical,keyCertSign,cRLSign',
  ]);
  await run([
    'req',
    '-newkey',
    'ML-DSA-65',
    '-keyout',
    '${dir.path}/leaf.key',
    '-out',
    '${dir.path}/leaf.csr',
    '-nodes',
    '-subj',
    '/CN=localhost',
    '-addext',
    'subjectAltName=DNS:localhost',
    '-addext',
    'keyUsage=critical,digitalSignature',
    '-addext',
    'extendedKeyUsage=serverAuth',
    '-addext',
    'basicConstraints=CA:FALSE',
  ]);
  await run([
    'x509',
    '-req',
    '-in',
    '${dir.path}/leaf.csr',
    '-CA',
    '${dir.path}/ca.pem',
    '-CAkey',
    '${dir.path}/ca.key',
    '-CAcreateserial',
    '-out',
    '${dir.path}/leaf.pem',
    '-days',
    '2',
    '-copy_extensions',
    'copy',
  ]);
  await run([
    'pkey',
    '-in',
    '${dir.path}/leaf.key',
    '-out',
    '${dir.path}/leaf-seed.key',
    '-provparam',
    'ml-dsa.output_formats=seed-only',
  ]);
  await run([
    'x509',
    '-in',
    '${dir.path}/ca.pem',
    '-outform',
    'DER',
    '-out',
    '${dir.path}/ca.der',
  ]);
  final pem = await File('${dir.path}/leaf.pem').readAsString();
  final blocks = PqX509.pemBlocks(pem);
  if (blocks.isEmpty) {
    throw StateError('leaf pem has no certificate');
  }
  final leaf = PqX509.parse(blocks.first.der);
  final certificate = leaf.certificate;
  final caDer = await File('${dir.path}/ca.der').readAsBytes();
  final path = PqX509.validate(
    chain: [blocks.first.der],
    anchors: [caDer],
    now: DateTime.now().toUtc(),
  );
  if (certificate == null ||
      !path.trusted ||
      certificate.algorithm != PqX509Algorithm.mlDsa65 ||
      !certificate.subjectAltNames.any(
        (name) =>
            name is PqX509DnsName && name.ascii.toLowerCase() == 'localhost',
      )) {
    throw StateError(
      'leaf ${certificate?.algorithm.name} trusted=${path.trusted} '
      '${path.failure ?? ''}',
    );
  }
  return OpensslLeaf(
    directory: dir,
    caDer: caDer,
    certPath: '${dir.path}/leaf.pem',
    keyPath: '${dir.path}/leaf-seed.key',
  );
}
