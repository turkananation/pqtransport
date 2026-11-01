import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:pqforge/pqforge.dart';
import 'package:pqtransport/pqtransport_io.dart';

Future<void> main(List<String> args) async {
  if (args.length != 1) {
    stderr.writeln(
      'usage: dart run tool/interop/openssl/server_flight.dart <openssl>',
    );
    exitCode = 64;
    return;
  }
  await handshakeServerFlight(args.single);
}

/// OpenSSL `s_client` and curl as TLS clients of [PqTlsSocket].
///
/// The raw-pk `s_server` flight is not used here. Certs are minted by
/// pqforge. The X25519MLKEM768 row does not pass `-groups`, so OpenSSL's
/// default ClientHello keeps both the hybrid share and the X25519 share.
/// The other two rows pass one group, because a default hello does not
/// offer them.
Future<void> handshakeServerFlight(String opensslBin) async {
  final env = <String, String>{
    ...Platform.environment,
    'LD_LIBRARY_PATH': _libDir(opensslBin),
  };
  for (final group in HybridGroup.values) {
    stdout.writeln('s_client ${_groupName(group)} chain 1');
    await _mlDsa(
      opensslBin,
      env,
      group: group,
      withIntermediate: false,
      defaultGroups: group == HybridGroup.x25519MlKem768,
    );
  }
  stdout.writeln('s_client X25519MLKEM768 chain 2');
  await _mlDsa(
    opensslBin,
    env,
    group: HybridGroup.x25519MlKem768,
    withIntermediate: true,
    defaultGroups: false,
  );
  stdout.writeln('s_client P-256 leaf on X25519MLKEM768');
  await _p256(opensslBin, env);
  stdout.writeln('curl --cacert against PqTlsSocket');
  await _curl(opensslBin, env);
  stdout.writeln('s_client wrong CA');
  await _negative(opensslBin, env, wrongName: false);
  stdout.writeln('s_client wrong hostname');
  await _negative(opensslBin, env, wrongName: true);
  stdout.writeln(
    'OpenSSL 3.5.9 s_client accepted PqTlsSocket: ML-DSA-65 on '
    'X25519MLKEM768, SecP256r1MLKEM768, and SecP384r1MLKEM1024 '
    '(chain length 1, and chain length 2 on X25519MLKEM768), plus one '
    'P-256 leaf on X25519MLKEM768. curl --cacert completed one '
    'HTTP/1.1 GET. Not a browser. Not WebPKI. Not curl --http3.',
  );
}

Future<void> _mlDsa(
  String opensslBin,
  Map<String, String> env, {
  required HybridGroup group,
  required bool withIntermediate,
  required bool defaultGroups,
}) async {
  final crypto = _cryptoFor(group);
  final signer = const PqTransportCrypto();
  final minted = _mintMlDsa(signer, withIntermediate: withIntermediate);
  final dir = await Directory.systemTemp.createTemp('pq-sclient-');
  try {
    final caPath = '${dir.path}/ca.pem';
    await File(caPath).writeAsString(minted.caPem);
    final result = await _peer(
      bin: opensslBin,
      env: env,
      args: _sClientArgs(
        caPath: caPath,
        group: defaultGroups ? null : group,
        sigalgs: 'mldsa65',
        hostname: 'localhost',
      ),
      identity: minted.identity,
      group: group,
      crypto: crypto,
      http: false,
      requireHandshake: true,
    );
    _requireVerifyOk(result, _groupName(group));
  } finally {
    await dir.delete(recursive: true);
  }
}

Future<void> _p256(String opensslBin, Map<String, String> env) async {
  final minted = _mintP256();
  final dir = await Directory.systemTemp.createTemp('pq-sclient-p256-');
  try {
    final caPath = '${dir.path}/ca.pem';
    await File(caPath).writeAsString(minted.caPem);
    final result = await _peer(
      bin: opensslBin,
      env: env,
      args: _sClientArgs(
        caPath: caPath,
        group: HybridGroup.x25519MlKem768,
        sigalgs: 'ecdsa_secp256r1_sha256',
        hostname: 'localhost',
      ),
      identity: minted.identity,
      group: HybridGroup.x25519MlKem768,
      crypto: const PqTransportCrypto(),
      http: false,
      requireHandshake: true,
    );
    _requireVerifyOk(result, 'P-256');
  } finally {
    await dir.delete(recursive: true);
  }
}

Future<void> _curl(String opensslBin, Map<String, String> env) async {
  final curl = _curlBin(opensslBin);
  if (!File(curl).existsSync()) {
    throw StateError('curl linked to OpenSSL 3.5.9 is missing at $curl');
  }
  final minted = _mintMlDsa(const PqTransportCrypto(), withIntermediate: false);
  final dir = await Directory.systemTemp.createTemp('pq-curl-server-');
  try {
    final caPath = '${dir.path}/ca.pem';
    await File(caPath).writeAsString(minted.caPem);
    final result = await _peer(
      bin: curl,
      env: env,
      args: [
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
        'localhost:{port}:127.0.0.1',
        '--max-time',
        '20',
        'https://localhost:{port}/',
      ],
      identity: minted.identity,
      group: HybridGroup.x25519MlKem768,
      crypto: const PqTransportCrypto(),
      http: true,
      requireHandshake: true,
    );
    if (result.exitCode != 0 || !result.stdout.toString().contains('ok')) {
      throw StateError(
        'curl --cacert against PqTlsSocket failed\n'
        '${result.stdout}\n${result.stderr}',
      );
    }
  } finally {
    await dir.delete(recursive: true);
  }
}

Future<void> _negative(
  String opensslBin,
  Map<String, String> env, {
  required bool wrongName,
}) async {
  final signer = const PqTransportCrypto();
  final real = _mintMlDsa(signer, withIntermediate: false);
  final other = _mintMlDsa(signer, withIntermediate: false);
  final dir = await Directory.systemTemp.createTemp('pq-sclient-neg-');
  try {
    final caPath = '${dir.path}/ca.pem';
    await File(caPath).writeAsString(wrongName ? real.caPem : other.caPem);
    final result = await _peer(
      bin: opensslBin,
      env: env,
      args: _sClientArgs(
        caPath: caPath,
        group: HybridGroup.x25519MlKem768,
        sigalgs: 'mldsa65',
        hostname: wrongName ? 'mismatch.example' : 'localhost',
      ),
      identity: real.identity,
      group: HybridGroup.x25519MlKem768,
      crypto: const PqTransportCrypto(),
      http: false,
      requireHandshake: false,
    );
    final text = '${result.stdout}\n${result.stderr}';
    if (result.exitCode == 0 || text.contains('Verify return code: 0')) {
      throw StateError(
        '${wrongName ? 'hostname' : 'wrong CA'} was accepted\n$text',
      );
    }
    if (text.contains('unknown option') || text.contains('Usage:')) {
      throw StateError('s_client rejected the flags\n$text');
    }
  } finally {
    await dir.delete(recursive: true);
  }
}

List<String> _sClientArgs({
  required String caPath,
  required HybridGroup? group,
  required String sigalgs,
  required String hostname,
}) => [
  's_client',
  '-connect',
  '127.0.0.1:{port}',
  '-servername',
  'localhost',
  '-verify_hostname',
  hostname,
  '-tls1_3',
  '-CAfile',
  caPath,
  '-no-CAfile',
  '-no-CApath',
  '-verify',
  '1',
  '-verify_return_error',
  '-ciphersuites',
  'TLS_AES_256_GCM_SHA384',
  '-sigalgs',
  sigalgs,
  if (group != null) ...['-groups', _groupName(group)],
  '-ign_eof',
];

Future<ProcessResult> _peer({
  required String bin,
  required Map<String, String> env,
  required List<String> args,
  required PqTlsServerIdentity identity,
  required HybridGroup group,
  required PqTransportCrypto crypto,
  required bool http,
  required bool requireHandshake,
}) async {
  final bound = await IoTcpServer.bind(InternetAddress.loopbackIPv4, 0);
  final port = bound.port;
  final serve = _serve(
    bound: bound,
    identity: identity,
    group: group,
    crypto: crypto,
    http: http,
    requireHandshake: requireHandshake,
  );
  final result = await Process.run(bin, [
    for (final arg in args) arg.replaceAll('{port}', '$port'),
  ], environment: env);
  Object? serveError;
  try {
    await serve.timeout(const Duration(seconds: 8));
  } on Object catch (e) {
    serveError = e;
  }
  if (requireHandshake && (result.exitCode != 0 || serveError != null)) {
    throw StateError(
      '$bin failed (${result.exitCode}) serve=$serveError\n'
      '${result.stdout}\n${result.stderr}',
    );
  }
  return result;
}

Future<void> _serve({
  required IoTcpServer bound,
  required PqTlsServerIdentity identity,
  required HybridGroup group,
  required PqTransportCrypto crypto,
  required bool http,
  required bool requireHandshake,
}) async {
  try {
    final raw = await bound.connections.first.timeout(
      const Duration(seconds: 15),
    );
    final tls = PqTlsSocket.server(
      raw,
      crypto: crypto,
      identity: identity,
      group: group,
      alpnProtocols: const [httpAlpnH1],
    );
    final buf = BytesBuilder(copy: false);
    final request = Completer<void>();
    final sub = tls.applicationData.listen((chunk) {
      buf.add(chunk);
      if (!request.isCompleted && _headers(buf.toBytes())) {
        request.complete();
      }
    });
    try {
      final hs = await tls.handshake(timeout: const Duration(seconds: 20));
      if (hs.isFailure) {
        if (requireHandshake) {
          throw StateError('PqTlsSocket handshake: ${hs.errorOrNull}');
        }
        return;
      }
      if (!http) return;
      await request.future.timeout(const Duration(seconds: 10));
      final sent = await tls.send(
        Uint8List.fromList(
          utf8.encode(
            'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n'
            'Connection: close\r\n\r\nok',
          ),
        ),
      );
      if (sent.isFailure) {
        throw StateError('HTTP response: ${sent.errorOrNull}');
      }
    } finally {
      await sub.cancel();
      await tls.close();
    }
  } on Object {
    if (requireHandshake) rethrow;
  } finally {
    await bound.close();
  }
}

bool _headers(Uint8List bytes) {
  if (bytes.length < 4) return false;
  for (var i = 0; i + 3 < bytes.length; i++) {
    if (bytes[i] == 13 &&
        bytes[i + 1] == 10 &&
        bytes[i + 2] == 13 &&
        bytes[i + 3] == 10) {
      return true;
    }
  }
  return false;
}

void _requireVerifyOk(ProcessResult result, String label) {
  final text = '${result.stdout}\n${result.stderr}';
  if (result.exitCode != 0 || !text.contains('Verify return code: 0')) {
    throw StateError('$label verify failed\n$text');
  }
}

final class _Minted {
  const _Minted(this.identity, this.caPem);

  final PqTlsServerIdentity identity;
  final String caPem;
}

_Minted _mintMlDsa(PqTransportCrypto crypto, {required bool withIntermediate}) {
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
  final PqX509Name issuerName;
  final Uint8List issuerSecret;
  final List<Uint8List> extra;
  if (!withIntermediate) {
    issuerName = rootName;
    issuerSecret = rootKeys.secretKey;
    extra = const [];
  } else {
    final midKeys = crypto.mlDsaKeyGen();
    final midName = PqX509Name.commonName('pqtransport-intermediate');
    final mid = PqX509.mint(
      issuer: rootName,
      subject: midName,
      publicKey: PqX509MlDsaKey(PqX509Algorithm.mlDsa65, midKeys.publicKey),
      algorithm: PqX509Algorithm.mlDsa65,
      sign: (tbs) =>
          crypto.mlDsaSign(secretKey: rootKeys.secretKey, message: tbs),
      notBefore: notBefore,
      notAfter: notAfter,
      serial: Uint8List.fromList([2]),
      ca: true,
      keyCertSign: true,
      includeEku: false,
    );
    issuerName = midName;
    issuerSecret = midKeys.secretKey;
    extra = [mid];
  }
  final leafKeys = crypto.mlDsaKeyGen();
  final leafKey = PqX509MlDsaKey(PqX509Algorithm.mlDsa65, leafKeys.publicKey);
  final leaf = PqX509.mint(
    issuer: issuerName,
    subject: PqX509Name.commonName('localhost'),
    publicKey: leafKey,
    algorithm: PqX509Algorithm.mlDsa65,
    sign: (tbs) => crypto.mlDsaSign(secretKey: issuerSecret, message: tbs),
    notBefore: notBefore,
    notAfter: notAfter,
    serial: Uint8List.fromList([withIntermediate ? 3 : 2]),
    subjectAltNames: const [PqX509DnsName('localhost')],
  );
  return _Minted(
    PqTlsServerIdentity.x509(
      leafKey: leafKey,
      sign: (content) =>
          crypto.mlDsaSign(secretKey: leafKeys.secretKey, message: content),
      chain: [leaf, ...extra],
      certificateDnsName: 'localhost',
    ),
    PqX509.toPem(root),
  );
}

_Minted _mintP256() {
  final now = DateTime.now().toUtc();
  final notBefore = now.subtract(const Duration(hours: 1));
  final notAfter = now.add(const Duration(days: 1));
  final caKeys = PqEcdsaP256.generateKeyPair();
  final leafKeys = PqEcdsaP256.generateKeyPair();
  final caName = PqX509Name.commonName('pqtransport-p256');
  Uint8List signCa(Uint8List tbs) => PqX509.encodeEcdsaSignature(
    PqEcdsaP256.sign(privateKey: caKeys.secretKey, message: tbs),
  );
  final ca = PqX509.mint(
    issuer: caName,
    subject: caName,
    publicKey: PqX509EcdsaP256Key(caKeys.publicKey),
    algorithm: PqX509Algorithm.ecdsaP256Sha256,
    sign: signCa,
    notBefore: notBefore,
    notAfter: notAfter,
    serial: Uint8List.fromList([1]),
    ca: true,
    keyCertSign: true,
    includeEku: false,
  );
  final leaf = PqX509.mint(
    issuer: caName,
    subject: PqX509Name.commonName('localhost'),
    publicKey: PqX509EcdsaP256Key(leafKeys.publicKey),
    algorithm: PqX509Algorithm.ecdsaP256Sha256,
    sign: signCa,
    notBefore: notBefore,
    notAfter: notAfter,
    serial: Uint8List.fromList([2]),
    subjectAltNames: const [PqX509DnsName('localhost')],
  );
  return _Minted(
    PqTlsServerIdentity.x509(
      leafKey: PqX509EcdsaP256Key(leafKeys.publicKey),
      sign: (content) =>
          PqEcdsaP256.sign(privateKey: leafKeys.secretKey, message: content),
      chain: [leaf],
      certificateDnsName: 'localhost',
    ),
    PqX509.toPem(ca),
  );
}

String _groupName(HybridGroup group) => switch (group) {
  HybridGroup.x25519MlKem768 => 'X25519MLKEM768',
  HybridGroup.secP256r1MlKem768 => 'SecP256r1MLKEM768',
  HybridGroup.secP384r1MlKem1024 => 'SecP384r1MLKEM1024',
};

PqTransportCrypto _cryptoFor(HybridGroup group) => switch (group) {
  HybridGroup.secP384r1MlKem1024 => const PqTransportCrypto(
    profile: PqForgeProfile.maximum,
  ),
  _ => const PqTransportCrypto(),
};

String _libDir(String bin) {
  final lib = Directory('${File(bin).parent.parent.path}/lib');
  final extra = Platform.environment['LD_LIBRARY_PATH'];
  if (!lib.existsSync()) return extra ?? '';
  return extra == null || extra.isEmpty ? lib.path : '${lib.path}:$extra';
}

String _curlBin(String opensslBin) {
  final built = '${File(opensslBin).parent.parent.path}/curl/bin/curl';
  if (File(built).existsSync()) return built;
  return Platform.environment['CURL_BIN'] ?? built;
}
