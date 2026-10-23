@TestOn('vm')
library;

import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

import 'package:pqtransport/pqtransport_io.dart';
import 'package:test/test.dart';

void main() {
  test('TCP accept and connect complete a TLS handshake', () async {
    final crypto = PqTransportCrypto();
    final identity = PqTlsServerIdentity.generate(crypto);
    final bound = await IoTcpServer.bind(InternetAddress.loopbackIPv4, 0);
    final accepted = bound.connections.first;
    final clientSock = await IoTcpSocket.connect(
      InternetAddress.loopbackIPv4.address,
      bound.port,
    );
    final serverSock = await accepted.timeout(const Duration(seconds: 5));
    final client = PqTlsSocket.client(clientSock, crypto: crypto);
    final server = PqTlsSocket.server(
      serverSock,
      crypto: crypto,
      identity: identity,
    );
    final hs = await Future.wait([server.handshake(), client.handshake()]);
    expect(hs[0].isSuccess, isTrue, reason: '${hs[0].errorOrNull}');
    expect(hs[1].isSuccess, isTrue, reason: '${hs[1].errorOrNull}');
    expect(client.peerAuthenticated, isTrue);
    await client.send(Uint8List.fromList([9, 9]));
    final got = await server.applicationData.first.timeout(
      const Duration(seconds: 5),
    );
    expect(got, [9, 9]);
    await client.close();
    await server.close();
    await bound.close();
  }, timeout: const Timeout(Duration(seconds: 40)));

  test('OpenSSL ML-DSA-65 PKCS#8 loads when the binary is present', () async {
    const bin = '/tmp/openssl-3.5.9-install/bin/openssl';
    if (!File(bin).existsSync()) return;
    final dir = await Directory.systemTemp.createTemp('pq-id-');
    try {
      final extra = Platform.environment['LD_LIBRARY_PATH'];
      final env = {
        ...Platform.environment,
        'LD_LIBRARY_PATH': extra == null || extra.isEmpty
            ? '/tmp/openssl-3.5.9-install/lib'
            : '/tmp/openssl-3.5.9-install/lib:$extra',
        'OPENSSL_CONF':
            '${Directory.current.path}/tool/interop/openssl/openssl.cnf',
      };
      await _run(bin, env, [
        'genpkey',
        '-algorithm',
        'ML-DSA-65',
        '-out',
        '${dir.path}/key.pem',
      ]);
      await _run(bin, env, [
        'pkey',
        '-in',
        '${dir.path}/key.pem',
        '-pubout',
        '-out',
        '${dir.path}/pub.pem',
      ]);
      final loaded = await readMlDsaIdentityPem(
        '${dir.path}/pub.pem',
        '${dir.path}/key.pem',
      );
      expect(loaded.isSuccess, isTrue, reason: '${loaded.errorOrNull}');
      final crypto = PqTransportCrypto();
      final message = Uint8List.fromList([4, 5, 6]);
      final sig = crypto.mlDsaSign(
        secretKey: loaded.valueOrNull!.secretKey,
        message: message,
      );
      expect(
        crypto.mlDsaVerify(
          publicKey: loaded.valueOrNull!.publicKey,
          message: message,
          signatureBytes: sig,
        ),
        isTrue,
      );
    } finally {
      await dir.delete(recursive: true);
    }
  }, timeout: const Timeout(Duration(seconds: 30)));
}

Future<void> _run(
  String bin,
  Map<String, String> env,
  List<String> args,
) async {
  final result = await Process.run(bin, args, environment: env);
  if (result.exitCode != 0) {
    throw StateError('$bin ${args.first}\n${result.stderr}');
  }
}
