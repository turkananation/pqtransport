import 'dart:io';
import 'dart:typed_data';

import 'package:pqtransport/pqtransport.dart';
import 'package:swissarmyknife/swissarmyknife.dart';

/// TLS 1.3 over an in-memory socket. No `SecureSocket`.
///
/// The default client offers X25519MLKEM768 first, then X25519. The
/// server authenticates with an ML-DSA-65 raw public key. `serverName`
/// is SNI only. A raw public key does not check that name.
/// `peerAuthenticated` is true only after CertificateVerify.
///
/// `onlyShares` forces one group. X.509 is
/// `certificateTypes: [TlsCertificateType.x509]` plus caller anchors.
/// That path is the OpenSSL interop, not this program.
Future<void> main() async {
  final crypto = PqTransportCrypto();
  final identity = PqTlsServerIdentity.generate(crypto);
  final (a, b) = MemoryByteSocket.pair();
  final client = PqTlsSocket.client(
    a,
    crypto: crypto,
    serverName: 'app.example',
    alpnProtocols: const [httpAlpnH1],
  );
  final server = PqTlsSocket.server(
    b,
    crypto: crypto,
    identity: identity,
    alpnProtocols: const [httpAlpnH1],
  );

  final hs = await Future.wait([server.handshake(), client.handshake()]);
  if (hs.any((r) => r.isFailure) ||
      !client.peerAuthenticated ||
      client.negotiatedGroup != TlsNamedGroup.x25519MlKem768 ||
      client.alpn != httpAlpnH1) {
    stderr.writeln(
      'handshake failed: client ${hs[1].errorOrNull} '
      'server ${hs[0].errorOrNull} '
      'auth ${client.peerAuthenticated} group ${client.negotiatedGroup}',
    );
    exitCode = 1;
    await client.close();
    await server.close();
    return;
  }

  final sent = await client.send(Uint8List.fromList('ping'.codeUnits));
  final got = await server.applicationData.first;
  final key = client.exporter('app', Uint8List(0), 32);
  if (sent.isFailure ||
      String.fromCharCodes(got) != 'ping' ||
      key.length != 32) {
    stderr.writeln('application data failed: ${sent.errorOrNull}');
    exitCode = 1;
  } else {
    stdout.writeln(
      'tls 1.3: ${client.negotiatedGroup!.name} alpn ${client.alpn} '
      'authenticated exporter ${key.length}',
    );
  }
  await client.close();
  await server.close();
}
