import 'dart:typed_data';

import 'package:pqforge/pqforge.dart';
import 'package:pqtransport/pqtransport.dart';
import 'package:test/test.dart';

void main() {
  final crypto = PqTransportCrypto();

  Future<void> finish(PqTlsClient client, PqTlsServer server) async {
    final hello = await client.startHandshake();
    expect(hello.isSuccess, isTrue, reason: '${hello.errorOrNull}');
    final toClient = (await server.ingest(hello.valueOrNull!)).valueOrNull!;
    final toServer = <Uint8List>[];
    for (final record in toClient) {
      final back = await client.ingest(record);
      expect(back.isSuccess, isTrue, reason: '${back.errorOrNull}');
      toServer.addAll(back.valueOrNull!);
    }
    expect(client.isComplete, isTrue);
    for (final record in toServer) {
      final back = await server.ingest(record);
      expect(back.isSuccess, isTrue, reason: '${back.errorOrNull}');
      expect(back.valueOrNull, isEmpty);
    }
    expect(server.isComplete, isTrue);
  }

  test(
    'zlib compress_certificate is accepted and is not the default',
    () async {
      final identity = PqTlsServerIdentity.generate(crypto);
      final client = PqTlsClient(crypto: crypto, compressCertificate: true);
      final server = PqTlsServer(crypto: crypto, identity: identity);
      await finish(client, server);
      expect(client.certificateWasCompressed, zlibCertificateCompression);
      expect(client.peerAuthenticated, isTrue);

      final plain = PqTlsClient(crypto: crypto);
      final again = PqTlsServer(
        crypto: crypto,
        identity: PqTlsServerIdentity.generate(crypto),
      );
      await finish(plain, again);
      expect(plain.certificateWasCompressed, isFalse);
    },
  );

  test(
    'client certificate is required, checked, and omitted on success',
    () async {
      final serverKey = crypto.mlDsaKeyGen();
      final clientKey = TlsClientIdentity.generate(crypto);
      final client = PqTlsClient(crypto: crypto, clientIdentity: clientKey);
      final server = PqTlsServer(
        crypto: crypto,
        identity: PqTlsServerIdentity(
          publicKey: serverKey.publicKey,
          secretKey: serverKey.secretKey,
        ),
        clientAuth: TlsClientAuth(publicKeys: [clientKey.publicKey]),
      );
      await finish(client, server);
      expect(server.authenticatedClientKey, clientKey.publicKey);

      final refused = PqTlsClient(crypto: crypto);
      final asking = PqTlsServer(
        crypto: crypto,
        identity: PqTlsServerIdentity.generate(crypto),
        clientAuth: TlsClientAuth(publicKeys: [clientKey.publicKey]),
      );
      final hello = await refused.startHandshake();
      final flight = await asking.ingest(hello.valueOrNull!);
      expect(flight.isSuccess, isTrue, reason: '${flight.errorOrNull}');
      final records = <Uint8List>[];
      for (final record in flight.valueOrNull!) {
        final back = await refused.ingest(record);
        expect(back.isSuccess, isTrue, reason: '${back.errorOrNull}');
        records.addAll(back.valueOrNull!);
      }
      final done = await asking.ingest(records.single);
      expect(done.isFailure, isTrue);
      expect(done.errorOrNull!.alert, tlsAlertCertificateRequired);
    },
  );

  test('SLH-DSA-SHA2-128f CertificateVerify round-trips', () async {
    final identity = PqTlsServerIdentity.slhDsa(PqSlhDsaAlgorithm.sha2128f);
    final client = PqTlsClient(
      crypto: crypto,
      signatureSchemes: const [tlsSignatureMldsa65, tlsSignatureSlhDsaSha2128f],
    );
    final server = PqTlsServer(crypto: crypto, identity: identity);
    await finish(client, server);
    expect(client.peerAuthenticated, isTrue);
    for (final algorithm in PqSlhDsaAlgorithm.values) {
      expect(tlsSignatureForSlh(algorithm), greaterThan(0));
      expect(tlsSlhDsaAlgorithm(tlsSignatureForSlh(algorithm)), algorithm);
    }
  }, timeout: const Timeout(Duration(seconds: 180)));
}
