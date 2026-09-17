import 'dart:typed_data';

import 'package:pqtransport/pqtransport.dart';

Future<void> main() async {
  final crypto = PqTransportCrypto();
  final net = MemoryDatagramNetwork();
  final aEp = const PqEndpoint('127.0.0.1', 4242);
  final bEp = const PqEndpoint('127.0.0.1', 4243);
  final a = PqEncryptedUdpSocket(
    raw: PqUdpSocket(channel: net.bind(aEp), throttleWindow: Duration.zero),
    crypto: crypto,
  );
  final b = PqEncryptedUdpSocket(
    raw: PqUdpSocket(channel: net.bind(bEp), throttleWindow: Duration.zero),
    crypto: crypto,
  );
  final kem = crypto.kemKeyGen();
  final salt = crypto.randomBytes(16);
  final flight = (await a.initiate(
    peerKemPublicKey: kem.publicKey,
    deploymentSalt: salt,
  )).valueOrNull!;
  final reply = (await b.accept(
    kemSecretKey: kem.secretKey,
    initiatorFlight: flight,
    deploymentSalt: salt,
  )).valueOrNull!;
  await a.completeInitiate(responderClassicalPublic: reply);
  await a.send(Uint8List.fromList('hello'.codeUnits), bEp);
}
