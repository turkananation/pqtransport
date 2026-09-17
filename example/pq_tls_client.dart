import 'dart:typed_data';

import 'package:pqtransport/pqtransport.dart';

Future<void> main() async {
  final crypto = PqTransportCrypto();
  final identity = PqTlsServerIdentity.generate(crypto);
  final client = PqTlsClient(crypto: crypto);
  final server = PqTlsServer(crypto: crypto, identity: identity);

  final ch = (await client.startHandshake()).valueOrNull!;
  final flight = (await server.ingest(ch)).valueOrNull!;
  await client.ingest(flight[0]);
  final finished = (await client.ingest(flight[1])).valueOrNull!;
  await server.ingest(finished.first);

  final exp = client.exporter('example', Uint8List(0), 32);
  // ignore: avoid_print
  print('handshake complete, exporter len=${exp.length}');
}
