import 'dart:typed_data';

import 'package:pqtransport/pqtransport.dart';

Future<void> main() async {
  final net = MemoryDatagramNetwork();
  final server = PqMdnsServer(
    channel: net.bind(const PqEndpoint('10.0.0.1', mdnsPort)),
  );
  server.beginProbe('printer._pq._tcp.local.');
  server.completeProbe(collision: false);
  server.completeProbe(collision: false);
  await server.announce(
    DnsA(
      name: 'printer._pq._tcp.local.',
      address: Uint8List.fromList([10, 0, 0, 1]),
    ),
  );
}
