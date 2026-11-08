import 'dart:io';
import 'dart:typed_data';

import 'package:pqtransport/pqtransport.dart';

/// HTTP/3 GET on a QUIC connection whose ALPN is `h3`.
///
/// `PqQuicConn.pair` links the two ends in memory. `PqQuicConn.client`
/// takes the same arguments plus `deliver`, which is where a real UDP
/// socket would send the datagram. `roundTripH3` refuses any other ALPN.
/// This is not `curl --http3`.
Future<void> main() async {
  final (client, server) = PqQuicConn.pair(alpnProtocols: const [httpAlpnH3]);
  final hs = await Future.wait([client.handshake(), server.handshake()]);
  final h3 = PqHttp3Session.server(server);
  final serving = () async {
    final accepted = await h3.accept();
    if (accepted.isFailure) return accepted;
    final (id, _) = accepted.valueOrNull!;
    return h3.respond(
      id,
      PqHttpResponse(
        status: 200,
        headers: const {'content-type': 'text/plain'},
        body: Uint8List.fromList('pq-h3'.codeUnits),
        version: HttpVersion.h3,
      ),
    );
  }();

  final res = await PqHttpClient(prefer: HttpVersion.h3).roundTripH3(
    conn: client,
    request: PqHttpRequest(
      method: 'GET',
      uri: Uri.parse('https://app.example/health'),
    ),
  );
  final served = await serving;
  final body = res.valueOrNull == null
      ? ''
      : String.fromCharCodes(res.valueOrNull!.body);
  if (hs.any((r) => r.isFailure) ||
      client.alpn != httpAlpnH3 ||
      res.isFailure ||
      served.isFailure ||
      body != 'pq-h3') {
    stderr.writeln('http/3 failed: ${res.errorOrNull ?? served.errorOrNull}');
    exitCode = 1;
  } else {
    stdout.writeln('http/3: ${res.valueOrNull!.status} $body');
  }
  await client.close();
  await server.close();
}
