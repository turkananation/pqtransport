import 'dart:io';
import 'dart:typed_data';

import 'package:pqtransport/pqtransport.dart';

/// HTTP/1.1 GET on a finished `PqTlsSocket`. ALPN is `http/1.1`.
///
/// `PqHttpClient` does not take the socket in its constructor.
/// `roundTrip` follows ALPN. A silent drop from `h2` fails unless
/// `allowDowngrade` is set.
Future<void> main() async {
  final crypto = PqTransportCrypto();
  final identity = PqTlsServerIdentity.generate(crypto);
  final (a, b) = MemoryByteSocket.pair();
  final client = PqTlsSocket.client(
    a,
    crypto: crypto,
    alpnProtocols: const [httpAlpnH1],
  );
  final server = PqTlsSocket.server(
    b,
    crypto: crypto,
    identity: identity,
    alpnProtocols: const [httpAlpnH1],
  );
  server.applicationData.listen((raw) async {
    await server.send(
      encodeHttp1Response(
        PqHttpResponse(
          status: 200,
          headers: const {'content-type': 'text/plain'},
          body: Uint8List.fromList('pq-ok'.codeUnits),
          version: HttpVersion.h1,
        ),
      ),
    );
  });

  final hs = await Future.wait([server.handshake(), client.handshake()]);
  final res = await PqHttpClient().roundTrip(
    tls: client,
    request: PqHttpRequest(
      method: 'GET',
      uri: Uri.parse('https://app.example/health'),
    ),
  );
  final body = res.valueOrNull == null
      ? ''
      : String.fromCharCodes(res.valueOrNull!.body);
  if (hs.any((r) => r.isFailure) || res.isFailure || body != 'pq-ok') {
    stderr.writeln('http/1.1 failed: ${res.errorOrNull}');
    exitCode = 1;
  } else {
    stdout.writeln('http/1.1: ${res.valueOrNull!.status} $body');
  }
  await client.close();
  await server.close();
}
