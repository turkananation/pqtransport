import 'dart:io';
import 'dart:typed_data';

import 'package:pqtransport/pqtransport.dart';

/// HTTP/2 GET on ALPN `h2`. The server is `PqHttp2Session.server`.
///
/// This is the same preface, SETTINGS, HEADERS, and HPACK that the
/// nghttp2 interop checks in cleartext. The TLS here is ours.
Future<void> main() async {
  final crypto = PqTransportCrypto();
  final identity = PqTlsServerIdentity.generate(crypto);
  final (a, b) = MemoryByteSocket.pair();
  final client = PqTlsSocket.client(
    a,
    crypto: crypto,
    alpnProtocols: const [httpAlpnH2],
  );
  final server = PqTlsSocket.server(
    b,
    crypto: crypto,
    identity: identity,
    alpnProtocols: const [httpAlpnH2],
  );
  final hs = await Future.wait([server.handshake(), client.handshake()]);
  final h2 = PqHttp2Session.server(server);
  final serving = () async {
    final accepted = await h2.accept(timeout: const Duration(seconds: 20));
    if (accepted.isFailure) return accepted;
    final (id, _) = accepted.valueOrNull!;
    return h2.respond(
      id,
      PqHttpResponse(
        status: 200,
        headers: const {'content-type': 'text/plain'},
        body: Uint8List.fromList('h2-ok'.codeUnits),
        version: HttpVersion.h2,
      ),
    );
  }();

  final res = await PqHttpClient(prefer: HttpVersion.h2).roundTripH2(
    tls: client,
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
      client.alpn != httpAlpnH2 ||
      res.isFailure ||
      served.isFailure ||
      body != 'h2-ok') {
    stderr.writeln('http/2 failed: ${res.errorOrNull ?? served.errorOrNull}');
    exitCode = 1;
  } else {
    stdout.writeln('http/2: ${res.valueOrNull!.status} $body');
  }
  await h2.close();
  await client.close();
  await server.close();
}
