import 'dart:async';
import 'dart:typed_data';

import 'package:pqtransport/pqtransport.dart';
import 'package:test/test.dart';

void main() {
  final crypto = PqTransportCrypto();

  test('PqTlsSocket handshake then HTTP/1.1 GET over mock TLS', () async {
    final identity = PqTlsServerIdentity.generate(crypto);
    final (clientSock, serverSock) = MemoryByteSocket.pair();
    final client = PqTlsSocket.client(clientSock, crypto: crypto);
    final server = PqTlsSocket.server(
      serverSock,
      crypto: crypto,
      identity: identity,
    );

    late StreamSubscription<Uint8List> sub;
    sub = server.applicationData.listen((req) async {
      final decoded = String.fromCharCodes(req);
      expect(decoded, contains('GET /dns-query HTTP/1.1'));
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
    expect(hs[0].isSuccess, isTrue, reason: '${hs[0].errorOrNull}');
    expect(hs[1].isSuccess, isTrue, reason: '${hs[1].errorOrNull}');
    expect(client.isComplete, isTrue);
    expect(server.isComplete, isTrue);

    final http = PqHttpClient();
    final resp = await http.roundTripH1(
      tls: client,
      request: PqHttpRequest(
        method: 'GET',
        uri: Uri.parse('https://example.test/dns-query'),
      ),
    );
    expect(resp.isSuccess, isTrue, reason: '${resp.errorOrNull}');
    expect(resp.valueOrNull!.status, 200);
    expect(String.fromCharCodes(resp.valueOrNull!.body), 'pq-ok');

    final cExp = client.exporter('http', Uint8List(0), 16);
    final sExp = server.exporter('http', Uint8List(0), 16);
    expect(cExp, sExp);

    await sub.cancel();
    await client.close();
    await server.close();
  }, timeout: const Timeout(Duration(seconds: 40)));
}
