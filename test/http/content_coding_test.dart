@TestOn('vm')
library;

import 'dart:io';
import 'dart:typed_data';

import 'package:pqtransport/pqtransport_io.dart';
import 'package:pqtransport/src/http/content_coding.dart';
import 'package:test/test.dart';

void main() {
  test('q-values pick deflate ahead of gzip when deflate is preferred', () {
    expect(selectContentCoding('gzip;q=0.5, deflate;q=1.0, br'), 'deflate');
    expect(selectContentCoding('gzip, deflate;q=0'), 'gzip');
    expect(selectContentCoding('br, zstd'), isNull);
  });

  test('deflate is the zlib wrapper, not raw DEFLATE', () {
    final clear = Uint8List.fromList('pq-deflate'.codeUnits);
    final wire = zlib.encode(clear);
    expect(wire[0], 0x78);
    final back = decodeContentCoding('deflate', Uint8List.fromList(wire));
    expect(back.isSuccess, isTrue);
    expect(back.valueOrNull, clear);
    final again = encodeContentCoding('deflate', clear);
    expect(
      decodeContentCoding('deflate', again.valueOrNull!).valueOrNull,
      clear,
    );
  });

  test('gzip is RFC 1952 and round-trips', () {
    final clear = Uint8List.fromList('pq-gzip'.codeUnits);
    final wire = gzip.encode(clear);
    expect(wire[0], 0x1f);
    expect(wire[1], 0x8b);
    final back = decodeContentCoding('gzip', Uint8List.fromList(wire));
    expect(back.isSuccess, isTrue, reason: '${back.errorOrNull}');
    expect(back.valueOrNull, clear);
  });

  test('HTTP/2 inflates a request and gzips the response', () async {
    final crypto = PqTransportCrypto();
    final identity = PqTlsServerIdentity.generate(crypto);
    final server = await PqHttpServer.bind(
      InternetAddress.loopbackIPv4,
      0,
      identity: identity,
      crypto: crypto,
    );
    Uint8List? seen;
    server.mount((request) async {
      seen = Uint8List.fromList(request.body);
      return PqHttpResponse(
        status: 200,
        headers: const {},
        body: Uint8List.fromList('pq-out'.codeUnits),
        version: HttpVersion.h2,
      );
    });
    final sock = await IoTcpSocket.connect('127.0.0.1', server.port);
    final tls = PqTlsSocket.client(
      sock,
      crypto: crypto,
      alpnProtocols: const [httpAlpnH2],
    );
    final hs = await tls.handshake();
    expect(hs.isSuccess, isTrue, reason: '${hs.errorOrNull}');
    expect(tls.alpn, httpAlpnH2);
    final session = PqHttp2Session.client(tls);
    final compressed = Uint8List.fromList(
      gzip.encode(Uint8List.fromList('pq-in'.codeUnits)),
    );
    final raw = await session.request(
      PqHttpRequest(
        method: 'POST',
        uri: Uri.parse('https://localhost/echo'),
        headers: const {'content-encoding': 'gzip', 'accept-encoding': 'gzip'},
        body: compressed,
      ),
    );
    expect(raw.isSuccess, isTrue, reason: '${raw.errorOrNull}');
    expect(seen, Uint8List.fromList('pq-in'.codeUnits));
    final headers = raw.valueOrNull!.headers;
    final coding = headers.entries
        .where((entry) => entry.key.toLowerCase() == 'content-encoding')
        .map((entry) => entry.value)
        .join(',');
    expect(coding, 'gzip');
    expect(gzip.decode(raw.valueOrNull!.body), 'pq-out'.codeUnits);
    await session.close();
    await tls.close();

    final sock2 = await IoTcpSocket.connect('127.0.0.1', server.port);
    final tls2 = PqTlsSocket.client(
      sock2,
      crypto: crypto,
      alpnProtocols: const [httpAlpnH2],
    );
    final hs2 = await tls2.handshake();
    expect(hs2.isSuccess, isTrue, reason: '${hs2.errorOrNull}');
    final inflated = await PqHttpClient(prefer: HttpVersion.h2).roundTripH2(
      tls: tls2,
      request: PqHttpRequest(
        method: 'GET',
        uri: Uri.parse('https://localhost/echo'),
        headers: const {'accept-encoding': 'gzip'},
      ),
    );
    expect(inflated.isSuccess, isTrue, reason: '${inflated.errorOrNull}');
    expect(String.fromCharCodes(inflated.valueOrNull!.body), 'pq-out');
    expect(
      inflated.valueOrNull!.headers.keys.map((key) => key.toLowerCase()),
      isNot(contains('content-encoding')),
    );
    await tls2.close();
    await server.close();
  });
}
