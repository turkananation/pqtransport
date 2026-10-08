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
    expect(client.alpn, httpAlpnH1);
    expect(server.alpn, httpAlpnH1);

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

  test('HTTP/2 GET over PqTlsSocket ALPN h2', () async {
    final identity = PqTlsServerIdentity.generate(crypto);
    final (clientSock, serverSock) = MemoryByteSocket.pair();
    final client = PqTlsSocket.client(
      clientSock,
      crypto: crypto,
      alpnProtocols: const [httpAlpnH2],
    );
    final server = PqTlsSocket.server(
      serverSock,
      crypto: crypto,
      identity: identity,
      alpnProtocols: const [httpAlpnH2],
    );

    final hs = await Future.wait([server.handshake(), client.handshake()]);
    expect(hs[0].isSuccess, isTrue, reason: '${hs[0].errorOrNull}');
    expect(hs[1].isSuccess, isTrue, reason: '${hs[1].errorOrNull}');
    expect(client.alpn, httpAlpnH2);
    expect(server.alpn, httpAlpnH2);

    final serverH2 = PqHttp2Session.server(server);
    final serving = () async {
      final accepted = await serverH2.accept(
        timeout: const Duration(seconds: 20),
      );
      expect(accepted.isSuccess, isTrue, reason: '${accepted.errorOrNull}');
      final (streamId, req) = accepted.valueOrNull!;
      expect(req.method, 'GET');
      expect(req.uri.path, '/dns-query');
      final sent = await serverH2.respond(
        streamId,
        PqHttpResponse(
          status: 200,
          headers: const {'content-type': 'text/plain'},
          body: Uint8List.fromList('h2-ok'.codeUnits),
          version: HttpVersion.h2,
        ),
      );
      expect(sent.isSuccess, isTrue, reason: '${sent.errorOrNull}');
    }();

    final http = PqHttpClient(prefer: HttpVersion.h2);
    final resp = await http.roundTripH2(
      tls: client,
      request: PqHttpRequest(
        method: 'GET',
        uri: Uri.parse('https://example.test/dns-query'),
      ),
    );
    expect(resp.isSuccess, isTrue, reason: '${resp.errorOrNull}');
    expect(resp.valueOrNull!.status, 200);
    expect(resp.valueOrNull!.version, HttpVersion.h2);
    expect(String.fromCharCodes(resp.valueOrNull!.body), 'h2-ok');
    expect(resp.valueOrNull!.headers['content-type'], 'text/plain');

    await serving;
    await serverH2.close();
    await client.close();
    await server.close();
  }, timeout: const Timeout(Duration(seconds: 40)));

  test('HTTP/2 POST with body over PqTlsSocket', () async {
    final identity = PqTlsServerIdentity.generate(crypto);
    final (clientSock, serverSock) = MemoryByteSocket.pair();
    final client = PqTlsSocket.client(
      clientSock,
      crypto: crypto,
      alpnProtocols: const [httpAlpnH2, httpAlpnH1],
    );
    final server = PqTlsSocket.server(
      serverSock,
      crypto: crypto,
      identity: identity,
      alpnProtocols: const [httpAlpnH2, httpAlpnH1],
    );
    final hs = await Future.wait([server.handshake(), client.handshake()]);
    expect(hs[0].isSuccess, isTrue, reason: '${hs[0].errorOrNull}');
    expect(client.alpn, httpAlpnH2);

    final serverH2 = PqHttp2Session.server(server);
    final serving = () async {
      final accepted = await serverH2.accept(
        timeout: const Duration(seconds: 20),
      );
      expect(accepted.isSuccess, isTrue, reason: '${accepted.errorOrNull}');
      final (streamId, req) = accepted.valueOrNull!;
      expect(req.method, 'POST');
      expect(String.fromCharCodes(req.body), 'ping-body');
      await serverH2.respond(
        streamId,
        PqHttpResponse(
          status: 204,
          headers: const {},
          body: Uint8List(0),
          version: HttpVersion.h2,
        ),
      );
    }();

    final clientH2 = PqHttp2Session.client(client);
    final resp = await clientH2.request(
      PqHttpRequest(
        method: 'POST',
        uri: Uri.parse('https://example.test/echo'),
        headers: const {'content-type': 'text/plain'},
        body: 'ping-body'.codeUnits,
      ),
    );
    expect(resp.isSuccess, isTrue, reason: '${resp.errorOrNull}');
    expect(resp.valueOrNull!.status, 204);
    expect(resp.valueOrNull!.body, isEmpty);

    await serving;
    await clientH2.close();
    await serverH2.close();
    await client.close();
    await server.close();
  }, timeout: const Timeout(Duration(seconds: 40)));

  test('ALPN no overlap is no_application_protocol', () async {
    final identity = PqTlsServerIdentity.generate(crypto);
    final (clientSock, serverSock) = MemoryByteSocket.pair();
    final client = PqTlsSocket.client(
      clientSock,
      crypto: crypto,
      alpnProtocols: const [httpAlpnH2],
    );
    final server = PqTlsSocket.server(
      serverSock,
      crypto: crypto,
      identity: identity,
      alpnProtocols: const [httpAlpnH1],
    );
    final hs = await Future.wait([server.handshake(), client.handshake()]);
    final failed = hs.where((r) => r.isFailure).toList();
    expect(failed, isNotEmpty);
    expect(
      failed.first.errorOrNull!.message,
      contains('no_application_protocol'),
    );
    await client.close();
    await server.close();
  }, timeout: const Timeout(Duration(seconds: 40)));

  test('prefer h2 refuses silent downgrade to http/1.1 ALPN', () async {
    final identity = PqTlsServerIdentity.generate(crypto);
    final (clientSock, serverSock) = MemoryByteSocket.pair();
    final client = PqTlsSocket.client(clientSock, crypto: crypto);
    final server = PqTlsSocket.server(
      serverSock,
      crypto: crypto,
      identity: identity,
    );
    final hs = await Future.wait([server.handshake(), client.handshake()]);
    expect(hs[0].isSuccess && hs[1].isSuccess, isTrue);
    expect(client.alpn, httpAlpnH1);

    final refused = await PqHttpClient(prefer: HttpVersion.h2).roundTrip(
      tls: client,
      request: PqHttpRequest(
        method: 'GET',
        uri: Uri.parse('https://example.test/'),
      ),
    );
    expect(refused.isFailure, isTrue);
    expect(refused.errorOrNull!.message, contains('h2 downgrade'));

    late StreamSubscription<Uint8List> sub;
    sub = server.applicationData.listen((req) async {
      await server.send(
        encodeHttp1Response(
          PqHttpResponse(
            status: 200,
            headers: const {},
            body: Uint8List.fromList('downgraded'.codeUnits),
            version: HttpVersion.h1,
          ),
        ),
      );
    });
    final allowed =
        await PqHttpClient(
          prefer: HttpVersion.h2,
          allowDowngrade: true,
        ).roundTrip(
          tls: client,
          request: PqHttpRequest(
            method: 'GET',
            uri: Uri.parse('https://example.test/'),
          ),
        );
    expect(allowed.isSuccess, isTrue, reason: '${allowed.errorOrNull}');
    expect(String.fromCharCodes(allowed.valueOrNull!.body), 'downgraded');

    await sub.cancel();
    await client.close();
    await server.close();
  }, timeout: const Timeout(Duration(seconds: 40)));
}
