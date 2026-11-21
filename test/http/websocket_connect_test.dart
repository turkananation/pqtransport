import 'dart:typed_data';

import 'package:pqtransport/pqtransport.dart';
import 'package:test/test.dart';

void main() {
  final crypto = PqTransportCrypto();

  test('HTTP/2 extended CONNECT carries one WebSocket text frame', () async {
    final sockets = MemoryByteSocket.pair();
    final identity = PqTlsServerIdentity.generate(crypto);
    final clientTls = PqTlsSocket.client(
      sockets.$1,
      crypto: crypto,
      alpnProtocols: const [httpAlpnH2],
    );
    final serverTls = PqTlsSocket.server(
      sockets.$2,
      crypto: crypto,
      identity: identity,
      alpnProtocols: const [httpAlpnH2],
    );
    final hs = await Future.wait([
      serverTls.handshake(),
      clientTls.handshake(),
    ]);
    expect(hs.every((r) => r.isSuccess), isTrue);
    final client = PqHttp2Session.client(clientTls);
    final server = PqHttp2Session.server(serverTls);
    final serving = () async {
      final accepted = await server.accept(
        untilFin: false,
        timeout: const Duration(seconds: 10),
      );
      expect(accepted.isSuccess, isTrue, reason: '${accepted.errorOrNull}');
      final (id, request) = accepted.valueOrNull!;
      expect(request.protocol, 'websocket');
      final responded = await server.respond(
        id,
        PqHttpResponse(
          status: 200,
          headers: const {},
          body: Uint8List(0),
          version: HttpVersion.h2,
        ),
        fin: false,
      );
      expect(responded.isSuccess, isTrue, reason: '${responded.errorOrNull}');
      final data = await server.readData(id);
      expect(data.isSuccess, isTrue, reason: '${data.errorOrNull}');
      final events = WebSocketDecoder(
        expectMasked: true,
      ).add(data.valueOrNull!);
      expect(events.isSuccess, isTrue, reason: '${events.errorOrNull}');
      final text = events.valueOrNull!.single as WebSocketInboundData;
      expect(text.text, isTrue);
      expect(String.fromCharCodes(text.data), 'pq-ws');
    }();
    final opened = await client.beginRequest(
      PqHttpRequest(
        method: 'CONNECT',
        uri: Uri.parse('https://localhost/pq'),
        protocol: 'websocket',
      ),
    );
    expect(opened.isSuccess, isTrue, reason: '${opened.errorOrNull}');
    final response = await client.readResponse(
      opened.valueOrNull!,
      untilFin: false,
    );
    expect(response.valueOrNull!.status, 200);
    final wrote = await client.writeData(
      opened.valueOrNull!,
      encodeWebSocketData(
        text: true,
        fromClient: true,
        data: Uint8List.fromList('pq-ws'.codeUnits),
      ),
    );
    expect(wrote.isSuccess, isTrue, reason: '${wrote.errorOrNull}');
    await serving;
  });

  test('HTTP/3 extended CONNECT carries one WebSocket text frame', () async {
    final pair = PqQuicConn.pair(
      crypto: crypto,
      alpnProtocols: const [httpAlpnH3],
    );
    final hs = await Future.wait([pair.$1.handshake(), pair.$2.handshake()]);
    expect(hs.every((r) => r.isSuccess), isTrue);
    final client = PqHttp3Session.client(pair.$1);
    final server = PqHttp3Session.server(pair.$2);
    final started = await Future.wait([client.start(), server.start()]);
    expect(started.every((r) => r.isSuccess), isTrue);
    final serving = () async {
      final accepted = await server.accept(
        untilFin: false,
        timeout: const Duration(seconds: 10),
      );
      expect(accepted.isSuccess, isTrue, reason: '${accepted.errorOrNull}');
      final (id, request) = accepted.valueOrNull!;
      expect(request.protocol, 'websocket');
      final responded = await server.respond(
        id,
        PqHttpResponse(
          status: 200,
          headers: const {},
          body: Uint8List(0),
          version: HttpVersion.h3,
        ),
        fin: false,
      );
      expect(responded.isSuccess, isTrue, reason: '${responded.errorOrNull}');
      final data = await server.readData(id);
      expect(data.isSuccess, isTrue, reason: '${data.errorOrNull}');
      final events = WebSocketDecoder(
        expectMasked: true,
      ).add(data.valueOrNull!);
      expect(events.isSuccess, isTrue, reason: '${events.errorOrNull}');
      expect(
        String.fromCharCodes(
          (events.valueOrNull!.single as WebSocketInboundData).data,
        ),
        'pq-ws',
      );
    }();
    final opened = await client.beginRequest(
      PqHttpRequest(
        method: 'CONNECT',
        uri: Uri.parse('https://localhost/pq'),
        protocol: 'websocket',
      ),
      fin: false,
    );
    expect(opened.isSuccess, isTrue, reason: '${opened.errorOrNull}');
    final response = await client.readResponse(
      opened.valueOrNull!,
      untilFin: false,
    );
    expect(response.isSuccess, isTrue, reason: '${response.errorOrNull}');
    expect(response.valueOrNull!.status, 200);
    final wrote = await client.writeData(
      opened.valueOrNull!,
      encodeWebSocketData(
        text: true,
        fromClient: true,
        data: Uint8List.fromList('pq-ws'.codeUnits),
      ),
    );
    expect(wrote.isSuccess, isTrue, reason: '${wrote.errorOrNull}');
    await serving;
  });
}
