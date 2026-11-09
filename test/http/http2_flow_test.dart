import 'dart:typed_data';

import 'package:pqtransport/pqtransport.dart';
import 'package:test/test.dart';

void main() {
  final crypto = PqTransportCrypto();

  Future<(PqTlsSocket, PqTlsSocket, PqHttp2Session, PqHttp2Session)>
  pair() async {
    final identity = PqTlsServerIdentity.generate(crypto);
    final sockets = MemoryByteSocket.pair();
    final client = PqTlsSocket.client(
      sockets.$1,
      crypto: crypto,
      alpnProtocols: const [httpAlpnH2],
    );
    final server = PqTlsSocket.server(
      sockets.$2,
      crypto: crypto,
      identity: identity,
      alpnProtocols: const [httpAlpnH2],
    );
    final hs = await Future.wait([server.handshake(), client.handshake()]);
    expect(hs[0].isSuccess, isTrue, reason: '${hs[0].errorOrNull}');
    expect(hs[1].isSuccess, isTrue, reason: '${hs[1].errorOrNull}');
    return (
      client,
      server,
      PqHttp2Session.client(client),
      PqHttp2Session.server(server),
    );
  }

  test(
    'a body past 65535 waits for WINDOW_UPDATE and trailers arrive',
    () async {
      final (client, server, clientH2, serverH2) = await pair();
      final body = Uint8List(http2DefaultInitialWindowSize + 4096);
      for (var i = 0; i < body.length; i++) {
        body[i] = i & 0xff;
      }
      final serving = () async {
        final accepted = await serverH2.accept(
          timeout: const Duration(seconds: 20),
        );
        expect(accepted.isSuccess, isTrue, reason: '${accepted.errorOrNull}');
        final (id, req) = accepted.valueOrNull!;
        expect(req.body, body);
        final sent = await serverH2.respond(
          id,
          PqHttpResponse(
            status: 200,
            headers: const {'content-type': 'text/plain'},
            body: Uint8List.fromList('ok'.codeUnits),
            version: HttpVersion.h2,
          ),
          trailers: const {'x-checksum': '1'},
        );
        expect(sent.isSuccess, isTrue, reason: '${sent.errorOrNull}');
      }();
      final resp = await clientH2.request(
        PqHttpRequest(
          method: 'POST',
          uri: Uri.parse('https://example.test/big'),
          body: body,
        ),
        timeout: const Duration(seconds: 20),
      );
      expect(resp.isSuccess, isTrue, reason: '${resp.errorOrNull}');
      expect(String.fromCharCodes(resp.valueOrNull!.body), 'ok');
      expect(resp.valueOrNull!.trailers['x-checksum'], '1');
      expect(clientH2.streamState(1), Http2StreamState.closed);
      await serving;

      await client.send(
        Http2Frame(
          type: http2FramePriority,
          flags: 0,
          streamId: 1,
          payload: Uint8List.fromList([0, 0, 0, 0, 0]),
        ).encode(),
      );
      final again = () async {
        final accepted = await serverH2.accept(
          timeout: const Duration(seconds: 20),
        );
        expect(accepted.isSuccess, isTrue, reason: '${accepted.errorOrNull}');
        await serverH2.respond(
          accepted.valueOrNull!.$1,
          PqHttpResponse(
            status: 204,
            headers: const {},
            body: Uint8List(0),
            version: HttpVersion.h2,
          ),
        );
      }();
      final second = await clientH2.request(
        PqHttpRequest(
          method: 'GET',
          uri: Uri.parse('https://example.test/next'),
        ),
      );
      expect(second.isSuccess, isTrue, reason: '${second.errorOrNull}');
      expect(second.valueOrNull!.status, 204);
      await again;

      await serverH2.close();
      final after = await clientH2.request(
        PqHttpRequest(
          method: 'GET',
          uri: Uri.parse('https://example.test/gone'),
        ),
      );
      expect(after.isFailure, isTrue);
      expect('${after.errorOrNull}', contains('goaway'));

      await clientH2.close();
      await client.close();
      await server.close();
    },
    timeout: const Timeout(Duration(seconds: 40)),
  );

  test('WINDOW_UPDATE past 2^31-1 is FLOW_CONTROL_ERROR', () async {
    final (client, server, clientH2, serverH2) = await pair();
    await Future.wait([clientH2.ensureStarted(), serverH2.ensureStarted()]);
    await client.send(encodeHttp2WindowUpdate(0, http2MaxWindowSize));
    final accepted = await serverH2.accept(
      timeout: const Duration(seconds: 10),
    );
    expect(accepted.isFailure, isTrue);
    expect('${accepted.errorOrNull}', contains('flow control'));
    await clientH2.close();
    await serverH2.close();
    await client.close();
    await server.close();
  }, timeout: const Timeout(Duration(seconds: 40)));

  test(
    'a frame between HEADERS and CONTINUATION is an error, and push is refused',
    () async {
      final (client, server, clientH2, serverH2) = await pair();
      await Future.wait([clientH2.ensureStarted(), serverH2.ensureStarted()]);
      await client.send(
        Http2Frame(
          type: http2FrameHeaders,
          flags: 0,
          streamId: 1,
          payload: Uint8List.fromList([0x82]),
        ).encode(),
      );
      await client.send(
        Http2Frame(
          type: http2FramePing,
          flags: 0,
          streamId: 0,
          payload: Uint8List(http2PingPayloadBytes),
        ).encode(),
      );
      final accepted = await serverH2.accept(
        timeout: const Duration(seconds: 10),
      );
      expect(accepted.isFailure, isTrue);
      expect('${accepted.errorOrNull}', contains('continuation'));
      await clientH2.close();
      await serverH2.close();
      await client.close();
      await server.close();

      final pushed = await pair();
      await Future.wait([pushed.$3.ensureStarted(), pushed.$4.ensureStarted()]);
      await pushed.$1.send(
        Http2Frame(
          type: http2FramePushPromise,
          flags: http2FlagEndHeaders,
          streamId: 1,
          payload: Uint8List.fromList([0, 0, 0, 2]),
        ).encode(),
      );
      final refused = await pushed.$4.accept(
        timeout: const Duration(seconds: 10),
      );
      expect(refused.isFailure, isTrue);
      expect('${refused.errorOrNull}', contains('push'));
      await pushed.$3.close();
      await pushed.$4.close();
      await pushed.$1.close();
      await pushed.$2.close();
    },
    timeout: const Timeout(Duration(seconds: 40)),
  );

  test('a header block over one frame is CONTINUATION', () async {
    final (client, server, clientH2, serverH2) = await pair();
    final value = 'a' * 20000;
    final serving = () async {
      final accepted = await serverH2.accept(
        timeout: const Duration(seconds: 20),
      );
      expect(accepted.isSuccess, isTrue, reason: '${accepted.errorOrNull}');
      expect(accepted.valueOrNull!.$2.headers['x-b'], value);
      await serverH2.respond(
        accepted.valueOrNull!.$1,
        PqHttpResponse(
          status: 200,
          headers: const {},
          body: Uint8List(0),
          version: HttpVersion.h2,
        ),
      );
    }();
    final resp = await clientH2.request(
      PqHttpRequest(
        method: 'GET',
        uri: Uri.parse('https://example.test/cont'),
        headers: {'x-b': value},
      ),
      timeout: const Duration(seconds: 20),
    );
    expect(resp.isSuccess, isTrue, reason: '${resp.errorOrNull}');
    expect(resp.valueOrNull!.status, 200);
    await serving;
    await clientH2.close();
    await serverH2.close();
    await client.close();
    await server.close();
  }, timeout: const Timeout(Duration(seconds: 40)));

  test('a header list past the peer limit is refused', () async {
    final (client, server, clientH2, serverH2) = await pair();
    await Future.wait([clientH2.ensureStarted(), serverH2.ensureStarted()]);
    final resp = await clientH2.request(
      PqHttpRequest(
        method: 'GET',
        uri: Uri.parse('https://example.test/hdr'),
        headers: {'x-big': 'a' * 70000},
      ),
    );
    expect(resp.isFailure, isTrue);
    expect('${resp.errorOrNull}', contains('header list'));
    await clientH2.close();
    await serverH2.close();
    await client.close();
    await server.close();
  }, timeout: const Timeout(Duration(seconds: 40)));

  test('a frame over MAX_FRAME_SIZE is FRAME_SIZE_ERROR', () async {
    final (client, server, clientH2, serverH2) = await pair();
    await Future.wait([clientH2.ensureStarted(), serverH2.ensureStarted()]);
    await client.send(
      Uint8List.fromList([0x00, 0x40, 0x01, http2FrameData, 0, 0, 0, 0, 1]),
    );
    final accepted = await serverH2.accept(
      timeout: const Duration(seconds: 10),
    );
    expect(accepted.isFailure, isTrue);
    expect('${accepted.errorOrNull}', contains('frame'));
    await clientH2.close();
    await serverH2.close();
    await client.close();
    await server.close();
  }, timeout: const Timeout(Duration(seconds: 40)));

  test('DATA on an idle stream is a connection error', () async {
    final (client, server, clientH2, serverH2) = await pair();
    await Future.wait([clientH2.ensureStarted(), serverH2.ensureStarted()]);
    await client.send(
      Http2Frame(
        type: http2FrameData,
        flags: http2FlagEndStream,
        streamId: 1,
        payload: Uint8List.fromList([1]),
      ).encode(),
    );
    final accepted = await serverH2.accept(
      timeout: const Duration(seconds: 10),
    );
    expect(accepted.isFailure, isTrue);
    expect('${accepted.errorOrNull}', contains('idle'));
    await clientH2.close();
    await serverH2.close();
    await client.close();
    await server.close();
  }, timeout: const Timeout(Duration(seconds: 40)));
}
