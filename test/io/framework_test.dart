@TestOn('vm')
library;

import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

import 'package:pqtransport/pqtransport_io.dart';
import 'package:pqtransport/relic.dart';
import 'package:pqtransport/shelf.dart';
import 'package:relic_core/relic_core.dart' hide Result;
import 'package:shelf/shelf.dart' as shelf;
import 'package:swissarmyknife/swissarmyknife.dart';
import 'package:test/test.dart';

void main() {
  test('a Shelf handler replaces SecurityContext', () async {
    final crypto = PqTransportCrypto();
    final identity = PqTlsServerIdentity.generate(crypto);
    final server = await serveShelf(
      (request) => shelf.Response.ok('shelf-ok ${request.requestedUri.path}'),
      InternetAddress.loopbackIPv4,
      0,
      identity: identity,
    );
    addTearDown(server.close);
    final response = await _get(crypto, server.port, '/shelf');
    expect(response.isSuccess, isTrue, reason: '${response.errorOrNull}');
    expect(response.valueOrNull!.status, 200);
    expect(String.fromCharCodes(response.valueOrNull!.body), 'shelf-ok /shelf');
  });

  test('a Relic adapter replaces IOAdapter SecurityContext', () async {
    final crypto = PqTransportCrypto();
    final identity = PqTlsServerIdentity.generate(crypto);
    final adapter = await PqRelicAdapter.bind(
      InternetAddress.loopbackIPv4,
      0,
      identity: identity,
    );
    final relic = RelicServer(() => adapter);
    await relic.mountAndStart(
      (request) =>
          Response.ok(body: Body.fromString('relic-ok ${request.url.path}')),
    );
    addTearDown(relic.close);
    final response = await _get(crypto, adapter.port, '/relic');
    expect(response.isSuccess, isTrue, reason: '${response.errorOrNull}');
    expect(response.valueOrNull!.status, 200);
    expect(String.fromCharCodes(response.valueOrNull!.body), 'relic-ok /relic');
  });

  test('Expect 100-continue, then the body, then 200', () async {
    final crypto = PqTransportCrypto();
    final identity = PqTlsServerIdentity.generate(crypto);
    final server = await PqHttpServer.bind(
      InternetAddress.loopbackIPv4,
      0,
      identity: identity,
    );
    addTearDown(server.close);
    server.mount((request) async {
      return PqHttpResponse(
        status: 200,
        headers: const {},
        body: Uint8List.fromList(
          'got:${String.fromCharCodes(request.body)}'.codeUnits,
        ),
        version: HttpVersion.h1,
      );
    });
    final tls = await _tls(crypto, server.port);
    addTearDown(tls.close);
    final app = _App(tls);
    addTearDown(app.close);
    await tls.send(
      Uint8List.fromList(
        'POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 5\r\n'
                'Expect: 100-continue\r\n\r\n'
            .codeUnits,
      ),
    );
    final interim = await app.until(
      (raw) => String.fromCharCodes(raw).contains('\r\n\r\n'),
    );
    expect(String.fromCharCodes(interim), 'HTTP/1.1 100 Continue\r\n\r\n');
    app.consume(interim.length);
    await tls.send(Uint8List.fromList('Hello'.codeUnits));
    final finalBytes = await app.until((raw) {
      final parsed = tryParseHttp1Response(raw, closed: false);
      return parsed.isSuccess && parsed.valueOrNull!.response?.status == 200;
    });
    final parsed = tryParseHttp1Response(finalBytes, closed: false);
    expect(
      String.fromCharCodes(parsed.valueOrNull!.response!.body),
      'got:Hello',
    );
  });

  test(
    'a buffered Expect body does not get 100, and a bad Expect is 417',
    () async {
      final crypto = PqTransportCrypto();
      final identity = PqTlsServerIdentity.generate(crypto);
      final server = await PqHttpServer.bind(
        InternetAddress.loopbackIPv4,
        0,
        identity: identity,
      );
      addTearDown(server.close);
      server.mount((request) async {
        return PqHttpResponse(
          status: 200,
          headers: const {},
          body: Uint8List.fromList(request.body),
          version: HttpVersion.h1,
        );
      });
      final tls = await _tls(crypto, server.port);
      addTearDown(tls.close);
      final app = _App(tls);
      addTearDown(app.close);
      await tls.send(
        Uint8List.fromList(
          'POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 5\r\n'
                  'Expect: 100-continue\r\n\r\nHello'
              .codeUnits,
        ),
      );
      final ok = await app.until((raw) {
        final parsed = tryParseHttp1Response(raw, closed: false);
        return parsed.isSuccess && !parsed.valueOrNull!.incomplete;
      });
      final text = String.fromCharCodes(ok);
      expect(text, isNot(contains('100 Continue')));
      expect(text, startsWith('HTTP/1.1 200 OK\r\n'));
      await tls.close();

      final again = await _tls(crypto, server.port);
      addTearDown(again.close);
      final second = _App(again);
      addTearDown(second.close);
      await again.send(
        Uint8List.fromList(
          'POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 1\r\n'
                  'Expect: no-thanks\r\n\r\n'
              .codeUnits,
        ),
      );
      final rejected = await second.until(
        (raw) => String.fromCharCodes(raw).contains('\r\n\r\n'),
      );
      expect(
        String.fromCharCodes(rejected),
        startsWith('HTTP/1.1 417 Expectation Failed\r\n'),
      );
    },
  );

  test(
    'Shelf hijack sees the unread body and writes the raw response',
    () async {
      final crypto = PqTransportCrypto();
      final identity = PqTlsServerIdentity.generate(crypto);
      final server = await serveShelf(
        (request) {
          expect(request.method, 'POST');
          request.hijack((channel) {
            expect(channel.stream.first, completion(equals('Hello'.codeUnits)));
            channel.sink.add(
              'HTTP/1.1 404 Not Found\r\n'
                      'date: Mon, 23 May 2005 22:38:34 GMT\r\n'
                      'Content-Length: 13\r\n'
                      '\r\n'
                      'Hello, world!'
                  .codeUnits,
            );
            unawaited(channel.sink.close());
          });
        },
        InternetAddress.loopbackIPv4,
        0,
        identity: identity,
      );
      addTearDown(server.close);
      final response = await _post(crypto, server.port, 'Hello');
      expect(response.isSuccess, isTrue, reason: '${response.errorOrNull}');
      expect(response.valueOrNull!.status, 404);
      expect(
        response.valueOrNull!.headers['date'],
        'Mon, 23 May 2005 22:38:34 GMT',
      );
      expect(String.fromCharCodes(response.valueOrNull!.body), 'Hello, world!');
    },
  );

  test(
    'close of an idle connection does not wait out the idle timeout',
    () async {
      final crypto = PqTransportCrypto();
      final identity = PqTlsServerIdentity.generate(crypto);
      final server = await PqHttpServer.bind(
        InternetAddress.loopbackIPv4,
        0,
        identity: identity,
        config: const PqHttpServerConfig(idleTimeout: Duration(seconds: 30)),
      );
      server.mount((request) async {
        return PqHttpResponse(
          status: 204,
          headers: const {},
          body: Uint8List(0),
          version: HttpVersion.h1,
        );
      });
      final tls = await _tls(crypto, server.port);
      addTearDown(tls.close);
      final watch = Stopwatch()..start();
      await server.close();
      expect(watch.elapsed, lessThan(const Duration(seconds: 2)));
    },
  );
}

Future<Result<PqHttpResponse, PqTransportError>> _get(
  PqTransportCrypto crypto,
  int port,
  String path,
) async {
  final socket = await IoTcpSocket.connect(
    InternetAddress.loopbackIPv4.address,
    port,
  );
  final tls = PqTlsSocket.client(
    socket,
    crypto: crypto,
    alpnProtocols: const [httpAlpnH1],
  );
  final handshake = await tls.handshake();
  if (handshake.isFailure) return Result.failure(handshake.errorOrNull!);
  final response = await PqHttpClient().roundTripH1(
    tls: tls,
    request: PqHttpRequest(
      method: 'GET',
      uri: Uri.parse('https://localhost$path'),
    ),
  );
  await tls.close();
  return response;
}

Future<PqTlsSocket> _tls(PqTransportCrypto crypto, int port) async {
  final socket = await IoTcpSocket.connect(
    InternetAddress.loopbackIPv4.address,
    port,
  );
  final tls = PqTlsSocket.client(
    socket,
    crypto: crypto,
    alpnProtocols: const [httpAlpnH1],
  );
  final handshake = await tls.handshake();
  if (handshake.isFailure) {
    throw handshake.errorOrNull!;
  }
  return tls;
}

Future<Result<PqHttpResponse, PqTransportError>> _post(
  PqTransportCrypto crypto,
  int port,
  String body,
) async {
  final tls = await _tls(crypto, port);
  final response = await PqHttpClient().roundTripH1(
    tls: tls,
    request: PqHttpRequest(
      method: 'POST',
      uri: Uri.parse('https://localhost/'),
      body: body.codeUnits,
    ),
  );
  await tls.close();
  return response;
}

final class _App {
  _App(PqTlsSocket tls) {
    _sub = tls.applicationData.listen((chunk) {
      _chunks.add(chunk);
      for (final waiter in List<Completer<void>>.of(_waiters)) {
        if (!waiter.isCompleted) waiter.complete();
      }
      _waiters.clear();
    });
  }

  final _chunks = <Uint8List>[];
  final _waiters = <Completer<void>>[];
  var _offset = 0;
  late final StreamSubscription<Uint8List> _sub;

  Uint8List get bytes {
    final all = BytesBuilder(copy: false);
    for (final chunk in _chunks) {
      all.add(chunk);
    }
    return Uint8List.sublistView(all.toBytes(), _offset);
  }

  void consume(int count) {
    _offset += count;
  }

  Future<Uint8List> until(bool Function(Uint8List raw) ready) async {
    while (true) {
      final raw = bytes;
      if (ready(raw)) return raw;
      final waiter = Completer<void>();
      _waiters.add(waiter);
      if (ready(bytes) && !waiter.isCompleted) waiter.complete();
      await waiter.future.timeout(const Duration(seconds: 10));
    }
  }

  Future<void> close() => _sub.cancel();
}
