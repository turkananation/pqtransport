import 'dart:typed_data';

import 'package:pqtransport/pqtransport.dart';
import 'package:test/test.dart';

void main() {
  Uint8List ascii(String text) => Uint8List.fromList(text.codeUnits);

  test('chunked body and trailer', () {
    final wire = ascii(
      'POST /pq HTTP/1.1\r\n'
      'Host: localhost\r\n'
      'Transfer-Encoding: chunked\r\n'
      '\r\n'
      '4\r\n'
      'pq-h\r\n'
      '2\r\n'
      '1!\r\n'
      '0\r\n'
      'x-trail: yes\r\n'
      '\r\n',
    );
    final parsed = tryParseHttp1Request(wire);
    expect(parsed.isSuccess, isTrue, reason: '${parsed.errorOrNull}');
    final request = parsed.valueOrNull!.request!;
    expect(String.fromCharCodes(request.body), 'pq-h1!');
    expect(request.trailers['x-trail'], 'yes');
    expect(parsed.valueOrNull!.consumed, wire.length);
  });

  test('a short buffer is incomplete, then one message', () {
    final full = ascii('HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\npq-h');
    final head = tryParseHttp1Response(
      Uint8List.sublistView(full, 0, 20),
      closed: false,
    );
    expect(head.valueOrNull!.incomplete, isTrue);
    final done = tryParseHttp1Response(full, closed: false);
    expect(String.fromCharCodes(done.valueOrNull!.response!.body), 'pq-h');
  });

  test('obs-fold and Content-Length plus chunked fail', () {
    final folded = tryParseHttp1Request(
      ascii('GET / HTTP/1.1\r\nHost: localhost\r\n \tmore\r\n\r\n'),
    );
    expect(folded.errorOrNull!.message, contains('obs-fold'));
    final both = tryParseHttp1Request(
      ascii(
        'POST / HTTP/1.1\r\nHost: localhost\r\n'
        'Content-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\n',
      ),
    );
    expect(both.errorOrNull!.message, contains('length'));
  });

  test('two different Content-Length values fail', () {
    final parsed = tryParseHttp1Request(
      ascii(
        'POST / HTTP/1.1\r\nHost: localhost\r\n'
        'Content-Length: 1\r\nContent-Length: 2\r\n\r\n',
      ),
    );
    expect(parsed.isFailure, isTrue);
  });

  test('reason phrase is the registered one, not always OK', () {
    final wire = String.fromCharCodes(
      encodeHttp1Response(
        PqHttpResponse(
          status: 404,
          headers: const {},
          body: Uint8List(0),
          version: HttpVersion.h1,
        ),
      ),
    );
    expect(wire, startsWith('HTTP/1.1 404 Not Found\r\n'));
    expect(wire, contains('content-length: 0\r\n'));
  });

  test('chunked response encoding round-trips', () {
    final wire = encodeHttp1Response(
      PqHttpResponse(
        status: 200,
        headers: const {'transfer-encoding': 'chunked'},
        body: Uint8List.fromList('pq-h1'.codeUnits),
        version: HttpVersion.h1,
        trailers: const {'x-trail': 'yes'},
      ),
    );
    final parsed = tryParseHttp1Response(wire, closed: false);
    expect(parsed.isSuccess, isTrue, reason: '${parsed.errorOrNull}');
    final response = parsed.valueOrNull!.response!;
    expect(String.fromCharCodes(response.body), 'pq-h1');
    expect(response.trailers['x-trail'], 'yes');
  });

  test('Connection: close is reported', () {
    final parsed = tryParseHttp1Request(
      ascii('GET /pq HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n'),
    );
    expect(parsed.valueOrNull!.close, isTrue);
    expect(parsed.valueOrNull!.request!.uri.path, '/pq');
  });

  test('HTTP/1.1 without Host, or two Host fields, fails', () {
    final missing = tryParseHttp1Request(ascii('GET /pq HTTP/1.1\r\n\r\n'));
    expect(missing.errorOrNull!.message, contains('host'));
    final twice = tryParseHttp1Request(
      ascii('GET /pq HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n'),
    );
    expect(twice.errorOrNull!.message, contains('host'));
    final controls = tryParseHttp1Request(
      ascii('GET /pq HTTP/1.1\r\nHost: a\x00b\r\n\r\n'),
    );
    expect(controls.errorOrNull!.message, contains('host'));
    final http10 = tryParseHttp1Request(ascii('GET /pq HTTP/1.0\r\n\r\n'));
    expect(http10.isSuccess, isTrue, reason: '${http10.errorOrNull}');
    final absolute = tryParseHttp1Request(
      ascii('GET https://example.test/pq HTTP/1.1\r\n\r\n'),
    );
    expect(absolute.errorOrNull!.message, contains('host'));
  });

  test('two keep-alive responses are consumed one at a time', () {
    final wire = ascii(
      'HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nA'
      'HTTP/1.1 200 OK\r\nContent-Length: 1\r\nConnection: close\r\n\r\nB',
    );
    final first = tryParseHttp1Response(wire, closed: false);
    expect(first.valueOrNull!.incomplete, isFalse);
    expect(first.valueOrNull!.close, isFalse);
    expect(String.fromCharCodes(first.valueOrNull!.response!.body), 'A');
    final rest = Uint8List.sublistView(wire, first.valueOrNull!.consumed);
    final second = tryParseHttp1Response(rest, closed: false);
    expect(String.fromCharCodes(second.valueOrNull!.response!.body), 'B');
    expect(second.valueOrNull!.close, isTrue);
  });

  test(
    'identical Content-Length, chunk extensions, and close-delimited bodies',
    () {
      // RFC 9112 §6.3: duplicate Content-Length is an error only when
      // the values differ. The same value twice is one length.
      final same = tryParseHttp1Request(
        ascii(
          'POST / HTTP/1.1\r\nHost: localhost\r\n'
          'Content-Length: 1\r\nContent-Length: 1\r\n\r\nZ',
        ),
      );
      expect(same.isSuccess, isTrue, reason: '${same.errorOrNull}');
      expect(String.fromCharCodes(same.valueOrNull!.request!.body), 'Z');
      final emptyHost = tryParseHttp1Request(
        ascii('GET / HTTP/1.0\r\nHost: \r\n\r\n'),
      );
      expect(emptyHost.errorOrNull!.message, contains('host'));

      // RFC 9112 §7.1.1. A recipient ignores a chunk extension it does
      // not understand, including one on the last chunk.
      final ext = ascii(
        'HTTP/1.1 200 OK\r\nTransfer-Encoding: Chunked\r\n\r\n'
        '5;ext=1\r\nhello\r\n'
        '0;last\r\n\r\n',
      );
      final parsed = tryParseHttp1Response(ext, closed: false);
      expect(parsed.isSuccess, isTrue, reason: '${parsed.errorOrNull}');
      expect(String.fromCharCodes(parsed.valueOrNull!.response!.body), 'hello');

      // No Content-Length and no chunked: the body is the rest of the
      // connection, not an empty message while the socket is still open.
      final untilClose = ascii('HTTP/1.0 200 OK\r\n\r\nhello');
      final open = tryParseHttp1Response(untilClose, closed: false);
      expect(open.valueOrNull!.incomplete, isTrue);
      final shut = tryParseHttp1Response(untilClose, closed: true);
      expect(String.fromCharCodes(shut.valueOrNull!.response!.body), 'hello');
    },
  );
}
