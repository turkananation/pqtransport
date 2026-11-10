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
}
