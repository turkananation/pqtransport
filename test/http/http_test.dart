import 'dart:typed_data';

import 'package:pqtransport/pqtransport.dart';
import 'package:test/test.dart';

void main() {
  test('HTTP/1.1 request/response round trip', () {
    final req = PqHttpRequest(
      method: 'GET',
      uri: Uri.parse('https://example.test/dns-query'),
    );
    final wire = encodeHttp1Request(req);
    expect(String.fromCharCodes(wire), contains('GET /dns-query HTTP/1.1'));
    final resp = decodeHttp1Response(
      Uint8List.fromList(
        'HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nhi'.codeUnits,
      ),
    );
    expect(resp.isSuccess, isTrue);
    expect(resp.valueOrNull!.status, 200);
    expect(String.fromCharCodes(resp.valueOrNull!.body), 'hi');
  });

  test('HTTP/1.1 rejects truncated response', () {
    final r = decodeHttp1Response(Uint8List.fromList('HTTP/1.1'.codeUnits));
    expect(r.isFailure, isTrue);
  });

  test('HTTP/3 frame round trip', () {
    final f = Http3Frame(
      type: http3FrameData,
      payload: Uint8List.fromList([1, 2, 3]),
    );
    final dec = Http3Frame.decode(f.encode());
    expect(dec.isSuccess, isTrue);
    expect(dec.valueOrNull!.payload, [1, 2, 3]);
  });

  test('HTTP/3 empty and truncated frames fail', () {
    expect(Http3Frame.decode(Uint8List(0)).isFailure, isTrue);
    expect(Http3Frame.decode(Uint8List.fromList([0x01])).isFailure, isTrue);
  });

  test('PqHttpClient default refuses silent h3 downgrade', () {
    final c = PqHttpClient(prefer: HttpVersion.h3, allowDowngrade: false);
    expect(c.allowDowngrade, isFalse);
    expect(c.prefer, HttpVersion.h3);
  });

  test('roundTripH1 refuses incomplete TLS', () async {
    final (a, _) = MemoryByteSocket.pair();
    final tls = PqTlsSocket.client(a);
    final r = await PqHttpClient().roundTripH1(
      tls: tls,
      request: PqHttpRequest(
        method: 'GET',
        uri: Uri.parse('https://example.test/'),
      ),
    );
    expect(r.isFailure, isTrue);
    expect(r.errorOrNull!.code, PqTransportErrorCode.handshakeFailure);
  });
}
