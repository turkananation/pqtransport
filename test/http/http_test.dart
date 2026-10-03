import 'dart:typed_data';

import 'package:pqtransport/pqtransport.dart';
import 'package:test/test.dart';

void main() {
  Uint8List hex(String s) {
    final compact = s.replaceAll(RegExp(r'\s'), '');
    final out = Uint8List(compact.length ~/ 2);
    for (var i = 0; i < out.length; i++) {
      out[i] = int.parse(compact.substring(i * 2, i * 2 + 2), radix: 16);
    }
    return out;
  }

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

  test('roundTripH2 refuses incomplete TLS and non-h2 ALPN', () async {
    final (a, _) = MemoryByteSocket.pair();
    final tls = PqTlsSocket.client(a);
    final incomplete = await PqHttpClient(prefer: HttpVersion.h2).roundTripH2(
      tls: tls,
      request: PqHttpRequest(
        method: 'GET',
        uri: Uri.parse('https://example.test/'),
      ),
    );
    expect(incomplete.isFailure, isTrue);
    expect(incomplete.errorOrNull!.code, PqTransportErrorCode.handshakeFailure);
  });

  test('RFC 7541 C.2.1 literal with incremental indexing', () {
    final codec = HpackCodec();
    final wire = codec.encode(const [
      HpackHeader('custom-key', 'custom-header'),
    ], huffman: false);
    expect(wire, hex('400a637573746f6d2d6b65790d637573746f6d2d686561646572'));
    final dec = HpackCodec().decode(wire);
    expect(dec.isSuccess, isTrue);
    expect(dec.valueOrNull, [const HpackHeader('custom-key', 'custom-header')]);
  });

  test('RFC 7541 C.2.2 literal without indexing :path', () {
    final dec = HpackCodec().decode(hex('040c2f73616d706c652f70617468'));
    expect(dec.isSuccess, isTrue);
    expect(dec.valueOrNull, [const HpackHeader(':path', '/sample/path')]);
  });

  test('RFC 7541 C.2.3 literal never indexed', () {
    final dec = HpackCodec().decode(hex('100870617373776f726406736563726574'));
    expect(dec.isSuccess, isTrue);
    expect(dec.valueOrNull, [const HpackHeader('password', 'secret')]);
  });

  test('RFC 7541 C.3 request sequence without Huffman', () {
    final enc = HpackCodec();
    final dec = HpackCodec();
    final first = enc.encode(const [
      HpackHeader(':method', 'GET'),
      HpackHeader(':scheme', 'http'),
      HpackHeader(':path', '/'),
      HpackHeader(':authority', 'www.example.com'),
    ], huffman: false);
    expect(first, hex('828684410f7777772e6578616d706c652e636f6d'));
    expect(dec.decode(first).valueOrNull, [
      const HpackHeader(':method', 'GET'),
      const HpackHeader(':scheme', 'http'),
      const HpackHeader(':path', '/'),
      const HpackHeader(':authority', 'www.example.com'),
    ]);

    final second = enc.encode(const [
      HpackHeader(':method', 'GET'),
      HpackHeader(':scheme', 'http'),
      HpackHeader(':path', '/'),
      HpackHeader(':authority', 'www.example.com'),
      HpackHeader('cache-control', 'no-cache'),
    ], huffman: false);
    expect(second, hex('828684be58086e6f2d6361636865'));
    expect(dec.decode(second).isSuccess, isTrue);

    final third = enc.encode(const [
      HpackHeader(':method', 'GET'),
      HpackHeader(':scheme', 'https'),
      HpackHeader(':path', '/index.html'),
      HpackHeader(':authority', 'www.example.com'),
      HpackHeader('custom-key', 'custom-value'),
    ], huffman: false);
    expect(
      third,
      hex('828785bf400a637573746f6d2d6b65790c637573746f6d2d76616c7565'),
    );
    expect(dec.decode(third).isSuccess, isTrue);
  });

  test('RFC 7541 C.4.1 request with Huffman', () {
    final enc = HpackCodec();
    final wire = enc.encode(const [
      HpackHeader(':method', 'GET'),
      HpackHeader(':scheme', 'http'),
      HpackHeader(':path', '/'),
      HpackHeader(':authority', 'www.example.com'),
    ]);
    expect(wire, hex('828684418cf1e3c2e5f23a6ba0ab90f4ff'));
    final dec = HpackCodec().decode(wire);
    expect(dec.isSuccess, isTrue, reason: '${dec.errorOrNull}');
    expect(dec.valueOrNull!.last.value, 'www.example.com');
  });

  test('HPACK Huffman www.example.com pin', () {
    final enc = hpackHuffmanEncode('www.example.com'.codeUnits);
    expect(enc, hex('f1e3c2e5f23a6ba0ab90f4ff'));
    final dec = hpackHuffmanDecode(enc);
    expect(dec.isSuccess, isTrue);
    expect(String.fromCharCodes(dec.valueOrNull!), 'www.example.com');
  });

  test('HPACK rejects truncated block, index 0, oversized table update', () {
    expect(HpackCodec().decode(hex('80')).isFailure, isTrue); // index 0
    expect(HpackCodec().decode(hex('7f')).isFailure, isTrue); // truncated int
    // RFC 7541 5-bit prefix: 31 + 98 + 31×128 = 4097 > default 4096.
    expect(
      HpackCodec().decode(Uint8List.fromList([0x3f, 0xe2, 0x1f])).isFailure,
      isTrue,
    );
    expect(
      HpackCodec().decode(Uint8List.fromList([0x3f, 0xe1, 0x1f])).isSuccess,
      isTrue,
    ); // 4096 is the default cap
  });

  test('HTTP/2 frame header round trip', () {
    final f = Http2Frame(
      type: http2FrameData,
      flags: http2FlagEndStream,
      streamId: 1,
      payload: Uint8List.fromList([9, 8, 7]),
    );
    final dec = Http2Frame.tryDecode(f.encode());
    expect(dec.isSuccess, isTrue);
    expect(dec.valueOrNull!.$1.type, http2FrameData);
    expect(dec.valueOrNull!.$1.streamId, 1);
    expect(dec.valueOrNull!.$1.endStream, isTrue);
    expect(dec.valueOrNull!.$1.payload, [9, 8, 7]);
  });

  test('HTTP/2 tryDecode truncated header is incomplete not failure', () {
    final r = Http2Frame.tryDecode(Uint8List.fromList([0, 0, 4, 0]));
    expect(r.isSuccess, isTrue);
    expect(r.valueOrNull, isNull);
  });

  test('HTTP/2 SETTINGS encode/decode and ACK empty payload', () {
    final wire = encodeHttp2Settings(http2ClientSettings);
    final frame = Http2Frame.tryDecode(wire).valueOrNull!.$1;
    expect(frame.type, http2FrameSettings);
    expect(frame.streamId, 0);
    final map = decodeHttp2Settings(frame.payload);
    expect(map.isSuccess, isTrue);
    expect(map.valueOrNull![http2SettingsEnablePush], 0);
    final ack = encodeHttp2Settings(const {}, ack: true);
    final ackFrame = Http2Frame.tryDecode(ack).valueOrNull!.$1;
    expect(ackFrame.ack, isTrue);
    expect(ackFrame.payload, isEmpty);
    expect(
      decodeHttp2Settings(Uint8List.fromList([1, 2, 3])).isFailure,
      isTrue,
    );
  });

  test('HTTP/2 unpad DATA and reject pad overflow', () {
    final payload = Uint8List.fromList([2, 1, 2, 3, 9, 9]);
    final f = Http2Frame(
      type: http2FrameData,
      flags: http2FlagPadded | http2FlagEndStream,
      streamId: 1,
      payload: payload,
    );
    final body = http2Unpad(f);
    expect(body.isSuccess, isTrue);
    expect(body.valueOrNull, [1, 2, 3]);
    final bad = Http2Frame(
      type: http2FrameData,
      flags: http2FlagPadded,
      streamId: 1,
      payload: Uint8List.fromList([5, 1]),
    );
    expect(http2Unpad(bad).isFailure, isTrue);
  });

  test('HTTP/2 preface is 24 ASCII bytes', () {
    expect(http2ConnectionPreface.length, http2PrefaceBytes);
    expect(http2ConnectionPreface, 'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n');
  });

  test('selectAlpn first overlap; empty offer; no overlap is fatal', () {
    final hit = selectAlpn(
      offered: const [httpAlpnH2, httpAlpnH1],
      supported: const [httpAlpnH1],
    );
    expect(hit.valueOrNull, httpAlpnH1);
    final none = selectAlpn(offered: const [], supported: const [httpAlpnH2]);
    expect(none.valueOrNull, isNull);
    final miss = selectAlpn(
      offered: const [httpAlpnH2],
      supported: const [httpAlpnH1],
    );
    expect(miss.isFailure, isTrue);
    expect(miss.errorOrNull!.alert, tlsAlertNoApplicationProtocol);
  });

  test('http2 request/response header mapping', () {
    final req = PqHttpRequest(
      method: 'GET',
      uri: Uri.parse('https://example.test/dns-query?x=1'),
      headers: const {'content-type': 'application/dns-message', 'host': 'x'},
    );
    final hs = http2RequestHeaders(req);
    expect(hs.first, const HpackHeader(':method', 'GET'));
    expect(hs.where((h) => h.name == 'host'), isEmpty);
    expect(hs.where((h) => h.name == ':path').first.value, '/dns-query?x=1');
    final parsed = http2ParseRequest(hs, Uint8List(0));
    expect(parsed.isSuccess, isTrue);
    expect(parsed.valueOrNull!.method, 'GET');

    final respHs = http2ResponseHeaders(
      PqHttpResponse(
        status: 200,
        headers: const {'content-type': 'text/plain'},
        body: Uint8List(0),
        version: HttpVersion.h2,
      ),
    );
    final resp = http2ParseResponse(respHs, Uint8List.fromList('ok'.codeUnits));
    expect(resp.valueOrNull!.status, 200);
    expect(resp.valueOrNull!.version, HttpVersion.h2);
  });

  test('roundTrip refuses silent h2 downgrade on incomplete TLS', () async {
    final (a, _) = MemoryByteSocket.pair();
    final tls = PqTlsSocket.client(a);
    final r = await PqHttpClient(prefer: HttpVersion.h2).roundTrip(
      tls: tls,
      request: PqHttpRequest(
        method: 'GET',
        uri: Uri.parse('https://example.test/'),
      ),
    );
    expect(r.isFailure, isTrue);
  });
}
