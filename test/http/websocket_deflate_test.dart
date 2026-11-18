@TestOn('vm')
library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:pqtransport/pqtransport.dart';
import 'package:test/test.dart';

void main() {
  test('permessage-deflate round-trips and is the extension we answer with', () {
    final opened = acceptWebSocketHandshake({
      'upgrade': 'websocket',
      'connection': 'Upgrade',
      'sec-websocket-version': '13',
      'sec-websocket-key': 'dGhlIHNhbXBsZSBub25jZQ==',
      'sec-websocket-extensions':
          'permessage-deflate; client_no_context_takeover; client_max_window_bits',
    });
    expect(opened.isSuccess, isTrue, reason: '${opened.errorOrNull}');
    final opening = opened.valueOrNull!;
    expect(opening.deflate, isNotNull);
    expect(opening.extension, contains('permessage-deflate'));
    expect(opening.extension, contains('server_no_context_takeover'));
    expect(opening.extension, contains('client_no_context_takeover'));
    expect(opening.clientNoContextTakeover, isTrue);

    final engine = opening.deflate!;
    for (final text in ['', 'Hello', 'é' * 40]) {
      final wire = encodeWebSocketData(
        fromClient: true,
        text: true,
        data: Uint8List.fromList(utf8.encode(text)),
        deflate: engine,
        maskingKey: Uint8List.fromList([1, 2, 3, 4]),
      );
      expect(wire[0] & 0x40, 0x40);
      final decoded = WebSocketDecoder(
        expectMasked: true,
        deflate: engine,
      ).add(wire);
      expect(decoded.isSuccess, isTrue, reason: '${decoded.errorOrNull}');
      final message = decoded.valueOrNull!.single as WebSocketInboundData;
      expect(utf8.decode(message.data), text);
    }
  });

  test('an unknown deflate parameter is not accepted', () {
    final opened = acceptWebSocketHandshake({
      'upgrade': 'websocket',
      'connection': 'Upgrade',
      'sec-websocket-version': '13',
      'sec-websocket-key': 'dGhlIHNhbXBsZSBub25jZQ==',
      'sec-websocket-extensions': 'permessage-deflate; not-a-parameter',
    });
    expect(opened.valueOrNull!.extension, isNull);
    expect(opened.valueOrNull!.deflate, isNull);
  });
}
