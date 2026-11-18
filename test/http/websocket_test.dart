import 'dart:convert';
import 'dart:typed_data';

import 'package:pqtransport/pqtransport.dart';
import 'package:test/test.dart';

void main() {
  Uint8List bytes(List<int> values) => Uint8List.fromList(values);

  test('RFC 6455 unmasked and masked Hello', () {
    final unmasked = bytes([0x81, 0x05, 0x48, 0x65, 0x6c, 0x6c, 0x6f]);
    final client = WebSocketDecoder(expectMasked: false).add(unmasked);
    expect(client.isSuccess, isTrue, reason: '${client.errorOrNull}');
    final text = client.valueOrNull!.single as WebSocketInboundData;
    expect(text.text, isTrue);
    expect(utf8.decode(text.data), 'Hello');

    final masked = bytes([
      0x81,
      0x85,
      0x37,
      0xfa,
      0x21,
      0x3d,
      0x7f,
      0x9f,
      0x4d,
      0x51,
      0x58,
    ]);
    final server = WebSocketDecoder(expectMasked: true).add(masked);
    final echoed = server.valueOrNull!.single as WebSocketInboundData;
    expect(utf8.decode(echoed.data), 'Hello');
    expect(
      WebSocketDecoder(expectMasked: true).add(unmasked).errorOrNull!.message,
      contains('mask'),
    );
    expect(
      WebSocketDecoder(expectMasked: false).add(masked).errorOrNull!.message,
      contains('mask'),
    );

    final encoded = encodeWebSocketFrame(
      fromClient: true,
      fin: true,
      opcode: wsOpText,
      payload: Uint8List.fromList('Hello'.codeUnits),
      maskingKey: bytes([0x37, 0xfa, 0x21, 0x3d]),
    );
    expect(encoded, masked);
  });

  test('the opening handshake accept value is the RFC sample', () {
    expect(
      websocketAcceptValue('dGhlIHNhbXBsZSBub25jZQ=='),
      's3pPLMBiTxaQ9kYGzzhZRbK+xOo=',
    );
    final headers = {
      'upgrade': 'websocket',
      'connection': 'keep-alive, Upgrade',
      'sec-websocket-version': '13',
      'sec-websocket-key': 'dGhlIHNhbXBsZSBub25jZQ==',
      'sec-websocket-protocol': 'chat, superchat',
    };
    final opened = acceptWebSocketHandshake(headers, protocols: ['superchat']);
    expect(opened.isSuccess, isTrue, reason: '${opened.errorOrNull}');
    expect(opened.valueOrNull!.protocol, 'superchat');
    expect(opened.valueOrNull!.accept, 's3pPLMBiTxaQ9kYGzzhZRbK+xOo=');
    expect(
      websocketSwitchingProtocols(opened.valueOrNull!),
      contains('Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo='),
    );
    expect(
      acceptWebSocketHandshake({
        ...headers,
        'sec-websocket-version': '8',
      }).errorOrNull!.message,
      contains('version'),
    );
    expect(
      acceptWebSocketHandshake({
        ...headers,
        'sec-websocket-key': 'aaaa',
      }).errorOrNull!.message,
      contains('key'),
    );
  });

  test('reserved opcodes, RSV, and non-minimal lengths fail', () {
    WebSocketDecoder server() => WebSocketDecoder(expectMasked: false);
    expect(
      server().add(bytes([0x83, 0x00])).errorOrNull!.message,
      contains('opcode'),
    );
    expect(
      server().add(bytes([0x8b, 0x00])).errorOrNull!.message,
      contains('opcode'),
    );
    expect(
      server().add(bytes([0xc1, 0x00])).errorOrNull!.message,
      contains('rsv'),
    );
    expect(
      server().add(bytes([0x81, 0x7e, 0x00, 0x01, 0x58])).errorOrNull!.message,
      contains('length'),
    );
    expect(
      server()
          .add(
            bytes([
              0x81,
              0x7f,
              0x00,
              0x00,
              0x00,
              0x00,
              0x00,
              0x00,
              0x00,
              0x01,
              0x58,
            ]),
          )
          .errorOrNull!
          .message,
      contains('length'),
    );
    expect(
      server()
          .add(
            bytes([0x81, 0x7f, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
          )
          .errorOrNull!
          .message,
      contains('length'),
    );
  });

  test('control frames, close codes, and a message size cap', () {
    final decoder = WebSocketDecoder(expectMasked: false);
    final ping = encodeWebSocketFrame(
      fromClient: false,
      fin: true,
      opcode: wsOpPing,
      payload: Uint8List.fromList('xy'.codeUnits),
    );
    final pong = decoder.add(ping).valueOrNull!.single as WebSocketInboundPing;
    expect(utf8.decode(pong.payload), 'xy');
    expect(
      WebSocketDecoder(
        expectMasked: false,
      ).add(bytes([0x09, 0x00])).errorOrNull!.message,
      contains('control'),
    );
    expect(
      encodeWebSocketClose(fromClient: false, code: 1005).isFailure,
      isTrue,
    );
    expect(
      encodeWebSocketClose(fromClient: false, code: 1006).isFailure,
      isTrue,
    );
    expect(
      encodeWebSocketClose(fromClient: false, code: 1015).isFailure,
      isTrue,
    );
    final forbidden = encodeWebSocketFrame(
      fromClient: false,
      fin: true,
      opcode: wsOpClose,
      payload: bytes([0x03, 0xed]),
    );
    expect(
      WebSocketDecoder(expectMasked: false).add(forbidden).errorOrNull!.message,
      contains('close'),
    );
    expect(
      WebSocketDecoder(
        expectMasked: false,
      ).add(bytes([0x88, 0x01, 0x00])).errorOrNull!.message,
      contains('close'),
    );
    final capped = WebSocketDecoder(expectMasked: false, maxMessageBytes: 4);
    final tooBig = encodeWebSocketFrame(
      fromClient: false,
      fin: true,
      opcode: wsOpText,
      payload: Uint8List.fromList('hello'.codeUnits),
    );
    expect(capped.add(tooBig).errorOrNull!.message, contains('message'));
  });

  test(
    'UTF-8 is the assembled message, and a ping may sit between fragments',
    () {
      final decoder = WebSocketDecoder(expectMasked: false);
      final first = encodeWebSocketFrame(
        fromClient: false,
        fin: false,
        opcode: wsOpText,
        payload: bytes([0xc3]),
      );
      final ping = encodeWebSocketFrame(
        fromClient: false,
        fin: true,
        opcode: wsOpPing,
        payload: Uint8List(0),
      );
      final second = encodeWebSocketFrame(
        fromClient: false,
        fin: true,
        opcode: wsOpContinuation,
        payload: bytes([0xa9]),
      );
      expect(decoder.add(first).valueOrNull, isEmpty);
      final mid = decoder.add(ping).valueOrNull!.single;
      expect(mid, isA<WebSocketInboundPing>());
      final done =
          decoder.add(second).valueOrNull!.single as WebSocketInboundData;
      expect(utf8.decode(done.data), 'é');

      final bad = WebSocketDecoder(expectMasked: false);
      bad.add(
        encodeWebSocketFrame(
          fromClient: false,
          fin: false,
          opcode: wsOpText,
          payload: bytes([0xc3]),
        ),
      );
      expect(
        bad
            .add(
              encodeWebSocketFrame(
                fromClient: false,
                fin: true,
                opcode: wsOpContinuation,
                payload: bytes([0x28]),
              ),
            )
            .errorOrNull!
            .message,
        contains('utf8'),
      );
      final overlap = WebSocketDecoder(expectMasked: false);
      overlap.add(
        encodeWebSocketFrame(
          fromClient: false,
          fin: false,
          opcode: wsOpBinary,
          payload: bytes([1]),
        ),
      );
      expect(
        overlap
            .add(
              encodeWebSocketFrame(
                fromClient: false,
                fin: true,
                opcode: wsOpText,
                payload: bytes([2]),
              ),
            )
            .errorOrNull!
            .message,
        contains('fragment'),
      );
    },
  );
}
