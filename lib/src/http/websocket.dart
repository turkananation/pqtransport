import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'package:pqforge/pqforge.dart';
import 'package:stream_channel/stream_channel.dart';
import 'package:swissarmyknife/swissarmyknife.dart';

import '../core/errors.dart';
import '../core/lengths.dart';
import 'websocket_deflate.dart';
import 'websocket_deflate_api.dart';

export 'websocket_deflate_api.dart';

/// RFC 6455 opening handshake GUID.
const String websocketGuid = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11';

const int wsOpContinuation = 0;
const int wsOpText = 1;
const int wsOpBinary = 2;
const int wsOpClose = 8;
const int wsOpPing = 9;
const int wsOpPong = 10;

/// One accepted RFC 6455 opening handshake.
final class WebSocketOpening {
  const WebSocketOpening({
    required this.accept,
    required this.protocol,
    required this.extension,
    required this.deflate,
    required this.clientNoContextTakeover,
    required this.serverNoContextTakeover,
  });

  /// `Sec-WebSocket-Accept` value.
  final String accept;

  /// Selected subprotocol. Empty when none was selected.
  final String protocol;

  /// `Sec-WebSocket-Extensions` response value, or null.
  final String? extension;

  /// Null when permessage-deflate was not negotiated.
  final WebSocketDeflate? deflate;
  final bool clientNoContextTakeover;
  final bool serverNoContextTakeover;
}

/// RFC 6455 §4.2.2. [protocols] is the server's acceptable list, in
/// preference order. An empty list selects no subprotocol.
///
/// permessage-deflate (RFC 7692) is accepted only when this
/// compilation can run raw DEFLATE. The web barrel does not.
Result<WebSocketOpening, PqTransportError> acceptWebSocketHandshake(
  Map<String, String> headers, {
  Iterable<String> protocols = const [],
  bool allowDeflate = true,
}) {
  final fields = <String, String>{
    for (final entry in headers.entries) entry.key.toLowerCase(): entry.value,
  };
  if (!_hasToken(fields['upgrade'], 'websocket') ||
      !_hasToken(fields['connection'], 'upgrade')) {
    return Result.failure(PqTransportError.decodeFailure('websocket upgrade'));
  }
  final version = fields['sec-websocket-version']?.trim();
  if (version != '13') {
    return Result.failure(PqTransportError.decodeFailure('websocket version'));
  }
  final key = fields['sec-websocket-key'];
  if (key == null || !_websocketKey(key)) {
    return Result.failure(PqTransportError.decodeFailure('websocket key'));
  }
  final offered = _tokens(fields['sec-websocket-protocol']);
  final acceptable = protocols.toList();
  String selected = '';
  if (offered.isNotEmpty && acceptable.isNotEmpty) {
    for (final name in offered) {
      if (acceptable.contains(name)) {
        selected = name;
        break;
      }
    }
    if (selected.isEmpty) {
      return Result.failure(
        PqTransportError.decodeFailure('websocket protocol'),
      );
    }
  }
  final deflate = allowDeflate
      ? _negotiateDeflate(fields['sec-websocket-extensions'])
      : null;
  return Result.success(
    WebSocketOpening(
      accept: websocketAcceptValue(key),
      protocol: selected,
      extension: deflate?.$1,
      deflate: deflate?.$2,
      clientNoContextTakeover: deflate?.$3 ?? false,
      serverNoContextTakeover: deflate?.$4 ?? false,
    ),
  );
}

/// RFC 6455 §1.3. `base64(SHA-1(key + GUID))`.
String websocketAcceptValue(String key) {
  final digest = PqBytes.sha1(
    Uint8List.fromList(utf8.encode('$key$websocketGuid')),
  );
  return base64.encode(digest);
}

/// The 101 response. The status line is HTTP/1.1, which is the
/// version RFC 6455 requires for the opening handshake.
String websocketSwitchingProtocols(WebSocketOpening opening) {
  final b = StringBuffer()
    ..write('HTTP/1.1 101 Switching Protocols\r\n')
    ..write('Upgrade: websocket\r\n')
    ..write('Connection: Upgrade\r\n')
    ..write('Sec-WebSocket-Accept: ${opening.accept}\r\n');
  if (opening.protocol.isNotEmpty) {
    b.write('Sec-WebSocket-Protocol: ${opening.protocol}\r\n');
  }
  final extension = opening.extension;
  if (extension != null) {
    b.write('Sec-WebSocket-Extensions: $extension\r\n');
  }
  b.write('\r\n');
  return b.toString();
}

bool _websocketKey(String key) {
  try {
    return base64.decode(key).length == 16;
  } on FormatException {
    return false;
  }
}

bool _hasToken(String? value, String token) {
  return _tokens(value).any((part) => part.toLowerCase() == token);
}

List<String> _tokens(String? value) {
  if (value == null || value.isEmpty) return const [];
  return [
    for (final part in value.split(','))
      if (part.trim().isNotEmpty) part.trim(),
  ];
}

/// Response token, engine, client takeover, server takeover.
(String, WebSocketDeflate, bool, bool)? _negotiateDeflate(String? header) {
  if (header == null || header.isEmpty) return null;
  for (final offer in _tokens(header)) {
    final parts = [
      for (final part in offer.split(';')) part.trim(),
    ].where((part) => part.isNotEmpty).toList();
    if (parts.isEmpty || parts.first.toLowerCase() != 'permessage-deflate') {
      continue;
    }
    var clientTakeover = false;
    var serverBits = 15;
    var clientBits = 15;
    var clientBitsPresent = false;
    var ok = true;
    for (final param in parts.skip(1)) {
      final eq = param.indexOf('=');
      final name = (eq < 0 ? param : param.substring(0, eq)).toLowerCase();
      final raw = eq < 0 ? null : param.substring(eq + 1).trim();
      switch (name) {
        case 'client_no_context_takeover':
          if (raw != null) ok = false;
          clientTakeover = true;
        case 'server_no_context_takeover':
          if (raw != null) ok = false;
        case 'client_max_window_bits':
          clientBitsPresent = true;
          if (raw == null || raw.isEmpty) {
            clientBits = 15;
          } else {
            final bits = int.tryParse(raw);
            if (bits == null || bits < 8 || bits > 15) ok = false;
            clientBits = bits ?? 15;
          }
        case 'server_max_window_bits':
          final bits = int.tryParse(raw ?? '');
          if (bits == null || bits < 8 || bits > 15) ok = false;
          serverBits = bits ?? 15;
        default:
          ok = false;
      }
    }
    if (!ok) continue;
    // This server resets its compressor on every message, so the
    // response always says server_no_context_takeover. It does not
    // say client_no_context_takeover unless the client did.
    final response = StringBuffer('permessage-deflate');
    if (clientTakeover) response.write('; client_no_context_takeover');
    response.write('; server_no_context_takeover');
    if (clientBitsPresent && clientBits != 15) {
      response.write('; client_max_window_bits=$clientBits');
    }
    if (serverBits != 15) {
      response.write('; server_max_window_bits=$serverBits');
    }
    final engine = openWebSocketDeflate(
      clientNoContextTakeover: clientTakeover,
      serverNoContextTakeover: true,
      clientWindowBits: clientBits,
      serverWindowBits: serverBits,
    );
    if (engine == null) return null;
    return (response.toString(), engine, clientTakeover, true);
  }
  return null;
}

/// A frame from the peer, after unmasking. Data messages are assembled
/// by [WebSocketDecoder]; these events are not raw fragments.
sealed class WebSocketInbound {}

final class WebSocketInboundData extends WebSocketInbound {
  WebSocketInboundData({required this.text, required this.data});

  final bool text;
  final Uint8List data;
}

final class WebSocketInboundPing extends WebSocketInbound {
  WebSocketInboundPing(this.payload);
  final Uint8List payload;
}

final class WebSocketInboundPong extends WebSocketInbound {
  WebSocketInboundPong(this.payload);
  final Uint8List payload;
}

final class WebSocketInboundClose extends WebSocketInbound {
  WebSocketInboundClose({required this.code, required this.reason});

  /// Null when the peer sent an empty Close payload. That is not 1005
  /// on the wire.
  final int? code;
  final String reason;
}

/// RFC 6455 §5. [expectMasked] is true on a server.
final class WebSocketDecoder {
  WebSocketDecoder({
    required this.expectMasked,
    this.maxMessageBytes = http1DefaultMaxBodyBytes,
    this.deflate,
  });

  final bool expectMasked;
  final int maxMessageBytes;
  final WebSocketDeflate? deflate;

  final BytesBuilder _buf = BytesBuilder(copy: false);
  final BytesBuilder _message = BytesBuilder(copy: false);
  var _inMessage = false;
  var _opcode = 0;
  var _compressed = false;
  var _messageBytes = 0;

  Result<List<WebSocketInbound>, PqTransportError> add(List<int> chunk) {
    if (chunk.isNotEmpty) _buf.add(chunk);
    final bytes = _buf.takeBytes();
    final out = <WebSocketInbound>[];
    var i = 0;
    while (true) {
      if (bytes.length - i < 2) break;
      final b0 = bytes[i];
      final b1 = bytes[i + 1];
      final fin = (b0 & 0x80) != 0;
      final rsv1 = (b0 & 0x40) != 0;
      final rsv2 = (b0 & 0x20) != 0;
      final rsv3 = (b0 & 0x10) != 0;
      final opcode = b0 & 0x0f;
      final masked = (b1 & 0x80) != 0;
      var len = b1 & 0x7f;
      var header = 2;
      if (len == 126) {
        if (bytes.length - i < 4) break;
        len = (bytes[i + 2] << 8) | bytes[i + 3];
        if (len < 126) {
          return Result.failure(
            PqTransportError.decodeFailure('websocket length'),
          );
        }
        header = 4;
      } else if (len == 127) {
        if (bytes.length - i < 10) break;
        if ((bytes[i + 2] & 0x80) != 0) {
          return Result.failure(
            PqTransportError.decodeFailure('websocket length'),
          );
        }
        var big = 0;
        for (var k = 0; k < 8; k++) {
          big = (big << 8) | bytes[i + 2 + k];
        }
        if (big < 65536) {
          return Result.failure(
            PqTransportError.decodeFailure('websocket length'),
          );
        }
        len = big;
        header = 10;
      }
      final maskLen = masked ? 4 : 0;
      if (bytes.length - i < header + maskLen) break;
      if (len > maxMessageBytes) {
        return Result.failure(
          PqTransportError.decodeFailure('websocket message'),
        );
      }
      final total = header + maskLen + len;
      if (bytes.length - i < total) break;
      if (masked != expectMasked) {
        return Result.failure(PqTransportError.decodeFailure('websocket mask'));
      }
      if (opcode > 10 || (opcode >= 3 && opcode <= 7)) {
        return Result.failure(
          PqTransportError.decodeFailure('websocket opcode'),
        );
      }
      final payload = Uint8List(len);
      final dataAt = i + header + maskLen;
      if (masked) {
        final m0 = bytes[i + header];
        final m1 = bytes[i + header + 1];
        final m2 = bytes[i + header + 2];
        final m3 = bytes[i + header + 3];
        for (var k = 0; k < len; k++) {
          final mask = switch (k & 3) {
            0 => m0,
            1 => m1,
            2 => m2,
            _ => m3,
          };
          payload[k] = bytes[dataAt + k] ^ mask;
        }
      } else if (len > 0) {
        payload.setRange(0, len, bytes, dataAt);
      }
      i += total;
      final delivered = _take(
        fin: fin,
        rsv1: rsv1,
        rsv2: rsv2,
        rsv3: rsv3,
        opcode: opcode,
        payload: payload,
      );
      if (delivered.isFailure) return Result.failure(delivered.errorOrNull!);
      final event = delivered.valueOrNull;
      if (event != null) out.add(event);
    }
    if (i < bytes.length) {
      _buf.add(Uint8List.sublistView(bytes, i));
    }
    return Result.success(out);
  }

  Result<WebSocketInbound?, PqTransportError> _take({
    required bool fin,
    required bool rsv1,
    required bool rsv2,
    required bool rsv3,
    required int opcode,
    required Uint8List payload,
  }) {
    final control = opcode >= 8;
    if (rsv2 || rsv3 || (rsv1 && (deflate == null || control))) {
      return Result.failure(PqTransportError.decodeFailure('websocket rsv'));
    }
    if (control) {
      if (!fin || payload.length > 125) {
        return Result.failure(
          PqTransportError.decodeFailure('websocket control'),
        );
      }
      if (opcode == wsOpClose) return _close(payload);
      if (opcode == wsOpPing) {
        return Result.success(WebSocketInboundPing(payload));
      }
      return Result.success(WebSocketInboundPong(payload));
    }
    if (opcode == wsOpContinuation) {
      if (!_inMessage || rsv1) {
        return Result.failure(
          PqTransportError.decodeFailure('websocket fragment'),
        );
      }
    } else {
      if (_inMessage) {
        return Result.failure(
          PqTransportError.decodeFailure('websocket fragment'),
        );
      }
      _inMessage = true;
      _opcode = opcode;
      _compressed = rsv1;
      _messageBytes = 0;
    }
    if (_messageBytes + payload.length > maxMessageBytes) {
      return Result.failure(
        PqTransportError.decodeFailure('websocket message'),
      );
    }
    if (payload.isNotEmpty) {
      _message.add(payload);
      _messageBytes += payload.length;
    }
    if (!fin) return const Result.success(null);
    _inMessage = false;
    var data = _message.takeBytes();
    _messageBytes = 0;
    if (_compressed) {
      final engine = deflate;
      _compressed = false;
      if (engine == null) {
        return Result.failure(PqTransportError.decodeFailure('websocket rsv'));
      }
      try {
        data = engine.decompress(data);
      } on Object {
        return Result.failure(
          PqTransportError.decodeFailure('websocket deflate'),
        );
      }
      if (data.length > maxMessageBytes) {
        return Result.failure(
          PqTransportError.decodeFailure('websocket message'),
        );
      }
    }
    if (_opcode == wsOpText) {
      try {
        utf8.decode(data, allowMalformed: false);
      } on FormatException {
        return Result.failure(PqTransportError.decodeFailure('websocket utf8'));
      }
    }
    return Result.success(
      WebSocketInboundData(text: _opcode == wsOpText, data: data),
    );
  }

  Result<WebSocketInbound, PqTransportError> _close(Uint8List payload) {
    if (payload.isEmpty) {
      return Result.success(WebSocketInboundClose(code: null, reason: ''));
    }
    if (payload.length == 1) {
      return Result.failure(PqTransportError.decodeFailure('websocket close'));
    }
    final code = (payload[0] << 8) | payload[1];
    if (!websocketCloseOnWire(code)) {
      return Result.failure(PqTransportError.decodeFailure('websocket close'));
    }
    final reasonBytes = Uint8List.sublistView(payload, 2);
    final String reason;
    try {
      reason = utf8.decode(reasonBytes, allowMalformed: false);
    } on FormatException {
      return Result.failure(PqTransportError.decodeFailure('websocket utf8'));
    }
    return Result.success(WebSocketInboundClose(code: code, reason: reason));
  }
}

/// RFC 6455 §7.4. 1005, 1006, and 1015 must not appear on the wire.
/// 0–999, 1004, and 1016–2999 are not status codes an endpoint sends.
bool websocketCloseOnWire(int code) {
  if (code < 1000 || code > 4999) return false;
  if (code == 1004 || code == 1005 || code == 1006 || code == 1015) {
    return false;
  }
  if (code >= 1016 && code <= 2999) return false;
  return true;
}

/// Encodes one frame. A client frame is masked. A server frame is not.
/// [maskingKey] fixes the client mask for a test; otherwise it is
/// four fresh bytes.
Uint8List encodeWebSocketFrame({
  required bool fromClient,
  required bool fin,
  required int opcode,
  required Uint8List payload,
  bool rsv1 = false,
  bool rsv2 = false,
  bool rsv3 = false,
  Uint8List? maskingKey,
}) {
  if (opcode > 15 || payload.length > 125 && opcode >= 8) {
    throw ArgumentError('websocket frame');
  }
  Uint8List? mask;
  if (fromClient) {
    if (maskingKey != null && maskingKey.length != 4) {
      throw ArgumentError('websocket mask');
    }
    mask = maskingKey ?? PqBytes.randomBytes(4);
  }
  final header = BytesBuilder(copy: false);
  var b0 = opcode & 0x0f;
  if (fin) b0 |= 0x80;
  if (rsv1) b0 |= 0x40;
  if (rsv2) b0 |= 0x20;
  if (rsv3) b0 |= 0x10;
  header.addByte(b0);
  final maskedBit = mask == null ? 0 : 0x80;
  final len = payload.length;
  if (len < 126) {
    header.addByte(maskedBit | len);
  } else if (len <= 0xffff) {
    header.addByte(maskedBit | 126);
    header.addByte((len >> 8) & 0xff);
    header.addByte(len & 0xff);
  } else {
    header.addByte(maskedBit | 127);
    var rest = len;
    final wide = Uint8List(8);
    for (var i = 7; i >= 0; i--) {
      wide[i] = rest & 0xff;
      rest >>= 8;
    }
    header.add(wide);
  }
  if (mask != null) header.add(mask);
  final body = Uint8List(payload.length);
  if (mask == null) {
    body.setRange(0, payload.length, payload);
  } else {
    for (var i = 0; i < payload.length; i++) {
      body[i] = payload[i] ^ mask[i & 3];
    }
  }
  return Uint8List.fromList([...header.takeBytes(), ...body]);
}

/// Close payload. [code] null is an empty payload, not 1005 on the wire.
Result<Uint8List, PqTransportError> encodeWebSocketClose({
  required bool fromClient,
  int? code,
  String reason = '',
  Uint8List? maskingKey,
}) {
  if (code == null && reason.isNotEmpty) {
    return Result.failure(PqTransportError.decodeFailure('websocket close'));
  }
  final reasonBytes = utf8.encode(reason);
  if (code != null && !websocketCloseOnWire(code)) {
    return Result.failure(PqTransportError.decodeFailure('websocket close'));
  }
  if (reasonBytes.length > 123) {
    return Result.failure(PqTransportError.decodeFailure('websocket close'));
  }
  final status = code;
  final payload = Uint8List(status == null ? 0 : 2 + reasonBytes.length);
  if (status != null) {
    payload[0] = (status >> 8) & 0xff;
    payload[1] = status & 0xff;
    payload.setRange(2, payload.length, reasonBytes);
  }
  return Result.success(
    encodeWebSocketFrame(
      fromClient: fromClient,
      fin: true,
      opcode: wsOpClose,
      payload: payload,
      maskingKey: maskingKey,
    ),
  );
}

Uint8List encodeWebSocketData({
  required bool fromClient,
  required bool text,
  required Uint8List data,
  WebSocketDeflate? deflate,
  Uint8List? maskingKey,
}) {
  var payload = data;
  var rsv1 = false;
  if (deflate != null) {
    payload = deflate.compress(data);
    rsv1 = true;
  }
  return encodeWebSocketFrame(
    fromClient: fromClient,
    fin: true,
    opcode: text ? wsOpText : wsOpBinary,
    payload: payload,
    rsv1: rsv1,
    maskingKey: maskingKey,
  );
}

/// One side of an open WebSocket. The HTTP carriage is outside this
/// type: it already wrote 101, or the extended CONNECT 200.
final class WebSocketEndpoint {
  WebSocketEndpoint(
    this._channel, {
    required bool client,
    WebSocketDeflate? deflate,
    this.protocol = '',
    int maxMessageBytes = http1DefaultMaxBodyBytes,
  }) : _client = client,
       _deflate = deflate,
       _decoder = WebSocketDecoder(
         expectMasked: !client,
         deflate: deflate,
         maxMessageBytes: maxMessageBytes,
       ) {
    _sub = _channel.stream.listen(
      _onData,
      onError: (Object _) {
        _fail(1002, 'protocol');
      },
      onDone: _onDone,
      cancelOnError: true,
    );
  }

  final StreamChannel<List<int>> _channel;
  final bool _client;
  final WebSocketDeflate? _deflate;
  final WebSocketDecoder _decoder;
  final String protocol;
  final _events = StreamController<WebSocketInbound>();
  StreamSubscription<List<int>>? _sub;
  var _sentClose = false;
  var _finished = false;

  Stream<WebSocketInbound> get events => _events.stream;

  bool get isClosed => _finished || _sentClose;

  void sendText(String text) {
    _sendData(text: true, data: Uint8List.fromList(utf8.encode(text)));
  }

  void sendBytes(Uint8List data) {
    _sendData(text: false, data: data);
  }

  void ping([Uint8List? payload]) {
    if (_finished || _sentClose) return;
    _channel.sink.add(
      encodeWebSocketFrame(
        fromClient: _client,
        fin: true,
        opcode: wsOpPing,
        payload: payload ?? Uint8List(0),
      ),
    );
  }

  Result<void, PqTransportError> close([int? code, String? reason]) {
    if (_finished || _sentClose) {
      return Result.failure(PqTransportError.closed('websocket'));
    }
    final frame = encodeWebSocketClose(
      fromClient: _client,
      code: code,
      reason: reason ?? '',
    );
    if (frame.isFailure) return Result.failure(frame.errorOrNull!);
    _sentClose = true;
    _channel.sink.add(frame.valueOrNull!);
    return const Result.success(null);
  }

  void _sendData({required bool text, required Uint8List data}) {
    if (_finished || _sentClose) {
      throw StateError('websocket closed');
    }
    try {
      _channel.sink.add(
        encodeWebSocketData(
          fromClient: _client,
          text: text,
          data: data,
          deflate: _deflate,
        ),
      );
    } on Object {
      _fail(1002, 'deflate');
    }
  }

  void _onData(List<int> chunk) {
    final parsed = _decoder.add(chunk);
    if (parsed.isFailure) {
      _fail(1002, 'protocol');
      return;
    }
    for (final event in parsed.valueOrNull!) {
      switch (event) {
        case WebSocketInboundPing(:final payload):
          if (!_sentClose && !_finished) {
            _channel.sink.add(
              encodeWebSocketFrame(
                fromClient: _client,
                fin: true,
                opcode: wsOpPong,
                payload: payload,
              ),
            );
          }
        case WebSocketInboundPong():
          break;
        case WebSocketInboundData():
          if (!_events.isClosed) _events.add(event);
        case WebSocketInboundClose(:final code, :final reason):
          if (!_sentClose) {
            final echo = code != null && websocketCloseOnWire(code)
                ? code
                : 1000;
            final frame = encodeWebSocketClose(fromClient: _client, code: echo);
            if (frame.isSuccess) {
              _sentClose = true;
              _channel.sink.add(frame.valueOrNull!);
            }
          }
          if (!_events.isClosed) {
            _events.add(WebSocketInboundClose(code: code, reason: reason));
          }
          unawaited(_finish());
      }
    }
  }

  void _onDone() {
    if (!_events.isClosed) {
      _events.add(WebSocketInboundClose(code: null, reason: ''));
    }
    unawaited(_finish());
  }

  void _fail(int code, String reason) {
    if (!_sentClose && !_finished) {
      final frame = encodeWebSocketClose(
        fromClient: _client,
        code: code,
        reason: reason,
      );
      if (frame.isSuccess) {
        _sentClose = true;
        _channel.sink.add(frame.valueOrNull!);
      }
    }
    if (!_events.isClosed) {
      _events.add(WebSocketInboundClose(code: code, reason: reason));
    }
    unawaited(_finish());
  }

  Future<void> _finish() async {
    if (_finished) return;
    _finished = true;
    await _sub?.cancel();
    _sub = null;
    if (!_events.isClosed) await _events.close();
    try {
      await _channel.sink.close();
    } on StateError {
      // The carriage already closed it.
    }
  }
}
