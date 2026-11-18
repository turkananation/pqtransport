import 'dart:io';
import 'dart:typed_data';

import 'websocket_deflate_api.dart';

/// RFC 7692 raw DEFLATE on the VM. Context takeover keeps one zlib
/// filter. `no_context_takeover` finishes that filter after the message.
WebSocketDeflate? openWebSocketDeflate({
  required bool clientNoContextTakeover,
  required bool serverNoContextTakeover,
  required int clientWindowBits,
  required int serverWindowBits,
}) {
  if (serverWindowBits < 8 || serverWindowBits > 15) return null;
  if (clientWindowBits < 8 || clientWindowBits > 15) return null;
  try {
    return _IoWebSocketDeflate(
      clientNoContextTakeover: clientNoContextTakeover,
      serverNoContextTakeover: serverNoContextTakeover,
      clientWindowBits: clientWindowBits,
      serverWindowBits: serverWindowBits,
    );
  } on Object {
    return null;
  }
}

final class _IoWebSocketDeflate implements WebSocketDeflate {
  _IoWebSocketDeflate({
    required this.clientNoContextTakeover,
    required this.serverNoContextTakeover,
    required int clientWindowBits,
    required this.serverWindowBits,
  }) : _inflateWindowBits = 15 {
    if (clientWindowBits < 8 || clientWindowBits > 15) {
      throw ArgumentError.value(clientWindowBits, 'clientWindowBits');
    }
  }

  final bool clientNoContextTakeover;
  final bool serverNoContextTakeover;
  final int serverWindowBits;
  final int _inflateWindowBits;
  RawZLibFilter? _deflate;
  RawZLibFilter? _inflate;

  @override
  Uint8List compress(Uint8List message) {
    return _attempt(() => _compress(message));
  }

  @override
  Uint8List decompress(Uint8List payload) {
    return _attempt(() => _decompress(payload));
  }

  /// A raw filter's first call can fail when another isolate is inside
  /// dart:io. That filter is discarded. This is not a claim that the
  /// VM's zlib is isolated.
  Uint8List _attempt(Uint8List Function() body) {
    FormatException? last;
    for (var attempt = 0; attempt < 4; attempt++) {
      try {
        return body();
      } on FormatException catch (error) {
        last = error;
      }
    }
    final error = last;
    if (error == null) throw StateError('websocket deflate');
    throw error;
  }

  Uint8List _compress(Uint8List message) {
    final finish = serverNoContextTakeover;
    final filter = finish
        ? RawZLibFilter.deflateFilter(raw: true, windowBits: serverWindowBits)
        : (_deflate ??= RawZLibFilter.deflateFilter(
            raw: true,
            windowBits: serverWindowBits,
          ));
    if (message.isNotEmpty) filter.process(message, 0, message.length);
    // RFC 7692 strips the Z_SYNC_FLUSH trailer. Z_FINISH is a different
    // tail and is not part of the frame. no_context_takeover still
    // finishes the filter so zlib can release it.
    final bytes = _take(filter, end: false);
    if (finish) {
      try {
        _take(filter, end: true);
      } on Object {
        // Sync-flush bytes are already in [bytes]. Releasing the
        // filter is not part of the frame.
      }
      _deflate = null;
    }
    return _stripSyncFlush(bytes);
  }

  Uint8List _decompress(Uint8List payload) {
    final finish = clientNoContextTakeover;
    // The inflater window must be at least the peer's. 15 accepts
    // every legal client_max_window_bits.
    final filter = finish
        ? RawZLibFilter.inflateFilter(raw: true, windowBits: _inflateWindowBits)
        : (_inflate ??= RawZLibFilter.inflateFilter(
            raw: true,
            windowBits: _inflateWindowBits,
          ));
    final input = Uint8List(payload.length + 4);
    input.setRange(0, payload.length, payload);
    input[payload.length] = 0x00;
    input[payload.length + 1] = 0x00;
    input[payload.length + 2] = 0xff;
    input[payload.length + 3] = 0xff;
    filter.process(input, 0, input.length);
    final bytes = _take(filter, end: false);
    if (finish) {
      try {
        _take(filter, end: true);
      } on Object {
        // The inflated message is already in [bytes].
      }
      _inflate = null;
    }
    return bytes;
  }

  Uint8List _take(RawZLibFilter filter, {required bool end}) {
    final out = BytesBuilder(copy: false);
    while (true) {
      final chunk = filter.processed(flush: true, end: end);
      if (chunk == null) break;
      if (chunk.isNotEmpty) out.add(chunk);
    }
    return out.takeBytes();
  }

  Uint8List _stripSyncFlush(Uint8List bytes) {
    if (bytes.length < 4 ||
        bytes[bytes.length - 4] != 0x00 ||
        bytes[bytes.length - 3] != 0x00 ||
        bytes[bytes.length - 2] != 0xff ||
        bytes[bytes.length - 1] != 0xff) {
      throw FormatException('websocket deflate');
    }
    return Uint8List.sublistView(bytes, 0, bytes.length - 4);
  }
}
