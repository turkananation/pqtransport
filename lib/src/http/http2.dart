import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'package:swissarmyknife/swissarmyknife.dart';

import '../core/bytes.dart';
import '../core/errors.dart';
import '../core/lengths.dart';
import '../tls/pq_tls_socket.dart';
import 'hpack.dart';
import 'pq_http_client.dart';

/// RFC 9113 frame. Length is derived from [payload].
final class Http2Frame {
  const Http2Frame({
    required this.type,
    required this.flags,
    required this.streamId,
    required this.payload,
  });

  final int type;
  final int flags;
  final int streamId;
  final Uint8List payload;

  bool get ack => (flags & http2FlagAck) != 0;
  bool get endStream => (flags & http2FlagEndStream) != 0;
  bool get endHeaders => (flags & http2FlagEndHeaders) != 0;
  bool get padded => (flags & http2FlagPadded) != 0;
  bool get hasPriority => (flags & http2FlagPriority) != 0;

  Uint8List encode() {
    final b = BytesBuilder(copy: false);
    writeUint24(b, payload.length);
    b.addByte(type);
    b.addByte(flags);
    writeUint32(b, streamId & http2StreamIdMask);
    b.add(payload);
    return b.takeBytes();
  }

  /// Returns the frame and bytes consumed, or success(null) if truncated.
  static Result<(Http2Frame, int)?, PqTransportError> tryDecode(
    Uint8List wire, {
    int maxFrameSize = http2DefaultMaxFrameSize,
  }) {
    if (wire.length < http2FrameHeaderBytes) {
      return const Result.success(null);
    }
    final length = readUint24(wire, 0);
    if (length > maxFrameSize) {
      return Result.failure(
        PqTransportError.decodeFailure('http2 frame too large'),
      );
    }
    final total = http2FrameHeaderBytes + length;
    if (wire.length < total) return const Result.success(null);
    final type = wire[3];
    final flags = wire[4];
    final streamId = readUint32(wire, 5) & http2StreamIdMask;
    return Result.success((
      Http2Frame(
        type: type,
        flags: flags,
        streamId: streamId,
        payload: slice(wire, http2FrameHeaderBytes, total),
      ),
      total,
    ));
  }
}

Uint8List encodeHttp2Settings(Map<int, int> settings, {bool ack = false}) {
  final payload = BytesBuilder(copy: false);
  if (!ack) {
    settings.forEach((id, value) {
      writeUint16(payload, id);
      writeUint32(payload, value);
    });
  }
  return Http2Frame(
    type: http2FrameSettings,
    flags: ack ? http2FlagAck : 0,
    streamId: 0,
    payload: payload.takeBytes(),
  ).encode();
}

Result<Map<int, int>, PqTransportError> decodeHttp2Settings(Uint8List payload) {
  if (payload.length % http2SettingEntryBytes != 0) {
    return Result.failure(PqTransportError.decodeFailure('http2 settings len'));
  }
  final out = <int, int>{};
  for (var i = 0; i < payload.length; i += http2SettingEntryBytes) {
    final id = readUint16(payload, i);
    final value = readUint32(payload, i + 2);
    out[id] = value;
  }
  return Result.success(out);
}

Result<Uint8List, PqTransportError> http2Unpad(
  Http2Frame frame, {
  bool allowPriority = false,
}) {
  var start = 0;
  var end = frame.payload.length;
  if (frame.padded) {
    if (frame.payload.isEmpty) {
      return Result.failure(PqTransportError.decodeFailure('http2 pad'));
    }
    final pad = frame.payload[0];
    start = 1;
    end -= pad;
    if (end < start) {
      return Result.failure(
        PqTransportError.decodeFailure('http2 pad overflow'),
      );
    }
  }
  if (allowPriority && frame.hasPriority) {
    start += http2PriorityPayloadBytes;
    if (end < start) {
      return Result.failure(PqTransportError.decodeFailure('http2 priority'));
    }
  }
  return Result.success(slice(frame.payload, start, end));
}

List<HpackHeader> http2RequestHeaders(PqHttpRequest req) {
  final path = req.uri.hasQuery
      ? '${req.uri.path.isEmpty ? '/' : req.uri.path}?${req.uri.query}'
      : (req.uri.path.isEmpty ? '/' : req.uri.path);
  final scheme = req.uri.scheme.isEmpty ? 'https' : req.uri.scheme;
  var authority = req.uri.host;
  if (req.uri.hasPort) {
    authority = '$authority:${req.uri.port}';
  }
  final connect = req.method.toUpperCase() == 'CONNECT';
  final protocol = req.protocol;
  final List<HpackHeader> out;
  if (connect && protocol == null) {
    out = [
      const HpackHeader(':method', 'CONNECT'),
      HpackHeader(':authority', authority),
    ];
  } else if (connect && protocol != null) {
    out = [
      const HpackHeader(':method', 'CONNECT'),
      HpackHeader(':protocol', protocol),
      HpackHeader(':scheme', scheme),
      HpackHeader(':authority', authority),
      HpackHeader(':path', path),
    ];
  } else {
    out = [
      HpackHeader(':method', req.method),
      HpackHeader(':scheme', scheme),
      HpackHeader(':authority', authority),
      HpackHeader(':path', path),
    ];
  }
  req.headers.forEach((k, v) {
    final name = k.toLowerCase();
    if (name == 'host' ||
        name == 'connection' ||
        name == 'keep-alive' ||
        name == 'proxy-connection' ||
        name == 'transfer-encoding' ||
        name == 'upgrade' ||
        name.startsWith(':')) {
      return;
    }
    out.add(HpackHeader(name, v));
  });
  return out;
}

List<HpackHeader> http2ResponseHeaders(PqHttpResponse resp) {
  final out = <HpackHeader>[HpackHeader(':status', '${resp.status}')];
  resp.headers.forEach((k, v) {
    out.add(HpackHeader(k.toLowerCase(), v));
  });
  return out;
}

Result<PqHttpRequest, PqTransportError> http2ParseRequest(
  List<HpackHeader> headers,
  Uint8List body,
) {
  String? method;
  String? scheme;
  String? authority;
  String? path;
  String? protocol;
  final regular = <String, String>{};
  for (final h in headers) {
    if (h.name.startsWith(':')) {
      switch (h.name) {
        case ':method':
          if (method != null) {
            return Result.failure(
              PqTransportError.decodeFailure('http2 pseudo dup'),
            );
          }
          method = h.value;
        case ':scheme':
          if (scheme != null) {
            return Result.failure(
              PqTransportError.decodeFailure('http2 pseudo dup'),
            );
          }
          scheme = h.value;
        case ':authority':
          if (authority != null) {
            return Result.failure(
              PqTransportError.decodeFailure('http2 pseudo dup'),
            );
          }
          authority = h.value;
        case ':path':
          if (path != null) {
            return Result.failure(
              PqTransportError.decodeFailure('http2 pseudo dup'),
            );
          }
          path = h.value;
        case ':protocol':
          if (protocol != null) {
            return Result.failure(
              PqTransportError.decodeFailure('http2 pseudo dup'),
            );
          }
          protocol = h.value;
        default:
          return Result.failure(
            PqTransportError.decodeFailure('http2 pseudo ${h.name}'),
          );
      }
    } else {
      regular[h.name] = h.value;
    }
  }
  if (method == null) {
    return Result.failure(
      PqTransportError.decodeFailure('http2 missing pseudo'),
    );
  }
  final connect = method.toUpperCase() == 'CONNECT';
  if (protocol != null && !connect) {
    return Result.failure(PqTransportError.decodeFailure('http2 protocol'));
  }
  if (connect && protocol == null) {
    if (scheme != null ||
        path != null ||
        authority == null ||
        authority.isEmpty) {
      return Result.failure(PqTransportError.decodeFailure('http2 connect'));
    }
    return Result.success(
      PqHttpRequest(
        method: method,
        uri: Uri.parse('https://$authority/'),
        headers: regular,
        body: body,
      ),
    );
  }
  if (connect && protocol != null) {
    if (!_httpProtocolToken(protocol) ||
        scheme == null ||
        path == null ||
        authority == null ||
        authority.isEmpty) {
      return Result.failure(
        PqTransportError.decodeFailure('http2 extended connect'),
      );
    }
  } else if (path == null || scheme == null) {
    return Result.failure(
      PqTransportError.decodeFailure('http2 missing pseudo'),
    );
  }
  final host = authority ?? 'localhost';
  return Result.success(
    PqHttpRequest(
      method: method,
      uri: Uri.parse('$scheme://$host$path'),
      headers: regular,
      body: body,
      protocol: protocol,
    ),
  );
}

Result<PqHttpResponse, PqTransportError> http2ParseResponse(
  List<HpackHeader> headers,
  Uint8List body, {
  List<HpackHeader> trailers = const [],
}) {
  String? statusText;
  final regular = <String, String>{};
  for (final h in headers) {
    if (h.name == ':status') {
      statusText = h.value;
    } else if (h.name.startsWith(':')) {
      return Result.failure(
        PqTransportError.decodeFailure('http2 pseudo ${h.name}'),
      );
    } else {
      regular[h.name] = h.value;
    }
  }
  final status = int.tryParse(statusText ?? '');
  if (status == null) {
    return Result.failure(PqTransportError.decodeFailure('http2 :status'));
  }
  final trailerMap = <String, String>{};
  for (final h in trailers) {
    if (h.name.startsWith(':')) {
      return Result.failure(
        PqTransportError.decodeFailure('http2 trailer ${h.name}'),
      );
    }
    trailerMap[h.name] = h.value;
  }
  return Result.success(
    PqHttpResponse(
      status: status,
      headers: regular,
      body: body,
      version: HttpVersion.h2,
      trailers: trailerMap,
    ),
  );
}

const Map<int, int> http2ClientSettings = {
  http2SettingsEnablePush: 0,
  http2SettingsMaxConcurrentStreams: http2DefaultMaxConcurrentStreams,
  http2SettingsInitialWindowSize: http2DefaultInitialWindowSize,
  http2SettingsMaxFrameSize: http2DefaultMaxFrameSize,
  http2SettingsMaxHeaderListSize: http2DefaultMaxHeaderListSize,
};

const Map<int, int> http2ServerSettings = {
  http2SettingsEnableConnectProtocol: 1,
  http2SettingsNoRfc7540Priorities: 1,
  http2SettingsMaxConcurrentStreams: http2DefaultMaxConcurrentStreams,
  http2SettingsInitialWindowSize: http2DefaultInitialWindowSize,
  http2SettingsMaxFrameSize: http2DefaultMaxFrameSize,
  http2SettingsMaxHeaderListSize: http2DefaultMaxHeaderListSize,
};

bool _httpProtocolToken(String value) {
  if (value.isEmpty) return false;
  for (final unit in value.codeUnits) {
    final digit = unit >= 0x30 && unit <= 0x39;
    final upper = unit >= 0x41 && unit <= 0x5a;
    final lower = unit >= 0x61 && unit <= 0x7a;
    const extra = '!#\$%&\'*+-.^_`|~';
    if (!digit &&
        !upper &&
        !lower &&
        !extra.contains(String.fromCharCode(unit))) {
      return false;
    }
  }
  return true;
}

/// RFC 9218. Unknown parameters are ignored. Urgency outside 0..7 is ignored.
final class HttpPriority {
  const HttpPriority({this.urgency = 3, this.incremental = false});

  final int urgency;
  final bool incremental;
}

HttpPriority parseHttpPriority(String field) {
  var urgency = 3;
  var incremental = false;
  for (final part in field.split(',')) {
    final token = part.trim();
    if (token.length == 3 && token.startsWith('u=')) {
      final n = token.codeUnitAt(2) - 0x30;
      if (n >= 0 && n <= 7) urgency = n;
    } else if (token == 'i' || token == 'i=?1') {
      incremental = true;
    } else if (token == 'i=?0') {
      incremental = false;
    }
  }
  return HttpPriority(urgency: urgency, incremental: incremental);
}

/// RFC 9218 / RFC 8941. The priority field is ASCII. A tab or a space is
/// legal. Anything else is not a structured field.
bool httpPriorityText(Uint8List bytes) {
  for (final unit in bytes) {
    if (unit != 0x09 && (unit < 0x20 || unit > 0x7e)) return false;
  }
  return true;
}

String encodeHttpPriorityField({int urgency = 3, bool incremental = false}) {
  final u = urgency < 0 ? 0 : (urgency > 7 ? 7 : urgency);
  return incremental ? 'u=$u, i' : 'u=$u, i=?0';
}

Uint8List encodeHttp2PriorityUpdate(int streamId, String field) {
  final b = BytesBuilder(copy: false);
  writeUint32(b, streamId & http2StreamIdMask);
  b.add(utf8.encode(field));
  return Http2Frame(
    type: http2FramePriorityUpdate,
    flags: 0,
    streamId: 0,
    payload: b.takeBytes(),
  ).encode();
}

enum Http2StreamState { idle, open, halfClosedLocal, halfClosedRemote, closed }

int http2HeaderListSize(List<HpackHeader> headers) {
  var size = 0;
  for (final header in headers) {
    size += header.name.length + header.value.length + hpackEntryOverheadBytes;
  }
  return size;
}

Uint8List encodeHttp2WindowUpdate(int streamId, int increment) {
  final payload = BytesBuilder(copy: false);
  writeUint32(payload, increment & http2StreamIdMask);
  return Http2Frame(
    type: http2FrameWindowUpdate,
    flags: 0,
    streamId: streamId,
    payload: payload.takeBytes(),
  ).encode();
}

Uint8List encodeHttp2RstStream(int streamId, int errorCode) {
  final payload = BytesBuilder(copy: false);
  writeUint32(payload, errorCode);
  return Http2Frame(
    type: http2FrameRstStream,
    flags: 0,
    streamId: streamId,
    payload: payload.takeBytes(),
  ).encode();
}

Uint8List encodeHttp2Goaway({
  required int lastStreamId,
  required int errorCode,
}) {
  final payload = BytesBuilder(copy: false);
  writeUint32(payload, lastStreamId & http2StreamIdMask);
  writeUint32(payload, errorCode);
  return Http2Frame(
    type: http2FrameGoaway,
    flags: 0,
    streamId: 0,
    payload: payload.takeBytes(),
  ).encode();
}

/// HTTP/2 session over a completed [PqTlsSocket] (ALPN `h2`).
final class PqHttp2Session {
  PqHttp2Session._(this.tls, {required this.isClient})
    : _encode = HpackCodec(),
      _decode = HpackCodec() {
    _sub = tls.applicationData.listen(
      _onBytes,
      onDone: () {
        _closed = true;
        _wake();
      },
    );
  }

  factory PqHttp2Session.client(PqTlsSocket tls) =>
      PqHttp2Session._(tls, isClient: true);

  factory PqHttp2Session.server(PqTlsSocket tls) =>
      PqHttp2Session._(tls, isClient: false);

  final PqTlsSocket tls;
  final bool isClient;
  final HpackCodec _encode;
  final HpackCodec _decode;
  final BytesBuilder _buf = BytesBuilder(copy: false);
  final List<Http2Frame> _frames = [];
  StreamSubscription<Uint8List>? _sub;
  final List<Completer<void>> _waiters = [];
  PqTransportError? _error;
  var _prefaceDone = false;
  var _sawPeerSettings = false;
  var _started = false;
  var _closed = false;
  var _nextStreamId = http2ClientInitialStreamId;
  var _peerMaxFrameSize = http2DefaultMaxFrameSize;
  final int _localMaxFrameSize = http2DefaultMaxFrameSize;
  final int _localInitialWindow = http2DefaultInitialWindowSize;
  var _peerInitialWindow = http2DefaultInitialWindowSize;
  var _sendConnWindow = http2DefaultInitialWindowSize;
  var _recvConnWindow = http2DefaultInitialWindowSize;
  var _peerMaxConcurrent = http2DefaultMaxConcurrentStreams;
  final int _localMaxConcurrent = http2DefaultMaxConcurrentStreams;
  int? _peerMaxHeaderList;
  final int _localMaxHeaderList = http2DefaultMaxHeaderListSize;
  var _expectContinuation = false;
  var _continuationStream = 0;
  var _highestPeerStream = 0;
  var _goawaySent = false;
  var _peerConnectProtocol = 0;
  var _peerEnablePush = 1;
  int? _peerNoRfc7540Priorities;
  final Map<int, HttpPriority> priorities = {};
  final Map<int, _H2Stream> _streams = {};
  Completer<void>? _windowWaiter;
  Future<void> _outbox = Future<void>.value();

  bool get isStarted => _started;

  bool get peerExtendedConnect => _peerConnectProtocol == 1;

  int get peerEnablePush => _peerEnablePush;

  PqTransportError? get error => _error;

  Http2StreamState streamState(int id) =>
      _streams[id]?.state ?? Http2StreamState.idle;

  Future<Result<void, PqTransportError>> start({
    Duration timeout = const Duration(seconds: 10),
  }) async {
    if (_started) return const Result.success(null);
    if (isClient) {
      _prefaceDone = true;
      final sent = await tls.send(
        concatBytes([
          Uint8List.fromList(ascii.encode(http2ConnectionPreface)),
          encodeHttp2Settings(http2ClientSettings),
        ]),
      );
      if (sent.isFailure) return Result.failure(sent.errorOrNull!);
    } else {
      final sent = await tls.send(encodeHttp2Settings(http2ServerSettings));
      if (sent.isFailure) return Result.failure(sent.errorOrNull!);
    }
    final ready = await _waitUntil(() => _sawPeerSettings, timeout);
    if (ready.isFailure) return ready;
    _started = true;
    return const Result.success(null);
  }

  Future<Result<void, PqTransportError>> ensureStarted({
    Duration timeout = const Duration(seconds: 10),
  }) => start(timeout: timeout);

  Future<Result<PqHttpResponse, PqTransportError>> request(
    PqHttpRequest req, {
    Duration timeout = const Duration(seconds: 10),
  }) async {
    if (!isClient) {
      return Result.failure(
        PqTransportError.internalError('server cannot request'),
      );
    }
    final started = await ensureStarted(timeout: timeout);
    if (started.isFailure) return Result.failure(started.errorOrNull!);
    if (_error != null) return Result.failure(_error!);
    if (req.protocol != null && _peerConnectProtocol != 1) {
      return Result.failure(
        PqTransportError.decodeFailure('http2 connect protocol'),
      );
    }
    if (_localActive() >= _peerMaxConcurrent) {
      return Result.failure(
        PqTransportError.decodeFailure('http2 max streams'),
      );
    }
    final headers = http2RequestHeaders(req);
    final limited = _headerListTooLarge(headers, peer: true);
    if (limited != null) return Result.failure(limited);
    final streamId = _nextStreamId;
    _nextStreamId += 2;
    final endStream = req.body.isEmpty;
    _onLocalHeaders(streamId, endStream: endStream);
    final block = _encode.encode(headers);
    final sent = await _sendHeaderBlock(streamId, block, endStream: endStream);
    if (sent.isFailure) return Result.failure(sent.errorOrNull!);
    if (!endStream) {
      final data = await _sendBody(
        streamId,
        req.body,
        endStream: true,
        timeout: timeout,
      );
      if (data.isFailure) return Result.failure(data.errorOrNull!);
    }
    final assembled = await _collect(streamId, timeout);
    if (assembled.isFailure) return Result.failure(assembled.errorOrNull!);
    final (responseHeaders, body, _, trailers) = assembled.valueOrNull!;
    final sized = _headerListTooLarge(responseHeaders, peer: false);
    if (sized != null) {
      _failStream(streamId, http2ErrorProtocol);
      return Result.failure(sized);
    }
    final trailerSized = _headerListTooLarge(trailers, peer: false);
    if (trailerSized != null) {
      _failStream(streamId, http2ErrorProtocol);
      return Result.failure(trailerSized);
    }
    return http2ParseResponse(responseHeaders, body, trailers: trailers);
  }

  Future<Result<(int, PqHttpRequest), PqTransportError>> accept({
    Duration timeout = const Duration(seconds: 10),
  }) async {
    if (isClient) {
      return Result.failure(
        PqTransportError.internalError('client cannot accept'),
      );
    }
    final started = await ensureStarted(timeout: timeout);
    if (started.isFailure) return Result.failure(started.errorOrNull!);
    final assembled = await _collect(0, timeout);
    if (assembled.isFailure) return Result.failure(assembled.errorOrNull!);
    final (headers, body, streamId, _) = assembled.valueOrNull!;
    final sized = _headerListTooLarge(headers, peer: false);
    if (sized != null) {
      _failStream(streamId, http2ErrorProtocol);
      return Result.failure(sized);
    }
    final req = http2ParseRequest(headers, body);
    if (req.isFailure) return Result.failure(req.errorOrNull!);
    return Result.success((streamId, req.valueOrNull!));
  }

  Future<Result<void, PqTransportError>> respond(
    int streamId,
    PqHttpResponse resp, {
    Map<String, String> trailers = const {},
    Duration timeout = const Duration(seconds: 10),
  }) async {
    final trailerHeaders = [
      for (final entry in trailers.entries)
        HpackHeader(entry.key.toLowerCase(), entry.value),
    ];
    final headers = http2ResponseHeaders(resp);
    final limited = _headerListTooLarge(headers, peer: true);
    if (limited != null) return Result.failure(limited);
    final endStream = resp.body.isEmpty && trailerHeaders.isEmpty;
    _onLocalHeaders(streamId, endStream: endStream);
    final block = _encode.encode(headers);
    final sent = await _sendHeaderBlock(streamId, block, endStream: endStream);
    if (sent.isFailure) return sent;
    if (resp.body.isNotEmpty) {
      final data = await _sendBody(
        streamId,
        resp.body,
        endStream: trailerHeaders.isEmpty,
        timeout: timeout,
      );
      if (data.isFailure) return data;
    }
    if (trailerHeaders.isEmpty) return const Result.success(null);
    final trailerLimited = _headerListTooLarge(trailerHeaders, peer: true);
    if (trailerLimited != null) return Result.failure(trailerLimited);
    final trailersSent = await _sendHeaderBlock(
      streamId,
      _encode.encode(trailerHeaders),
      endStream: true,
    );
    if (trailersSent.isSuccess) _onLocalEnd(streamId);
    return trailersSent;
  }

  Future<void> close() async {
    if (!_goawaySent && _started && _error == null) {
      _goawaySent = true;
      await _send(
        encodeHttp2Goaway(
          lastStreamId: _highestPeerStream,
          errorCode: http2ErrorNoError,
        ),
      );
    }
    _closed = true;
    await _sub?.cancel();
    _sub = null;
    _wake();
    _wakeWindow();
  }

  Future<Result<void, PqTransportError>> _sendHeaderBlock(
    int streamId,
    Uint8List block, {
    required bool endStream,
  }) async {
    final max = _peerMaxFrameSize < http2TlsSafeDataBytes
        ? _peerMaxFrameSize
        : http2TlsSafeDataBytes;
    if (block.length <= max) {
      return _send(
        Http2Frame(
          type: http2FrameHeaders,
          flags: http2FlagEndHeaders | (endStream ? http2FlagEndStream : 0),
          streamId: streamId,
          payload: block,
        ).encode(),
      );
    }
    var offset = 0;
    var first = true;
    while (offset < block.length) {
      final take = block.length - offset > max ? max : block.length - offset;
      final last = offset + take >= block.length;
      final type = first ? http2FrameHeaders : http2FrameContinuation;
      var flags = 0;
      if (last) flags |= http2FlagEndHeaders;
      if (first && endStream && last) flags |= http2FlagEndStream;
      final r = await _send(
        Http2Frame(
          type: type,
          flags: flags,
          streamId: streamId,
          payload: slice(block, offset, offset + take),
        ).encode(),
      );
      if (r.isFailure) return r;
      offset += take;
      first = false;
    }
    if (endStream && block.length > max) {
      return _send(
        Http2Frame(
          type: http2FrameData,
          flags: http2FlagEndStream,
          streamId: streamId,
          payload: Uint8List(0),
        ).encode(),
      );
    }
    return const Result.success(null);
  }

  Future<
    Result<
      (List<HpackHeader>, Uint8List, int, List<HpackHeader>),
      PqTransportError
    >
  >
  _collect(int wantStream, Duration timeout) async {
    final headerParts = BytesBuilder(copy: false);
    final trailerParts = BytesBuilder(copy: false);
    final dataParts = BytesBuilder(copy: false);
    var headerPartsAreTrailers = false;
    var headersOpen = false;
    var headersDone = false;
    var streamEnded = false;
    var ended = false;
    var streamId = wantStream;
    final deadline = DateTime.now().add(timeout);
    while (!ended) {
      final remaining = deadline.difference(DateTime.now());
      if (remaining.isNegative) {
        return Result.failure(PqTransportError.decodeFailure('http2 timeout'));
      }
      final next = await _waitFrame(remaining);
      if (next.isFailure) return Result.failure(next.errorOrNull!);
      final frame = next.valueOrNull!;
      if (frame.type == http2FrameGoaway) {
        return Result.failure(PqTransportError.closed('http2 goaway'));
      }
      if (frame.type == http2FrameRstStream) {
        return Result.failure(PqTransportError.closed('http2 rst'));
      }
      if (wantStream != 0 && frame.streamId != wantStream) {
        continue;
      }
      if (wantStream == 0 &&
          frame.type != http2FrameHeaders &&
          frame.type != http2FrameContinuation &&
          frame.type != http2FrameData) {
        continue;
      }
      if (frame.type == http2FrameHeaders) {
        if (headersDone) {
          if (!frame.endStream) {
            return Result.failure(
              PqTransportError.decodeFailure('http2 unexpected headers'),
            );
          }
          headerPartsAreTrailers = true;
          streamId = frame.streamId;
          final body = http2Unpad(frame, allowPriority: true);
          if (body.isFailure) return Result.failure(body.errorOrNull!);
          trailerParts.add(body.valueOrNull!);
          headersOpen = !frame.endHeaders;
          ended = frame.endHeaders;
          continue;
        }
        if (frame.streamId == 0) {
          return Result.failure(
            PqTransportError.decodeFailure('http2 headers stream 0'),
          );
        }
        streamId = frame.streamId;
        final body = http2Unpad(frame, allowPriority: true);
        if (body.isFailure) return Result.failure(body.errorOrNull!);
        headerParts.add(body.valueOrNull!);
        headersOpen = !frame.endHeaders;
        headersDone = frame.endHeaders;
        streamEnded = frame.endStream;
        ended = streamEnded && headersDone;
      } else if (frame.type == http2FrameContinuation) {
        if (!headersOpen || frame.streamId != streamId) {
          return Result.failure(
            PqTransportError.decodeFailure('http2 continuation'),
          );
        }
        if (headerPartsAreTrailers) {
          trailerParts.add(frame.payload);
        } else {
          headerParts.add(frame.payload);
        }
        headersOpen = !frame.endHeaders;
        if (!headerPartsAreTrailers) headersDone = frame.endHeaders;
        ended = headerPartsAreTrailers
            ? frame.endHeaders
            : streamEnded && headersDone;
      } else if (frame.type == http2FrameData) {
        if (!headersDone || headersOpen || frame.streamId != streamId) {
          return Result.failure(
            PqTransportError.decodeFailure('http2 data before headers'),
          );
        }
        if (frame.streamId == 0) {
          return Result.failure(
            PqTransportError.decodeFailure('http2 data stream 0'),
          );
        }
        final body = http2Unpad(frame);
        if (body.isFailure) return Result.failure(body.errorOrNull!);
        dataParts.add(body.valueOrNull!);
        ended = frame.endStream;
      }
    }
    final decoded = _decode.decode(headerParts.takeBytes());
    if (decoded.isFailure) return Result.failure(decoded.errorOrNull!);
    final trailerBytes = trailerParts.takeBytes();
    final decodedTrailers = trailerBytes.isEmpty
        ? const Result<List<HpackHeader>, PqTransportError>.success([])
        : _decode.decode(trailerBytes);
    if (decodedTrailers.isFailure) {
      return Result.failure(decodedTrailers.errorOrNull!);
    }
    return Result.success((
      decoded.valueOrNull!,
      dataParts.takeBytes(),
      streamId,
      decodedTrailers.valueOrNull!,
    ));
  }

  void _onBytes(Uint8List chunk) {
    if (_error != null || _closed) return;
    _buf.add(chunk);
    _peel();
  }

  void _peel() {
    var wire = _buf.takeBytes();
    while (true) {
      if (!_prefaceDone) {
        if (wire.length < http2PrefaceBytes) {
          _buf.add(wire);
          return;
        }
        String got;
        try {
          got = ascii.decode(wire.sublist(0, http2PrefaceBytes));
        } on FormatException {
          _fail(PqTransportError.decodeFailure('http2 preface'));
          return;
        }
        if (got != http2ConnectionPreface) {
          _fail(PqTransportError.decodeFailure('http2 preface'));
          return;
        }
        _prefaceDone = true;
        wire = slice(wire, http2PrefaceBytes, wire.length);
        continue;
      }
      final decoded = Http2Frame.tryDecode(
        wire,
        maxFrameSize: _localMaxFrameSize,
      );
      if (decoded.isFailure) {
        _failConnection(http2ErrorFrameSize, 'http2 frame too large');
        return;
      }
      final pair = decoded.valueOrNull;
      if (pair == null) {
        _buf.add(wire);
        return;
      }
      final (frame, n) = pair;
      wire = n < wire.length ? slice(wire, n, wire.length) : Uint8List(0);
      _handleFrame(frame);
      if (_error != null) return;
    }
  }

  void _handleFrame(Http2Frame frame) {
    if (_expectContinuation &&
        (frame.type != http2FrameContinuation ||
            frame.streamId != _continuationStream)) {
      _failConnection(http2ErrorProtocol, 'http2 continuation interrupted');
      return;
    }
    switch (frame.type) {
      case http2FrameSettings:
        if (frame.streamId != 0) {
          _failConnection(http2ErrorProtocol, 'http2 settings stream');
          return;
        }
        if (frame.ack) {
          if (frame.payload.isNotEmpty) {
            _failConnection(http2ErrorProtocol, 'http2 settings ack payload');
          }
          return;
        }
        final settings = decodeHttp2Settings(frame.payload);
        if (settings.isFailure) {
          _failConnection(http2ErrorProtocol, 'http2 settings');
          return;
        }
        _applySettings(settings.valueOrNull!);
        _sawPeerSettings = true;
        unawaited(
          _send(encodeHttp2Settings(const {}, ack: true)).then((r) {
            if (r.isFailure) _fail(r.errorOrNull!);
          }),
        );
        _wake();
      case http2FramePing:
        if (frame.streamId != 0 ||
            frame.payload.length != http2PingPayloadBytes) {
          _failConnection(http2ErrorProtocol, 'http2 ping');
          return;
        }
        if (!frame.ack) {
          unawaited(
            _send(
              Http2Frame(
                type: http2FramePing,
                flags: http2FlagAck,
                streamId: 0,
                payload: frame.payload,
              ).encode(),
            ),
          );
        }
      case http2FrameWindowUpdate:
        _applyWindowUpdate(frame);
      case http2FramePriority:
        // RFC 7540 PRIORITY. Deprecated. SETTINGS_NO_RFC7540_PRIORITIES
        // tells the peer these signals are ignored, so this is not an error.
        return;
      case http2FramePushPromise:
        _failConnection(http2ErrorProtocol, 'http2 push');
      case http2FramePriorityUpdate:
        _takePriorityUpdate(frame);
      case http2FrameGoaway:
        _frames.add(frame);
        _wake();
      case http2FrameRstStream:
        if (frame.payload.length != http2RstStreamPayloadBytes) {
          _failConnection(http2ErrorFrameSize, 'http2 rst');
          return;
        }
        if (frame.streamId == 0) {
          _failConnection(http2ErrorProtocol, 'http2 rst');
          return;
        }
        final existing = _streams[frame.streamId];
        if (existing == null || existing.state == Http2StreamState.idle) {
          _failConnection(http2ErrorProtocol, 'http2 rst idle');
          return;
        }
        _onRemoteReset(frame.streamId);
        _frames.add(frame);
        _wake();
      case http2FrameData:
      case http2FrameHeaders:
      case http2FrameContinuation:
        if (!_acceptStreamFrame(frame)) return;
        _frames.add(frame);
        _wake();
      default:
        _failConnection(http2ErrorProtocol, 'http2 frame');
    }
  }

  void _takePriorityUpdate(Http2Frame frame) {
    if (isClient || frame.streamId != 0) {
      _failConnection(http2ErrorProtocol, 'http2 priority update');
      return;
    }
    if (frame.payload.length < 4) {
      _failConnection(http2ErrorFrameSize, 'http2 priority update');
      return;
    }
    final raw = readUint32(frame.payload, 0);
    if ((raw & 0x80000000) != 0) {
      _failConnection(http2ErrorProtocol, 'http2 priority update');
      return;
    }
    final prioritized = raw & http2StreamIdMask;
    if (prioritized == 0) {
      _failConnection(http2ErrorProtocol, 'http2 priority update');
      return;
    }
    final fieldBytes = Uint8List.sublistView(frame.payload, 4);
    if (!httpPriorityText(fieldBytes)) {
      _failConnection(http2ErrorProtocol, 'http2 priority update');
      return;
    }
    final field = utf8.decode(fieldBytes);
    final state = streamState(prioritized);
    // Push streams are server-initiated (even). An idle one was never
    // promised. RFC 9218 §7.1.
    if (prioritized.isEven && state == Http2StreamState.idle) {
      _failConnection(http2ErrorProtocol, 'http2 priority update');
      return;
    }
    if (state == Http2StreamState.halfClosedLocal ||
        state == Http2StreamState.closed) {
      return;
    }
    if (state == Http2StreamState.idle &&
        !priorities.containsKey(prioritized) &&
        _priorityLoad() >= _localMaxConcurrent) {
      _failConnection(http2ErrorProtocol, 'http2 priority update');
      return;
    }
    priorities[prioritized] = parseHttpPriority(field);
  }

  /// RFC 9218 §7.1. Clients only. The server records it and does not
  /// reorder streams from it.
  Future<Result<void, PqTransportError>> updatePriority(
    int streamId, {
    int urgency = 3,
    bool incremental = false,
  }) {
    if (!isClient || streamId <= 0) {
      return Future.value(
        Result.failure(PqTransportError.decodeFailure('http2 priority update')),
      );
    }
    // RFC 9218 §2.1. A server that omits the setting, or sends 0, is not
    // using this frame. Sending it anyway is wasted and often ignored.
    if (_sawPeerSettings && _peerNoRfc7540Priorities != 1) {
      return Future.value(
        Result.failure(PqTransportError.decodeFailure('http2 priority update')),
      );
    }
    return _send(
      encodeHttp2PriorityUpdate(
        streamId,
        encodeHttpPriorityField(urgency: urgency, incremental: incremental),
      ),
    );
  }

  void _applySettings(Map<int, int> map) {
    final push = map[http2SettingsEnablePush];
    if (push != null) {
      if (isClient || (push != 0 && push != 1)) {
        _failConnection(http2ErrorProtocol, 'http2 enable_push');
        return;
      }
      if (_peerEnablePush == 0 && push == 1) {
        _failConnection(http2ErrorProtocol, 'http2 enable_push');
        return;
      }
      _peerEnablePush = push;
    }
    final connect = map[http2SettingsEnableConnectProtocol];
    if (connect != null) {
      if (connect != 0 && connect != 1) {
        _failConnection(http2ErrorProtocol, 'http2 connect protocol');
        return;
      }
      if (!isClient) {
        _failConnection(http2ErrorProtocol, 'http2 connect protocol');
        return;
      }
      if (_peerConnectProtocol == 1 && connect == 0) {
        _failConnection(http2ErrorProtocol, 'http2 connect protocol');
        return;
      }
      _peerConnectProtocol = connect;
    }
    final oldPriorities = map[http2SettingsNoRfc7540Priorities];
    if (oldPriorities != null) {
      if (oldPriorities != 0 && oldPriorities != 1) {
        _failConnection(http2ErrorProtocol, 'http2 priorities');
        return;
      }
      if (_peerNoRfc7540Priorities != null &&
          _peerNoRfc7540Priorities != oldPriorities) {
        _failConnection(http2ErrorProtocol, 'http2 priorities');
        return;
      }
      _peerNoRfc7540Priorities = oldPriorities;
    }
    final maxFrame = map[http2SettingsMaxFrameSize];
    if (maxFrame != null) {
      if (maxFrame < http2MinMaxFrameSize || maxFrame > http2MaxMaxFrameSize) {
        _failConnection(http2ErrorProtocol, 'http2 max frame');
        return;
      }
      _peerMaxFrameSize = maxFrame;
    }
    final table = map[http2SettingsHeaderTableSize];
    if (table != null) _encode.setMaxTableSize(table);
    final concurrent = map[http2SettingsMaxConcurrentStreams];
    if (concurrent != null) _peerMaxConcurrent = concurrent;
    final headerList = map[http2SettingsMaxHeaderListSize];
    if (headerList != null) _peerMaxHeaderList = headerList;
    final window = map[http2SettingsInitialWindowSize];
    if (window == null) return;
    if (window > http2MaxWindowSize) {
      _failConnection(http2ErrorFlowControl, 'http2 window');
      return;
    }
    final delta = window - _peerInitialWindow;
    _peerInitialWindow = window;
    if (delta == 0) return;
    for (final stream in _streams.values) {
      final next = stream.send + delta;
      if (next < 0 || next > http2MaxWindowSize) {
        _failConnection(http2ErrorFlowControl, 'http2 window');
        return;
      }
      stream.send = next;
    }
    _wakeWindow();
  }

  void _applyWindowUpdate(Http2Frame frame) {
    if (frame.payload.length != http2WindowUpdatePayloadBytes) {
      _failConnection(http2ErrorProtocol, 'http2 window update');
      return;
    }
    final inc = readUint32(frame.payload, 0) & http2StreamIdMask;
    if (inc == 0) {
      _failConnection(http2ErrorProtocol, 'http2 window increment 0');
      return;
    }
    if (frame.streamId == 0) {
      if (_sendConnWindow > http2MaxWindowSize - inc) {
        _failConnection(http2ErrorFlowControl, 'http2 flow control');
        return;
      }
      _sendConnWindow += inc;
      _wakeWindow();
      return;
    }
    final stream = _streams[frame.streamId];
    if (stream == null || stream.state == Http2StreamState.idle) {
      _failConnection(http2ErrorProtocol, 'http2 window stream');
      return;
    }
    if (stream.state == Http2StreamState.closed) return;
    if (stream.send > http2MaxWindowSize - inc) {
      _failStream(frame.streamId, http2ErrorFlowControl);
      return;
    }
    stream.send += inc;
    _wakeWindow();
  }

  bool _acceptStreamFrame(Http2Frame frame) {
    if (frame.streamId == 0) {
      _failConnection(http2ErrorProtocol, 'http2 stream 0');
      return false;
    }
    if (frame.type == http2FrameHeaders && !frame.endHeaders) {
      _expectContinuation = true;
      _continuationStream = frame.streamId;
    } else if (frame.type == http2FrameContinuation) {
      _expectContinuation = !frame.endHeaders;
    } else if (frame.type == http2FrameHeaders) {
      _expectContinuation = false;
    }
    final remote = _remoteInitiated(frame.streamId);
    if (remote && frame.streamId > _highestPeerStream) {
      _highestPeerStream = frame.streamId;
    }
    final stream = _ensure(frame.streamId);
    if (frame.type != http2FrameContinuation &&
        (stream.state == Http2StreamState.closed ||
            stream.state == Http2StreamState.halfClosedRemote)) {
      _failStream(frame.streamId, http2ErrorStreamClosed);
      return false;
    }
    if (stream.state == Http2StreamState.idle &&
        frame.type != http2FrameHeaders) {
      _failConnection(http2ErrorProtocol, 'http2 idle');
      return false;
    }
    if (frame.type == http2FrameHeaders &&
        stream.state == Http2StreamState.idle &&
        remote &&
        _remoteActive() >= _localMaxConcurrent) {
      _failStream(frame.streamId, http2ErrorRefusedStream);
      return false;
    }
    if (frame.type == http2FrameData) {
      final n = frame.payload.length;
      if (n > _recvConnWindow || n > stream.recv) {
        if (n > _recvConnWindow) {
          _failConnection(http2ErrorFlowControl, 'http2 flow control');
        } else {
          _failStream(frame.streamId, http2ErrorFlowControl);
        }
        return false;
      }
      _recvConnWindow -= n;
      stream.recv -= n;
      _credit(frame.streamId, n);
    }
    _onRemoteFrame(frame);
    return true;
  }

  void _credit(int streamId, int n) {
    if (n == 0) return;
    _recvConnWindow += n;
    final stream = _streams[streamId];
    if (stream != null) stream.recv += n;
    unawaited(_send(encodeHttp2WindowUpdate(0, n)));
    unawaited(_send(encodeHttp2WindowUpdate(streamId, n)));
  }

  Future<Result<void, PqTransportError>> _sendBody(
    int streamId,
    List<int> body, {
    required bool endStream,
    required Duration timeout,
  }) async {
    final data = Uint8List.fromList(body);
    var offset = 0;
    while (offset < data.length) {
      final ready = await _waitSendWindow(streamId, timeout);
      if (ready.isFailure) return ready;
      final stream = _ensure(streamId);
      var n = data.length - offset;
      final frameCap = _peerMaxFrameSize < http2TlsSafeDataBytes
          ? _peerMaxFrameSize
          : http2TlsSafeDataBytes;
      if (n > frameCap) n = frameCap;
      if (n > _sendConnWindow) n = _sendConnWindow;
      if (n > stream.send) n = stream.send;
      if (n == 0) continue;
      final last = offset + n == data.length;
      _sendConnWindow -= n;
      stream.send -= n;
      final sent = await _send(
        Http2Frame(
          type: http2FrameData,
          flags: last && endStream ? http2FlagEndStream : 0,
          streamId: streamId,
          payload: Uint8List.sublistView(data, offset, offset + n),
        ).encode(),
      );
      if (sent.isFailure) return sent;
      offset += n;
      if (last && endStream) _onLocalEnd(streamId);
    }
    return const Result.success(null);
  }

  Future<Result<void, PqTransportError>> _waitSendWindow(
    int streamId,
    Duration timeout,
  ) async {
    final deadline = DateTime.now().add(timeout);
    while (_sendConnWindow == 0 || (_streams[streamId]?.send ?? 0) == 0) {
      if (_error != null) return Result.failure(_error!);
      if (_closed) return Result.failure(PqTransportError.closed('http2'));
      final remaining = deadline.difference(DateTime.now());
      if (remaining.isNegative) {
        return Result.failure(
          PqTransportError.decodeFailure('http2 window timeout'),
        );
      }
      final done = Completer<void>();
      _windowWaiter = done;
      if (_sendConnWindow > 0 && (_streams[streamId]?.send ?? 0) > 0) {
        if (identical(_windowWaiter, done)) _windowWaiter = null;
        break;
      }
      try {
        await done.future.timeout(remaining);
      } on TimeoutException {
        return Result.failure(
          PqTransportError.decodeFailure('http2 window timeout'),
        );
      } finally {
        if (identical(_windowWaiter, done)) _windowWaiter = null;
      }
    }
    if (_error != null) return Result.failure(_error!);
    return const Result.success(null);
  }

  _H2Stream _ensure(int id) => _streams.putIfAbsent(
    id,
    () => _H2Stream(send: _peerInitialWindow, recv: _localInitialWindow),
  );

  void _onLocalHeaders(int id, {required bool endStream}) {
    final stream = _ensure(id);
    switch (stream.state) {
      case Http2StreamState.idle:
        stream.state = endStream
            ? Http2StreamState.halfClosedLocal
            : Http2StreamState.open;
      case Http2StreamState.open:
        if (endStream) stream.state = Http2StreamState.halfClosedLocal;
      case Http2StreamState.halfClosedRemote:
        if (endStream) stream.state = Http2StreamState.closed;
      case Http2StreamState.halfClosedLocal:
      case Http2StreamState.closed:
        break;
    }
  }

  void _onLocalEnd(int id) {
    final stream = _streams[id];
    if (stream == null) return;
    stream.state = stream.state == Http2StreamState.halfClosedRemote
        ? Http2StreamState.closed
        : Http2StreamState.halfClosedLocal;
  }

  void _onRemoteFrame(Http2Frame frame) {
    final stream = _ensure(frame.streamId);
    final end = frame.endStream && frame.type != http2FrameContinuation;
    if (frame.type == http2FrameHeaders &&
        stream.state == Http2StreamState.idle) {
      stream.state = end
          ? Http2StreamState.halfClosedRemote
          : Http2StreamState.open;
      return;
    }
    if (!end) return;
    stream.state = stream.state == Http2StreamState.halfClosedLocal
        ? Http2StreamState.closed
        : Http2StreamState.halfClosedRemote;
  }

  void _onRemoteReset(int id) {
    final stream = _streams[id];
    if (stream == null) return;
    stream.state = Http2StreamState.closed;
  }

  int _localActive() {
    var n = 0;
    for (final entry in _streams.entries) {
      if (!_remoteInitiated(entry.key) && _active(entry.value.state)) n++;
    }
    return n;
  }

  int _priorityLoad() {
    var n = 0;
    for (final entry in _streams.entries) {
      if (_active(entry.value.state)) n++;
    }
    for (final id in priorities.keys) {
      if (streamState(id) == Http2StreamState.idle) n++;
    }
    return n;
  }

  int _remoteActive() {
    var n = 0;
    for (final entry in _streams.entries) {
      if (_remoteInitiated(entry.key) && _active(entry.value.state)) n++;
    }
    return n;
  }

  bool _remoteInitiated(int id) => isClient ? id.isEven : id.isOdd;

  bool _active(Http2StreamState state) =>
      state == Http2StreamState.open ||
      state == Http2StreamState.halfClosedLocal ||
      state == Http2StreamState.halfClosedRemote;

  PqTransportError? _headerListTooLarge(
    List<HpackHeader> headers, {
    required bool peer,
  }) {
    final limit = peer ? _peerMaxHeaderList : _localMaxHeaderList;
    if (limit != null && http2HeaderListSize(headers) > limit) {
      return PqTransportError.decodeFailure('http2 header list');
    }
    return null;
  }

  void _failStream(int id, int code) {
    final stream = _streams[id];
    if (stream != null) stream.state = Http2StreamState.closed;
    unawaited(_send(encodeHttp2RstStream(id, code)));
    _wake();
    _wakeWindow();
  }

  void _failConnection(int code, String why) {
    if (_error != null) return;
    _error = PqTransportError.decodeFailure(why);
    if (!_goawaySent) {
      _goawaySent = true;
      unawaited(
        _send(
          encodeHttp2Goaway(lastStreamId: _highestPeerStream, errorCode: code),
        ),
      );
    }
    _wake();
    _wakeWindow();
  }

  void _wakeWindow() {
    final waiter = _windowWaiter;
    if (waiter != null && !waiter.isCompleted) waiter.complete();
  }

  Future<Result<Http2Frame, PqTransportError>> _waitFrame(
    Duration timeout,
  ) async {
    final deadline = DateTime.now().add(timeout);
    while (_frames.isEmpty && _error == null && !_closed) {
      final remaining = deadline.difference(DateTime.now());
      if (remaining.isNegative) {
        return Result.failure(
          PqTransportError.decodeFailure('http2 wait frame'),
        );
      }
      final waited = await _waitUntil(
        () => _frames.isNotEmpty || _error != null || _closed,
        remaining,
      );
      if (waited.isFailure) return Result.failure(waited.errorOrNull!);
    }
    if (_error != null) return Result.failure(_error!);
    if (_frames.isEmpty) {
      return Result.failure(PqTransportError.closed('http2'));
    }
    return Result.success(_frames.removeAt(0));
  }

  Future<Result<void, PqTransportError>> _waitUntil(
    bool Function() pred,
    Duration timeout,
  ) async {
    if (_error != null) return Result.failure(_error!);
    if (pred()) return const Result.success(null);
    final done = Completer<void>();
    _waiters.add(done);
    if (pred() || _error != null) {
      if (!done.isCompleted) done.complete();
    }
    try {
      await done.future.timeout(timeout);
    } on TimeoutException {
      return Result.failure(PqTransportError.decodeFailure('http2 timeout'));
    } finally {
      _waiters.remove(done);
    }
    if (_error != null) return Result.failure(_error!);
    if (!pred()) {
      return Result.failure(PqTransportError.decodeFailure('http2 wait'));
    }
    return const Result.success(null);
  }

  void _wake() {
    for (final w in List<Completer<void>>.of(_waiters)) {
      if (!w.isCompleted) w.complete();
    }
  }

  void _fail(PqTransportError e) {
    _error ??= e;
    _wake();
  }

  Future<Result<void, PqTransportError>> _send(Uint8List bytes) {
    final done = Completer<Result<void, PqTransportError>>();
    _outbox = _outbox.then((_) async {
      final r = await tls.send(bytes);
      if (!done.isCompleted) done.complete(r);
    });
    return done.future;
  }
}

final class _H2Stream {
  _H2Stream({required this.send, required this.recv});

  int send;
  int recv;
  Http2StreamState state = Http2StreamState.idle;
}
