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
  final out = <HpackHeader>[
    HpackHeader(':method', req.method),
    HpackHeader(':scheme', scheme),
    HpackHeader(':authority', authority),
    HpackHeader(':path', path),
  ];
  req.headers.forEach((k, v) {
    final name = k.toLowerCase();
    if (name == 'host' ||
        name == 'connection' ||
        name == 'keep-alive' ||
        name == 'proxy-connection' ||
        name == 'transfer-encoding' ||
        name == 'upgrade') {
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
  final regular = <String, String>{};
  for (final h in headers) {
    if (h.name.startsWith(':')) {
      switch (h.name) {
        case ':method':
          method = h.value;
        case ':scheme':
          scheme = h.value;
        case ':authority':
          authority = h.value;
        case ':path':
          path = h.value;
        default:
          return Result.failure(
            PqTransportError.decodeFailure('http2 pseudo ${h.name}'),
          );
      }
    } else {
      regular[h.name] = h.value;
    }
  }
  if (method == null || path == null || scheme == null) {
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
    ),
  );
}

Result<PqHttpResponse, PqTransportError> http2ParseResponse(
  List<HpackHeader> headers,
  Uint8List body,
) {
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
  return Result.success(
    PqHttpResponse(
      status: status,
      headers: regular,
      body: body,
      version: HttpVersion.h2,
    ),
  );
}

const Map<int, int> http2ClientSettings = {
  http2SettingsEnablePush: 0,
  http2SettingsMaxConcurrentStreams: http2DefaultMaxConcurrentStreams,
  http2SettingsInitialWindowSize: http2DefaultInitialWindowSize,
  http2SettingsMaxFrameSize: http2DefaultMaxFrameSize,
};

const Map<int, int> http2ServerSettings = {
  http2SettingsMaxConcurrentStreams: http2DefaultMaxConcurrentStreams,
  http2SettingsInitialWindowSize: http2DefaultInitialWindowSize,
  http2SettingsMaxFrameSize: http2DefaultMaxFrameSize,
};

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
  Completer<void>? _waiter;
  PqTransportError? _error;
  var _prefaceDone = false;
  var _sawPeerSettings = false;
  var _started = false;
  var _closed = false;
  var _nextStreamId = http2ClientInitialStreamId;
  var _peerMaxFrameSize = http2DefaultMaxFrameSize;
  Future<void> _outbox = Future<void>.value();

  bool get isStarted => _started;

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
    final streamId = _nextStreamId;
    _nextStreamId += 2;
    final block = _encode.encode(http2RequestHeaders(req));
    final endStream = req.body.isEmpty;
    final sent = await _sendHeaderBlock(streamId, block, endStream: endStream);
    if (sent.isFailure) return Result.failure(sent.errorOrNull!);
    if (!endStream) {
      final data = await _send(
        Http2Frame(
          type: http2FrameData,
          flags: http2FlagEndStream,
          streamId: streamId,
          payload: Uint8List.fromList(req.body),
        ).encode(),
      );
      if (data.isFailure) return Result.failure(data.errorOrNull!);
    }
    final assembled = await _collect(streamId, timeout);
    if (assembled.isFailure) return Result.failure(assembled.errorOrNull!);
    final (headers, body, _) = assembled.valueOrNull!;
    return http2ParseResponse(headers, body);
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
    final (headers, body, streamId) = assembled.valueOrNull!;
    final req = http2ParseRequest(headers, body);
    if (req.isFailure) return Result.failure(req.errorOrNull!);
    return Result.success((streamId, req.valueOrNull!));
  }

  Future<Result<void, PqTransportError>> respond(
    int streamId,
    PqHttpResponse resp,
  ) async {
    final block = _encode.encode(http2ResponseHeaders(resp));
    final endStream = resp.body.isEmpty;
    final sent = await _sendHeaderBlock(streamId, block, endStream: endStream);
    if (sent.isFailure) return sent;
    if (!endStream) {
      return _send(
        Http2Frame(
          type: http2FrameData,
          flags: http2FlagEndStream,
          streamId: streamId,
          payload: resp.body,
        ).encode(),
      );
    }
    return const Result.success(null);
  }

  Future<void> close() async {
    _closed = true;
    await _sub?.cancel();
    _sub = null;
    _wake();
  }

  Future<Result<void, PqTransportError>> _sendHeaderBlock(
    int streamId,
    Uint8List block, {
    required bool endStream,
  }) async {
    final max = _peerMaxFrameSize;
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

  Future<Result<(List<HpackHeader>, Uint8List, int), PqTransportError>>
  _collect(int wantStream, Duration timeout) async {
    final headerParts = BytesBuilder(copy: false);
    final dataParts = BytesBuilder(copy: false);
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
          if (frame.endStream) {
            ended = true;
            continue;
          }
          return Result.failure(
            PqTransportError.decodeFailure('http2 unexpected headers'),
          );
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
        headerParts.add(frame.payload);
        headersOpen = !frame.endHeaders;
        headersDone = frame.endHeaders;
        ended = streamEnded && headersDone;
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
    return Result.success((
      decoded.valueOrNull!,
      dataParts.takeBytes(),
      streamId,
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
        maxFrameSize: http2DefaultMaxFrameSize,
      );
      if (decoded.isFailure) {
        _fail(decoded.errorOrNull!);
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
    switch (frame.type) {
      case http2FrameSettings:
        if (frame.streamId != 0) {
          _fail(PqTransportError.decodeFailure('http2 settings stream'));
          return;
        }
        if (frame.ack) {
          if (frame.payload.isNotEmpty) {
            _fail(PqTransportError.decodeFailure('http2 settings ack payload'));
          }
          return;
        }
        final settings = decodeHttp2Settings(frame.payload);
        if (settings.isFailure) {
          _fail(settings.errorOrNull!);
          return;
        }
        final map = settings.valueOrNull!;
        final maxFrame = map[http2SettingsMaxFrameSize];
        if (maxFrame != null) {
          if (maxFrame < http2MinMaxFrameSize ||
              maxFrame > http2MaxMaxFrameSize) {
            _fail(PqTransportError.decodeFailure('http2 max frame'));
            return;
          }
          _peerMaxFrameSize = maxFrame;
        }
        final table = map[http2SettingsHeaderTableSize];
        if (table != null) {
          _encode.setMaxTableSize(table);
        }
        final window = map[http2SettingsInitialWindowSize];
        if (window != null && window > http2MaxWindowSize) {
          _fail(PqTransportError.decodeFailure('http2 window'));
          return;
        }
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
          _fail(PqTransportError.decodeFailure('http2 ping'));
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
        if (frame.payload.length != http2WindowUpdatePayloadBytes) {
          _fail(PqTransportError.decodeFailure('http2 window update'));
          return;
        }
        final inc = readUint32(frame.payload, 0) & http2StreamIdMask;
        if (inc == 0) {
          _fail(PqTransportError.decodeFailure('http2 window increment 0'));
        }
      case http2FramePriority:
        return;
      case http2FramePushPromise:
        _fail(PqTransportError.decodeFailure('http2 push'));
      default:
        _frames.add(frame);
        _wake();
    }
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
    _waiter = done;
    if (pred() || _error != null) {
      if (!done.isCompleted) done.complete();
    }
    try {
      await done.future.timeout(timeout);
    } on TimeoutException {
      return Result.failure(PqTransportError.decodeFailure('http2 timeout'));
    } finally {
      if (identical(_waiter, done)) _waiter = null;
    }
    if (_error != null) return Result.failure(_error!);
    if (!pred()) {
      return Result.failure(PqTransportError.decodeFailure('http2 wait'));
    }
    return const Result.success(null);
  }

  void _wake() {
    final w = _waiter;
    if (w != null && !w.isCompleted) w.complete();
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
