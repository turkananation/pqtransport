import 'dart:async';
import 'dart:typed_data';

import 'package:swissarmyknife/swissarmyknife.dart';

import '../core/bytes.dart';
import '../core/errors.dart';
import '../core/lengths.dart';
import '../quic/connection.dart';
import '../quic/packet.dart';
import '../quic/stream.dart';
import 'hpack.dart';
import 'http2.dart';
import 'capsule.dart';
import 'pq_http_client.dart';
import 'qpack.dart';

final class Http3Frame {
  const Http3Frame({required this.type, required this.payload});
  final int type;
  final Uint8List payload;

  Uint8List encode() {
    final b = BytesBuilder(copy: false);
    writeQuicVarint(b, type);
    writeQuicVarint(b, payload.length);
    b.add(payload);
    return b.takeBytes();
  }

  static Result<Http3Frame, PqTransportError> decode(Uint8List wire) {
    final peeled = tryDecode(wire);
    if (peeled.isFailure) return Result.failure(peeled.errorOrNull!);
    return Result.success(peeled.valueOrNull!.$1);
  }

  static Result<(Http3Frame, int), PqTransportError> tryDecode(Uint8List wire) {
    if (wire.isEmpty) {
      return Result.failure(PqTransportError.decodeFailure('empty h3'));
    }
    final r = ByteReader(wire);
    final type = readVarint(r);
    if (type < 0) {
      return Result.failure(PqTransportError.decodeFailure('h3 type'));
    }
    final length = readVarint(r);
    if (length < 0) {
      return Result.failure(PqTransportError.decodeFailure('h3 len'));
    }
    if (r.remaining < length) {
      return Result.failure(PqTransportError.decodeFailure('h3 payload'));
    }
    if (length > httpMaxHeaderBytes && type == http3FrameHeaders) {
      return Result.failure(PqTransportError.decodeFailure('h3 headers huge'));
    }
    final payload = slice(wire, r.offset, r.offset + length);
    return Result.success((
      Http3Frame(type: type, payload: payload),
      r.offset + length,
    ));
  }
}

Uint8List encodeHttp3Settings(Map<int, int> settings) {
  final b = BytesBuilder(copy: false);
  settings.forEach((id, value) {
    writeQuicVarint(b, id);
    writeQuicVarint(b, value);
  });
  return Http3Frame(type: http3FrameSettings, payload: b.takeBytes()).encode();
}

Result<Map<int, int>, PqTransportError> decodeHttp3Settings(Uint8List payload) {
  final r = ByteReader(payload);
  final out = <int, int>{};
  while (r.remaining > 0) {
    final id = readVarint(r);
    final value = readVarint(r);
    if (id < 0 || value < 0) {
      return Result.failure(PqTransportError.decodeFailure('h3 settings'));
    }
    if (out.containsKey(id)) {
      return Result.failure(PqTransportError.decodeFailure('h3 settings dup'));
    }
    out[id] = value;
  }
  return Result.success(out);
}

const Map<int, int> http3ClientSettings = {
  http3SettingsQpackMaxTableCapacity: http3DefaultQpackMaxTableCapacity,
  http3SettingsMaxFieldSectionSize: httpMaxHeaderBytes,
  http3SettingsQpackBlockedStreams: http3DefaultQpackBlockedStreams,
};

const Map<int, int> http3ServerSettings = {
  http3SettingsQpackMaxTableCapacity: http3DefaultQpackMaxTableCapacity,
  http3SettingsMaxFieldSectionSize: httpMaxHeaderBytes,
  http3SettingsQpackBlockedStreams: http3DefaultQpackBlockedStreams,
  http3SettingsEnableConnectProtocol: 1,
};

List<HpackHeader> http3RequestHeaders(PqHttpRequest req) =>
    http2RequestHeaders(req);

List<HpackHeader> http3ResponseHeaders(PqHttpResponse resp) =>
    http2ResponseHeaders(resp);

Result<PqHttpRequest, PqTransportError> http3ParseRequest(
  List<HpackHeader> headers,
  Uint8List body, {
  List<HpackHeader> trailers = const [],
}) {
  final parsed = http2ParseRequest(headers, body);
  if (parsed.isFailure) return parsed;
  final trailerMap = <String, String>{};
  for (final header in trailers) {
    if (header.name.startsWith(':')) {
      return Result.failure(
        PqTransportError.decodeFailure('h3 trailer ${header.name}'),
      );
    }
    trailerMap[header.name] = header.value;
  }
  final req = parsed.valueOrNull!;
  return Result.success(
    PqHttpRequest(
      method: req.method,
      uri: req.uri,
      headers: req.headers,
      body: req.body,
      trailers: trailerMap,
      protocol: req.protocol,
    ),
  );
}

Result<PqHttpResponse, PqTransportError> http3ParseResponse(
  List<HpackHeader> headers,
  Uint8List body, {
  List<HpackHeader> trailers = const [],
}) {
  final parsed = http2ParseResponse(headers, body, trailers: trailers);
  if (parsed.isFailure) return parsed;
  final response = parsed.valueOrNull!;
  return Result.success(
    PqHttpResponse(
      status: response.status,
      headers: response.headers,
      body: response.body,
      version: HttpVersion.h3,
      trailers: response.trailers,
    ),
  );
}

/// HTTP/3 session over a completed [PqQuicConn] (ALPN `h3`).
///
/// One control stream, one QPACK encoder stream, and one QPACK decoder
/// stream. SETTINGS is the first control frame. GOAWAY, MAX_PUSH_ID, and
/// CANCEL_PUSH are acted on after that. Push stays off, so an unpromised
/// CANCEL_PUSH or a PUSH_PROMISE is an error. Not a complete RFC 9114 stack.
final class PqHttp3Session {
  PqHttp3Session._(this.conn, {required this.isClient})
    : _qpack = QpackCodec(maxTableCapacity: http3DefaultQpackMaxTableCapacity);

  factory PqHttp3Session.client(PqQuicConn conn) =>
      PqHttp3Session._(conn, isClient: true);

  factory PqHttp3Session.server(PqQuicConn conn) =>
      PqHttp3Session._(conn, isClient: false);

  final PqQuicConn conn;
  final bool isClient;
  final QpackCodec _qpack;
  var _started = false;
  var _sawPeerSettings = false;
  var _controlId = -1;
  var _encoderId = -1;
  var _decoderId = -1;
  int? _peerControl;
  int? _peerEncoder;
  int? _peerDecoder;
  int? _peerGoawayId;
  int? _sentGoaway;
  int? _maxPushId;
  int? _sentMaxPushId;
  int? _maxFieldSection;
  var _peerTableCapacity = 0;
  var _peerBlockedStreams = 0;
  var _peerConnectProtocol = 0;
  var _peerHttpDatagrams = false;
  var _advertisedHttpDatagrams = false;
  final Map<int, HttpPriority> priorities = {};
  final List<(int, Uint8List)> _httpDatagrams = [];
  final List<(int, HttpCapsule)> _capsules = [];
  final Map<int, BytesBuilder> _capsuleBuf = {};
  final Map<int, BytesBuilder> _capsuleFrames = {};
  final Set<int> _capsuleStreams = {};
  var _dynamicStreams = 0;
  final Set<int> _cancelledPush = {};
  final Map<int, int> _uniTypes = {};
  final Map<int, BytesBuilder> _uniBuf = {};
  final Set<int> _accepted = {};
  final Set<int> _blocked = {};
  Completer<void>? _waiter;
  PqTransportError? _error;

  bool get isStarted => _started;
  int? get peerGoawayId => _peerGoawayId;
  int? get maxPushId => _maxPushId;
  Set<int> get cancelledPushes => Set<int>.unmodifiable(_cancelledPush);
  int get localEncoderStreamId => _encoderId;
  int get localQpackInserts => _qpack.insertCount;
  int get remoteQpackInserts => _qpack.remoteInsertCount;

  bool get peerExtendedConnect => _peerConnectProtocol == 1;

  bool get peerHttpDatagrams => _peerHttpDatagrams;

  Future<Result<void, PqTransportError>> start({
    Duration timeout = const Duration(seconds: 10),
  }) async {
    if (_started) return const Result.success(null);
    _controlId = conn.openUni();
    _encoderId = conn.openUni();
    _decoderId = conn.openUni();
    final settings = Map<int, int>.of(
      isClient ? http3ClientSettings : http3ServerSettings,
    );
    // RFC 9297. Value 1 is legal only after a non-zero QUIC
    // max_datagram_frame_size from the peer. Omitting it means off.
    if (conn.peerMaxDatagramFrameSize > 0) {
      settings[http3SettingsH3Datagram] = 1;
      _advertisedHttpDatagrams = true;
    }
    final typeAndSettings = concatBytes([
      _varintBytes(http3StreamTypeControl),
      encodeHttp3Settings(settings),
    ]);
    final c = await conn.writeStream(_controlId, typeAndSettings);
    if (c.isFailure) return c;
    final enc = await conn.writeStream(
      _encoderId,
      _varintBytes(http3StreamTypeQpackEncoder),
    );
    if (enc.isFailure) return enc;
    final dec = await conn.writeStream(
      _decoderId,
      _varintBytes(http3StreamTypeQpackDecoder),
    );
    if (dec.isFailure) return dec;
    final ready = await _waitUntil(() => _sawPeerSettings, timeout);
    if (ready.isFailure) return ready;
    _started = true;
    return const Result.success(null);
  }

  Future<Result<void, PqTransportError>> ensureStarted({
    Duration timeout = const Duration(seconds: 10),
  }) => start(timeout: timeout);

  /// RFC 9114 §5.2. A later identifier must not be greater.
  Future<Result<void, PqTransportError>> goAway(int id) async {
    if (_error != null) return Result.failure(_error!);
    if (!isClient && id % 4 != 0) {
      return Result.failure(PqTransportError.decodeFailure('h3 goaway id'));
    }
    if (_sentGoaway != null && id > _sentGoaway!) {
      _fail(http3ErrorId, 'h3 goaway increased');
      return Result.failure(_error!);
    }
    _sentGoaway = id;
    return _writeControl(_idFrame(http3FrameGoaway, id));
  }

  /// Client only. RFC 9114 §7.2.7. A smaller value is H3_ID_ERROR.
  Future<Result<void, PqTransportError>> sendMaxPushId(int id) async {
    if (!isClient) {
      return Result.failure(
        PqTransportError.decodeFailure('h3 server max_push_id'),
      );
    }
    if (_sentMaxPushId != null && id < _sentMaxPushId!) {
      return Result.failure(PqTransportError.decodeFailure('h3 max_push_id'));
    }
    _sentMaxPushId = id;
    return _writeControl(_idFrame(http3FrameMaxPushId, id));
  }

  Future<Result<void, PqTransportError>> sendCancelPush(int id) {
    return _writeControl(_idFrame(http3FrameCancelPush, id));
  }

  /// RFC 9114 §4.1.1. RESET_STREAM and STOP_SENDING, both
  /// H3_REQUEST_CANCELLED.
  Future<Result<void, PqTransportError>> cancel(int streamId) async {
    final stop = await conn.stopSending(streamId, http3ErrorRequestCancelled);
    if (stop.isFailure) return stop;
    return conn.resetStream(streamId, http3ErrorRequestCancelled);
  }

  Future<Result<PqHttpResponse, PqTransportError>> request(
    PqHttpRequest req, {
    Duration timeout = const Duration(seconds: 10),
    bool fin = true,
    bool untilFin = true,
  }) async {
    final opened = await beginRequest(req, fin: fin, timeout: timeout);
    if (opened.isFailure) return Result.failure(opened.errorOrNull!);
    return readResponse(
      opened.valueOrNull!,
      untilFin: untilFin,
      timeout: timeout,
    );
  }

  /// Sends the request headers. [fin] is false for an extended CONNECT
  /// tunnel (RFC 9220): the stream stays open after the headers.
  Future<Result<int, PqTransportError>> beginRequest(
    PqHttpRequest req, {
    bool fin = true,
    Duration timeout = const Duration(seconds: 10),
  }) async {
    if (!isClient) {
      return Result.failure(
        PqTransportError.internalError('server cannot request'),
      );
    }
    final started = await ensureStarted(timeout: timeout);
    if (started.isFailure) return Result.failure(started.errorOrNull!);
    if (req.protocol != null && _peerConnectProtocol != 1) {
      return Result.failure(
        PqTransportError.decodeFailure('h3 connect protocol'),
      );
    }
    await _poll();
    if (_error != null) return Result.failure(_error!);
    final streamId = conn.openBidi();
    if (streamId < 0) {
      return Result.failure(PqTransportError.decodeFailure('h3 stream'));
    }
    // RFC 9114 §5.2. A server GOAWAY names the next client-initiated
    // bidirectional stream the server will not accept.
    if (_peerGoawayId != null && streamId >= _peerGoawayId!) {
      await conn.resetStream(streamId, http3ErrorRequestRejected);
      return Result.failure(PqTransportError.closed('h3 goaway'));
    }
    if (_capsuleProtocol(http3RequestHeaders(req))) {
      _capsuleStreams.add(streamId);
    }
    final encoded = await _writeMessage(
      streamId,
      http3RequestHeaders(req),
      req.body,
      req.trailers,
      fin: fin,
    );
    if (encoded.isFailure) return Result.failure(encoded.errorOrNull!);
    return Result.success(streamId);
  }

  /// Reads the response. [untilFin] is false when the stream is a
  /// tunnel and the headers are the whole HTTP message.
  Future<Result<PqHttpResponse, PqTransportError>> readResponse(
    int streamId, {
    bool untilFin = true,
    Duration timeout = const Duration(seconds: 10),
  }) async {
    final assembled = await _collect(streamId, timeout, untilFin: untilFin);
    if (assembled.isFailure) return Result.failure(assembled.errorOrNull!);
    final (headers, body, trailers) = assembled.valueOrNull!;
    return http3ParseResponse(headers, body, trailers: trailers);
  }

  Future<Result<(int, PqHttpRequest), PqTransportError>> accept({
    Duration timeout = const Duration(seconds: 10),
    bool untilFin = true,
  }) async {
    if (isClient) {
      return Result.failure(
        PqTransportError.internalError('client cannot accept'),
      );
    }
    final started = await ensureStarted(timeout: timeout);
    if (started.isFailure) return Result.failure(started.errorOrNull!);
    final deadline = DateTime.now().add(timeout);
    while (DateTime.now().isBefore(deadline)) {
      await _poll();
      if (_error != null) return Result.failure(_error!);
      for (final id in conn.streams.peerBidi(clientInitiated: true)) {
        if (_accepted.contains(id)) continue;
        if (_sentGoaway != null && id >= _sentGoaway!) {
          _accepted.add(id);
          await conn.stopSending(id, http3ErrorRequestRejected);
          await conn.resetStream(id, http3ErrorRequestRejected);
          continue;
        }
        if (conn.streamResetCode(id) != null) {
          _accepted.add(id);
          return Result.failure(PqTransportError.closed('h3 cancelled'));
        }
        if (!conn.streamHasData(id) && !conn.streamFin(id)) continue;
        final assembled = await _collect(id, timeout, untilFin: untilFin);
        if (assembled.isFailure) return Result.failure(assembled.errorOrNull!);
        _accepted.add(id);
        final (headers, body, trailers) = assembled.valueOrNull!;
        final req = http3ParseRequest(headers, body, trailers: trailers);
        if (req.isFailure) return Result.failure(req.errorOrNull!);
        return Result.success((id, req.valueOrNull!));
      }
      final ticked = await _waitUntil(
        () => conn.streams
            .peerBidi(clientInitiated: true)
            .any((id) => !_accepted.contains(id)),
        const Duration(milliseconds: 50),
      );
      if (ticked.isFailure) continue;
    }
    return Result.failure(PqTransportError.decodeFailure('h3 accept timeout'));
  }

  Future<Result<void, PqTransportError>> respond(
    int streamId,
    PqHttpResponse resp, {
    bool fin = true,
  }) {
    return _writeMessage(
      streamId,
      http3ResponseHeaders(resp),
      resp.body,
      resp.trailers,
      fin: fin,
    );
  }

  /// Reads control streams and QUIC DATAGRAM frames without waiting
  /// for a request or a response to finish.
  Future<Result<void, PqTransportError>> receive() async {
    await _poll();
    if (_error != null) return Result.failure(_error!);
    if (!_drainCapsuleStreams()) return Result.failure(_error!);
    return const Result.success(null);
  }

  /// DATA after the headers of a capsule stream. [accept] and
  /// [readResponse] own the stream until they return.
  bool _drainCapsuleStreams() {
    for (final id in _capsuleStreams.toList()) {
      final chunk = conn.readStream(id);
      final held = _capsuleFrames.remove(id);
      if (chunk.isEmpty && (held == null || held.isEmpty)) {
        if (conn.streamFin(id) && (_capsuleBuf[id]?.length ?? 0) > 0) {
          _fail(http3ErrorDatagram, 'h3 capsule');
          return false;
        }
        continue;
      }
      final wire = concatBytes([
        if (held != null && held.isNotEmpty) held.takeBytes(),
        chunk,
      ]);
      var off = 0;
      while (off < wire.length) {
        final one = Http3Frame.tryDecode(slice(wire, off, wire.length));
        if (one.isFailure) break;
        final (frame, n) = one.valueOrNull!;
        if (_requestFrameForbidden(frame.type)) {
          _fail(http3ErrorFrameUnexpected, 'h3 frame ${frame.type}');
          return false;
        }
        if (frame.type == http3FrameData) {
          if (!_feedCapsules(id, frame.payload)) return false;
        }
        off += n;
      }
      if (off < wire.length) {
        _capsuleFrames[id] = BytesBuilder(copy: false)
          ..add(slice(wire, off, wire.length));
      }
      if (conn.streamFin(id) &&
          off == wire.length &&
          (_capsuleBuf[id]?.length ?? 0) > 0) {
        _fail(http3ErrorDatagram, 'h3 capsule');
        return false;
      }
    }
    return _error == null;
  }

  Future<Result<void, PqTransportError>> _writeMessage(
    int streamId,
    List<HpackHeader> headers,
    List<int> body,
    Map<String, String> trailers, {
    required bool fin,
  }) async {
    if (trailers.keys.any((name) => name.startsWith(':'))) {
      return Result.failure(
        PqTransportError.decodeFailure('h3 trailer pseudo'),
      );
    }
    final dynamic =
        _peerTableCapacity > 0 &&
        _peerBlockedStreams > 0 &&
        _dynamicStreams < _peerBlockedStreams;
    final block = _qpack.encodeFieldSection(headers, useDynamic: dynamic);
    if (_qpack.sectionUsesDynamic(block)) _dynamicStreams++;
    final flushed = await _flushQpack();
    if (flushed.isFailure) return flushed;
    final frames = BytesBuilder(copy: false);
    frames.add(Http3Frame(type: http3FrameHeaders, payload: block).encode());
    if (body.isNotEmpty) {
      frames.add(
        Http3Frame(
          type: http3FrameData,
          payload: Uint8List.fromList(body),
        ).encode(),
      );
    }
    final end = fin && trailers.isEmpty;
    final sent = await conn.writeStream(streamId, frames.takeBytes(), fin: end);
    if (sent.isFailure) return sent;
    if (trailers.isEmpty) return const Result.success(null);
    final trailerBlock = _qpack.encodeFieldSection([
      for (final entry in trailers.entries)
        HpackHeader(entry.key.toLowerCase(), entry.value),
    ]);
    final trailerFlush = await _flushQpack();
    if (trailerFlush.isFailure) return trailerFlush;
    return conn.writeStream(
      streamId,
      Http3Frame(type: http3FrameHeaders, payload: trailerBlock).encode(),
      fin: fin,
    );
  }

  Future<
    Result<(List<HpackHeader>, Uint8List, List<HpackHeader>), PqTransportError>
  >
  _collect(int streamId, Duration timeout, {bool untilFin = true}) async {
    final deadline = DateTime.now().add(timeout);
    final buf = BytesBuilder(copy: false);
    List<HpackHeader>? headers;
    List<HpackHeader>? trailers;
    final body = BytesBuilder(copy: false);
    while (DateTime.now().isBefore(deadline)) {
      await _poll();
      if (_error != null) return Result.failure(_error!);
      final reset = conn.streamResetCode(streamId);
      if (reset != null && headers == null) {
        return Result.failure(PqTransportError.closed('h3 cancelled'));
      }
      buf.add(conn.readStream(streamId));
      final wire = buf.takeBytes();
      var off = 0;
      var blocked = false;
      while (off < wire.length) {
        final one = Http3Frame.tryDecode(slice(wire, off, wire.length));
        if (one.isFailure) break;
        final (frame, n) = one.valueOrNull!;
        if (_requestFrameForbidden(frame.type)) {
          _fail(http3ErrorFrameUnexpected, 'h3 frame ${frame.type}');
          return Result.failure(_error!);
        }
        if (frame.type != http3FrameHeaders && frame.type != http3FrameData) {
          off += n;
          continue;
        }
        if (frame.type == http3FrameHeaders) {
          if (_qpack.sectionBlocked(frame.payload)) {
            if (_blocked.add(streamId) &&
                _blocked.length > http3DefaultQpackBlockedStreams) {
              _fail(qpackErrorDecompressionFailed, 'qpack blocked');
              return Result.failure(_error!);
            }
            blocked = true;
            break;
          }
          _blocked.remove(streamId);
          final dec = _qpack.decodeFieldSection(frame.payload);
          if (dec.isFailure) return Result.failure(dec.errorOrNull!);
          final section = dec.valueOrNull!;
          if (_fieldSectionTooLarge(section)) {
            _fail(http3ErrorExcessiveLoad, 'h3 field section');
            return Result.failure(_error!);
          }
          if (_qpack.sectionUsesDynamic(frame.payload)) {
            _qpack.ackSection(streamId);
            final ack = await _flushQpack();
            if (ack.isFailure) return Result.failure(ack.errorOrNull!);
          }
          off += n;
          if (headers == null) {
            headers = section;
            if (_capsuleProtocol(section)) _capsuleStreams.add(streamId);
            continue;
          }
          if (trailers == null) {
            trailers = section;
            continue;
          }
          _fail(http3ErrorFrameUnexpected, 'h3 extra headers');
          return Result.failure(_error!);
        }
        if (headers == null || trailers != null) {
          _fail(http3ErrorFrameUnexpected, 'h3 data');
          return Result.failure(_error!);
        }
        if (_capsuleStreams.contains(streamId)) {
          final fed = _feedCapsules(streamId, frame.payload);
          if (!fed) return Result.failure(_error!);
        } else {
          body.add(frame.payload);
        }
        off += n;
      }
      if (off < wire.length) buf.add(slice(wire, off, wire.length));
      if (_capsuleStreams.contains(streamId) &&
          conn.streamFin(streamId) &&
          (_capsuleBuf[streamId]?.length ?? 0) > 0) {
        _fail(http3ErrorDatagram, 'h3 capsule');
        return Result.failure(_error!);
      }
      if (!blocked &&
          !untilFin &&
          headers != null &&
          buf.length == 0 &&
          !conn.streamHasData(streamId)) {
        return Result.success((
          headers,
          body.takeBytes(),
          trailers ?? const [],
        ));
      }
      if (!blocked &&
          headers != null &&
          conn.streamFin(streamId) &&
          buf.length == 0) {
        return Result.success((
          headers,
          body.takeBytes(),
          trailers ?? const [],
        ));
      }
      if (!blocked &&
          conn.streamFin(streamId) &&
          !conn.streamHasData(streamId) &&
          buf.length == 0) {
        return Result.failure(
          PqTransportError.decodeFailure(
            headers == null ? 'h3 no headers' : 'h3 incomplete',
          ),
        );
      }
      await _waitUntil(
        () =>
            conn.streamHasData(streamId) ||
            conn.streamFin(streamId) ||
            conn.streamResetCode(streamId) != null ||
            _error != null,
        const Duration(milliseconds: 20),
      );
    }
    return Result.failure(PqTransportError.decodeFailure('h3 collect timeout'));
  }

  bool _requestFrameForbidden(int type) {
    if (type == http3FrameSettings ||
        type == http3FrameGoaway ||
        type == http3FrameCancelPush ||
        type == http3FrameMaxPushId ||
        type == http3FramePushPromise ||
        type == http3FramePriorityUpdate ||
        type == http3FramePriorityUpdatePush ||
        type == 0x02 ||
        type == 0x06 ||
        type == 0x08 ||
        type == 0x09) {
      return true;
    }
    return false;
  }

  bool _fieldSectionTooLarge(List<HpackHeader> headers) {
    final limit = _maxFieldSection;
    if (limit == null) return false;
    var size = 0;
    for (final header in headers) {
      size += header.name.length + header.value.length;
    }
    return size > limit;
  }

  Future<Result<void, PqTransportError>> _flushQpack() async {
    final enc = _qpack.takeEncoderStream();
    if (enc.isNotEmpty) {
      final wrote = await conn.writeStream(_encoderId, enc);
      if (wrote.isFailure) return wrote;
    }
    final dec = _qpack.takeDecoderStream();
    if (dec.isNotEmpty) {
      final wrote = await conn.writeStream(_decoderId, dec);
      if (wrote.isFailure) return wrote;
    }
    return const Result.success(null);
  }

  Future<Result<void, PqTransportError>> _writeControl(Uint8List frame) async {
    final started = await ensureStarted();
    if (started.isFailure) return started;
    return conn.writeStream(_controlId, frame);
  }

  Future<void> _poll() async {
    _takeQuicDatagrams();
    for (final id in conn.streams.streams.keys.toList()) {
      if (!quicStreamIsUnidirectional(id)) continue;
      if (id == _controlId || id == _encoderId || id == _decoderId) continue;
      final data = conn.readStream(id);
      if (data.isEmpty && !conn.streamFin(id)) continue;
      if (data.isNotEmpty) await _onUni(id, data);
      _noteCriticalFin(id);
    }
  }

  Future<void> _onUni(int id, Uint8List data) async {
    final buf = _uniBuf.putIfAbsent(id, () => BytesBuilder(copy: false));
    buf.add(data);
    final wire = buf.takeBytes();
    var type = _uniTypes[id];
    var off = 0;
    if (type == null) {
      final r = ByteReader(wire);
      final t = readVarint(r);
      if (t < 0) {
        buf.add(wire);
        return;
      }
      type = t;
      _uniTypes[id] = t;
      off = r.offset;
      if (!_claimUni(id, t)) return;
    }
    if (type != http3StreamTypeControl &&
        type != http3StreamTypeQpackEncoder &&
        type != http3StreamTypeQpackDecoder) {
      return;
    }
    final rest = slice(wire, off, wire.length);
    if (type == http3StreamTypeControl) {
      final leftover = _onControl(rest);
      if (leftover.isNotEmpty) buf.add(leftover);
      return;
    }
    final ingested = type == http3StreamTypeQpackEncoder
        ? _qpack.ingestEncoderStream(rest)
        : _qpack.ingestDecoderStream(rest);
    if (ingested.isFailure) {
      _fail(
        type == http3StreamTypeQpackEncoder
            ? qpackErrorEncoderStream
            : qpackErrorDecoderStream,
        ingested.errorOrNull!.message,
      );
      return;
    }
    final consumed = ingested.valueOrNull!;
    if (consumed < rest.length) buf.add(slice(rest, consumed, rest.length));
  }

  bool _claimUni(int id, int type) {
    if (type == http3StreamTypeControl) {
      if (_peerControl != null) {
        _fail(http3ErrorStreamCreation, 'h3 second control');
        return false;
      }
      _peerControl = id;
      return true;
    }
    if (type == http3StreamTypeQpackEncoder) {
      if (_peerEncoder != null) {
        _fail(http3ErrorStreamCreation, 'h3 second encoder');
        return false;
      }
      _peerEncoder = id;
      return true;
    }
    if (type == http3StreamTypeQpackDecoder) {
      if (_peerDecoder != null) {
        _fail(http3ErrorStreamCreation, 'h3 second decoder');
        return false;
      }
      _peerDecoder = id;
      return true;
    }
    if (type == http3StreamTypePush) {
      _fail(
        isClient ? http3ErrorId : http3ErrorStreamCreation,
        'h3 push stream',
      );
      return false;
    }
    return true;
  }

  void _noteCriticalFin(int id) {
    if (!conn.streamFin(id)) return;
    final type = _uniTypes[id];
    if (type == null) return;
    final pending = _uniBuf[id];
    final leftover = pending == null || pending.isEmpty;
    if (type == http3StreamTypeControl) {
      _fail(
        leftover ? http3ErrorClosedCriticalStream : http3ErrorFrame,
        'h3 control closed',
      );
    } else if (type == http3StreamTypeQpackEncoder) {
      _fail(qpackErrorEncoderStream, 'h3 encoder closed');
    } else if (type == http3StreamTypeQpackDecoder) {
      _fail(qpackErrorDecoderStream, 'h3 decoder closed');
    }
  }

  Uint8List _onControl(Uint8List data) {
    var off = 0;
    while (off < data.length) {
      final one = Http3Frame.tryDecode(slice(data, off, data.length));
      if (one.isFailure) return slice(data, off, data.length);
      final (frame, n) = one.valueOrNull!;
      off += n;
      if (!_sawPeerSettings) {
        if (frame.type != http3FrameSettings) {
          _fail(http3ErrorMissingSettings, 'h3 missing settings');
          return Uint8List(0);
        }
        if (!_takeSettings(frame.payload)) return Uint8List(0);
        continue;
      }
      if (!_controlFrame(frame)) return Uint8List(0);
    }
    return Uint8List(0);
  }

  bool _takeSettings(Uint8List payload) {
    final decoded = decodeHttp3Settings(payload);
    if (decoded.isFailure) {
      _fail(http3ErrorSettings, 'h3 settings');
      return false;
    }
    final settings = decoded.valueOrNull!;
    for (final id in const [0x02, 0x03, 0x04, 0x05]) {
      if (settings.containsKey(id)) {
        _fail(http3ErrorSettings, 'h3 http2 setting');
        return false;
      }
    }
    _peerTableCapacity = settings[http3SettingsQpackMaxTableCapacity] ?? 0;
    _peerBlockedStreams = settings[http3SettingsQpackBlockedStreams] ?? 0;
    final connect = settings[http3SettingsEnableConnectProtocol];
    if (connect != null) {
      if (connect != 0 && connect != 1) {
        _fail(http3ErrorSettings, 'h3 connect protocol');
        return false;
      }
      if (!isClient) {
        _fail(http3ErrorSettings, 'h3 connect protocol');
        return false;
      }
      if (_peerConnectProtocol == 1 && connect == 0) {
        _fail(http3ErrorSettings, 'h3 connect protocol');
        return false;
      }
      _peerConnectProtocol = connect;
    }
    final datagrams = settings[http3SettingsH3Datagram];
    if (datagrams != null) {
      if (datagrams != 0 && datagrams != 1) {
        _fail(http3ErrorSettings, 'h3 datagram');
        return false;
      }
      if (datagrams == 1 && conn.peerMaxDatagramFrameSize <= 0) {
        _fail(http3ErrorSettings, 'h3 datagram');
        return false;
      }
      _peerHttpDatagrams = datagrams == 1;
    }
    _maxFieldSection = settings[http3SettingsMaxFieldSectionSize];
    _qpack.applyPeerLimits(
      maxTableCapacity: _peerTableCapacity,
      blockedStreams: _peerBlockedStreams,
    );
    _sawPeerSettings = true;
    _wake();
    return true;
  }

  /// RFC 9297. The quarter stream id is the client-initiated bidirectional
  /// stream id divided by four.
  Future<Result<void, PqTransportError>> sendHttpDatagram(
    int streamId,
    Uint8List payload,
  ) {
    if (!_advertisedHttpDatagrams ||
        !_peerHttpDatagrams ||
        streamId < 0 ||
        streamId % 4 != 0 ||
        conn.streams.streams[streamId] == null) {
      return Future.value(
        Result.failure(PqTransportError.decodeFailure('h3 datagram')),
      );
    }
    final body = BytesBuilder(copy: false);
    writeQuicVarint(body, streamId >> 2);
    body.add(payload);
    return conn.sendDatagram(body.takeBytes());
  }

  List<(int streamId, Uint8List payload)> takeHttpDatagrams() {
    _takeQuicDatagrams();
    final out = List<(int, Uint8List)>.of(_httpDatagrams);
    _httpDatagrams.clear();
    return out;
  }

  /// Capsules other than DATAGRAM on one request stream.
  List<HttpCapsule> takeCapsules(int streamId) {
    final keep = <(int, HttpCapsule)>[];
    final out = <HttpCapsule>[];
    for (final item in _capsules) {
      if (item.$1 == streamId) {
        out.add(item.$2);
      } else {
        keep.add(item);
      }
    }
    _capsules
      ..clear()
      ..addAll(keep);
    return out;
  }

  /// Datagrams for one request stream. Others stay queued.
  List<Uint8List> takeStreamDatagrams(int streamId) {
    _takeQuicDatagrams();
    final keep = <(int, Uint8List)>[];
    final out = <Uint8List>[];
    for (final item in _httpDatagrams) {
      if (item.$1 == streamId) {
        out.add(item.$2);
      } else {
        keep.add(item);
      }
    }
    _httpDatagrams
      ..clear()
      ..addAll(keep);
    return out;
  }

  bool get quicHttpDatagrams =>
      _advertisedHttpDatagrams &&
      _peerHttpDatagrams &&
      conn.peerMaxDatagramFrameSize > 0;

  /// RFC 9297 §3.2. One capsule as a DATA frame on the request stream.
  Future<Result<void, PqTransportError>> sendCapsule(
    int streamId,
    HttpCapsule capsule,
  ) {
    if (streamId < 0 || streamId % 4 != 0) {
      return Future.value(
        Result.failure(PqTransportError.decodeFailure('h3 capsule')),
      );
    }
    return conn.writeStream(
      streamId,
      Http3Frame(type: http3FrameData, payload: capsule.encode()).encode(),
    );
  }

  /// RFC 9297 §3.5. One DATAGRAM capsule on the request stream.
  /// Legal when HTTP datagrams were negotiated, including when the
  /// QUIC DATAGRAM transport parameter is zero.
  Future<Result<void, PqTransportError>> sendDatagramCapsule(
    int streamId,
    Uint8List payload,
  ) {
    if (!_peerHttpDatagrams || streamId < 0 || streamId % 4 != 0) {
      return Future.value(
        Result.failure(PqTransportError.decodeFailure('h3 capsule')),
      );
    }
    final frame = Http3Frame(
      type: http3FrameData,
      payload: HttpCapsule(type: HttpCapsule.datagram, value: payload).encode(),
    );
    return conn.writeStream(streamId, frame.encode());
  }

  bool _capsuleProtocol(List<HpackHeader> headers) {
    for (final header in headers) {
      if (header.name.toLowerCase() == 'capsule-protocol' &&
          header.value.trim() == '?1') {
        return true;
      }
    }
    return false;
  }

  bool _feedCapsules(int streamId, Uint8List data) {
    final held = _capsuleBuf.remove(streamId);
    final wire = concatBytes([
      if (held != null && held.isNotEmpty) held.takeBytes(),
      data,
    ]);
    var off = 0;
    while (off < wire.length) {
      final one = tryDecodeHttpCapsule(slice(wire, off, wire.length));
      if (one == null) break;
      off += one.consumed;
      // RFC 9297 §3.3. An unknown type is skipped by the datagram
      // mapping and kept for the application. CONNECT-IP uses that.
      if (one.capsule.type == HttpCapsule.datagram) {
        if (!_peerHttpDatagrams || !_advertisedHttpDatagrams) {
          _fail(http3ErrorDatagram, 'h3 capsule');
          return false;
        }
        _httpDatagrams.add((streamId, one.capsule.value));
      } else {
        _capsules.add((streamId, one.capsule));
      }
    }
    if (off < wire.length) {
      _capsuleBuf[streamId] = BytesBuilder(copy: false)
        ..add(slice(wire, off, wire.length));
    }
    return true;
  }

  /// RFC 9218 §7.2. Clients only. Sent on the control stream.
  Future<Result<void, PqTransportError>> updatePriority(
    int streamId, {
    int urgency = 3,
    bool incremental = false,
  }) {
    if (!isClient || streamId < 0 || streamId % 4 != 0) {
      return Future.value(
        Result.failure(PqTransportError.decodeFailure('h3 priority update')),
      );
    }
    final field = encodeHttpPriorityField(
      urgency: urgency,
      incremental: incremental,
    );
    final payload = BytesBuilder(copy: false);
    writeQuicVarint(payload, streamId);
    payload.add(Uint8List.fromList(field.codeUnits));
    return _writeControl(
      Http3Frame(
        type: http3FramePriorityUpdate,
        payload: payload.takeBytes(),
      ).encode(),
    );
  }

  bool _takePriority(Uint8List payload, {required bool push}) {
    if (isClient) {
      _fail(http3ErrorFrameUnexpected, 'h3 priority update');
      return false;
    }
    final reader = ByteReader(payload);
    final id = readVarint(reader);
    if (id < 0) {
      _fail(http3ErrorFrame, 'h3 priority update');
      return false;
    }
    // Push is off. A push id has not been promised.
    if (push || id % 4 != 0 || conn.streamBeyondLocalLimit(id)) {
      _fail(http3ErrorId, 'h3 priority update');
      return false;
    }
    final raw = slice(payload, reader.offset, payload.length);
    if (!httpPriorityText(raw)) {
      _fail(http3ErrorGeneralProtocol, 'h3 priority update');
      return false;
    }
    priorities[id] = parseHttpPriority(String.fromCharCodes(raw));
    return true;
  }

  void _takeQuicDatagrams() {
    for (final payload in conn.takeDatagrams()) {
      final reader = ByteReader(payload);
      final quarter = readVarint(reader);
      if (quarter < 0) continue;
      final id = quarter * 4;
      if (conn.streamBeyondLocalLimit(id)) {
        _fail(http3ErrorId, 'h3 datagram');
        return;
      }
      if (conn.streamFin(id) || conn.streamResetCode(id) != null) continue;
      _httpDatagrams.add((id, slice(payload, reader.offset, payload.length)));
    }
  }

  bool _controlFrame(Http3Frame frame) {
    if (frame.type == http3FrameSettings ||
        frame.type == http3FrameData ||
        frame.type == http3FrameHeaders ||
        frame.type == http3FramePushPromise ||
        frame.type == 0x02 ||
        frame.type == 0x06 ||
        frame.type == 0x08 ||
        frame.type == 0x09) {
      _fail(http3ErrorFrameUnexpected, 'h3 control ${frame.type}');
      return false;
    }
    if (frame.type == http3FrameGoaway) return _takeGoaway(frame.payload);
    if (frame.type == http3FrameMaxPushId) return _takeMaxPushId(frame.payload);
    if (frame.type == http3FrameCancelPush) {
      return _takeCancelPush(frame.payload);
    }
    if (frame.type == http3FramePriorityUpdate) {
      return _takePriority(frame.payload, push: false);
    }
    if (frame.type == http3FramePriorityUpdatePush) {
      return _takePriority(frame.payload, push: true);
    }
    // RFC 9114 §9. Unknown frame types are ignored. HTTP/2 frame
    // types reserved by §7.2.8 were already rejected above.
    return true;
  }

  bool _takeGoaway(Uint8List payload) {
    final id = _onlyVarint(payload);
    if (id == null) {
      _fail(http3ErrorFrame, 'h3 goaway');
      return false;
    }
    if (!isClient && _maxPushId != null && id > _maxPushId!) {
      _fail(http3ErrorId, 'h3 goaway push');
      return false;
    }
    if (isClient && id % 4 != 0) {
      _fail(http3ErrorId, 'h3 goaway stream');
      return false;
    }
    if (_peerGoawayId != null && id > _peerGoawayId!) {
      _fail(http3ErrorId, 'h3 goaway increased');
      return false;
    }
    _peerGoawayId = id;
    _wake();
    return true;
  }

  bool _takeMaxPushId(Uint8List payload) {
    if (isClient) {
      _fail(http3ErrorFrameUnexpected, 'h3 max_push_id');
      return false;
    }
    final id = _onlyVarint(payload);
    if (id == null) {
      _fail(http3ErrorFrame, 'h3 max_push_id');
      return false;
    }
    if (_maxPushId != null && id < _maxPushId!) {
      _fail(http3ErrorId, 'h3 max_push_id');
      return false;
    }
    _maxPushId = id;
    _wake();
    return true;
  }

  bool _takeCancelPush(Uint8List payload) {
    final id = _onlyVarint(payload);
    if (id == null) {
      _fail(http3ErrorFrame, 'h3 cancel_push');
      return false;
    }
    final allowed = isClient ? _sentMaxPushId : _maxPushId;
    if (allowed == null || id > allowed) {
      _fail(http3ErrorId, 'h3 cancel_push');
      return false;
    }
    // Push is off. No PUSH_PROMISE has named this id (RFC 9114 §7.2.3).
    _fail(http3ErrorId, 'h3 cancel_push unpromised');
    return false;
  }

  void _fail(int code, String why) {
    if (_error != null) return;
    _error = PqTransportError.decodeFailure(why);
    _wake();
    unawaited(conn.close(errorCode: code, application: true));
  }

  Future<Result<void, PqTransportError>> _waitUntil(
    bool Function() pred,
    Duration timeout,
  ) async {
    final deadline = DateTime.now().add(timeout);
    while (!pred()) {
      if (_error != null) return Result.failure(_error!);
      if (DateTime.now().isAfter(deadline)) {
        return Result.failure(PqTransportError.decodeFailure('h3 wait'));
      }
      await _poll();
      if (pred()) return const Result.success(null);
      final c = Completer<void>();
      _waiter = c;
      if (pred() || _error != null) {
        _wake();
        continue;
      }
      try {
        await c.future.timeout(const Duration(milliseconds: 20));
      } on TimeoutException {
        _wake();
      }
    }
    return const Result.success(null);
  }

  void _wake() {
    final w = _waiter;
    _waiter = null;
    if (w != null && !w.isCompleted) w.complete();
  }
}

Uint8List _varintBytes(int value) {
  final b = BytesBuilder(copy: false);
  writeQuicVarint(b, value);
  return b.takeBytes();
}

Uint8List _idFrame(int type, int id) {
  final payload = BytesBuilder(copy: false);
  writeQuicVarint(payload, id);
  return Http3Frame(type: type, payload: payload.takeBytes()).encode();
}

int? _onlyVarint(Uint8List payload) {
  final reader = ByteReader(payload);
  final value = readVarint(reader);
  if (value < 0 || reader.remaining != 0) return null;
  return value;
}
