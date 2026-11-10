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

const Map<int, int> http3ServerSettings = http3ClientSettings;

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

  Future<Result<void, PqTransportError>> start({
    Duration timeout = const Duration(seconds: 10),
  }) async {
    if (_started) return const Result.success(null);
    _controlId = conn.openUni();
    _encoderId = conn.openUni();
    _decoderId = conn.openUni();
    final typeAndSettings = concatBytes([
      _varintBytes(http3StreamTypeControl),
      encodeHttp3Settings(http3ClientSettings),
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
  }) async {
    if (!isClient) {
      return Result.failure(
        PqTransportError.internalError('server cannot request'),
      );
    }
    final started = await ensureStarted(timeout: timeout);
    if (started.isFailure) return Result.failure(started.errorOrNull!);
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
    final encoded = await _writeMessage(
      streamId,
      http3RequestHeaders(req),
      req.body,
      req.trailers,
      fin: true,
    );
    if (encoded.isFailure) return Result.failure(encoded.errorOrNull!);
    final assembled = await _collect(streamId, timeout);
    if (assembled.isFailure) return Result.failure(assembled.errorOrNull!);
    final (headers, body, trailers) = assembled.valueOrNull!;
    return http3ParseResponse(headers, body, trailers: trailers);
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
        final assembled = await _collect(id, timeout);
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
    PqHttpResponse resp,
  ) {
    return _writeMessage(
      streamId,
      http3ResponseHeaders(resp),
      resp.body,
      resp.trailers,
      fin: true,
    );
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
  _collect(int streamId, Duration timeout) async {
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
        body.add(frame.payload);
        off += n;
      }
      if (off < wire.length) buf.add(slice(wire, off, wire.length));
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
    _maxFieldSection = settings[http3SettingsMaxFieldSectionSize];
    _qpack.applyPeerLimits(
      maxTableCapacity: _peerTableCapacity,
      blockedStreams: _peerBlockedStreams,
    );
    _sawPeerSettings = true;
    _wake();
    return true;
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
