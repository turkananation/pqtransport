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
  Uint8List body,
) => http2ParseRequest(headers, body);

Result<PqHttpResponse, PqTransportError> http3ParseResponse(
  List<HpackHeader> headers,
  Uint8List body,
) {
  final r = http2ParseResponse(headers, body);
  if (r.isFailure) return r;
  final v = r.valueOrNull!;
  return Result.success(
    PqHttpResponse(
      status: v.status,
      headers: v.headers,
      body: v.body,
      version: HttpVersion.h3,
    ),
  );
}

/// HTTP/3 session over a completed [PqQuicConn] (ALPN `h3`).
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
  final Map<int, int> _uniTypes = {};
  final Map<int, BytesBuilder> _uniBuf = {};
  final Set<int> _accepted = {};
  Completer<void>? _waiter;
  PqTransportError? _error;

  bool get isStarted => _started;

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
    final streamId = conn.openBidi();
    final block = _qpack.encodeFieldSection(http3RequestHeaders(req));
    final frames = BytesBuilder(copy: false);
    frames.add(Http3Frame(type: http3FrameHeaders, payload: block).encode());
    if (req.body.isNotEmpty) {
      frames.add(
        Http3Frame(
          type: http3FrameData,
          payload: Uint8List.fromList(req.body),
        ).encode(),
      );
    }
    final sent = await conn.writeStream(
      streamId,
      frames.takeBytes(),
      fin: true,
    );
    if (sent.isFailure) return Result.failure(sent.errorOrNull!);
    final assembled = await _collect(streamId, timeout);
    if (assembled.isFailure) return Result.failure(assembled.errorOrNull!);
    final (headers, body) = assembled.valueOrNull!;
    return http3ParseResponse(headers, body);
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
      for (final id in conn.streams.peerBidi(clientInitiated: true)) {
        if (_accepted.contains(id)) continue;
        if (!conn.streamHasData(id) && !conn.streamFin(id)) continue;
        final assembled = await _collect(id, timeout);
        if (assembled.isFailure) return Result.failure(assembled.errorOrNull!);
        _accepted.add(id);
        final (headers, body) = assembled.valueOrNull!;
        final req = http3ParseRequest(headers, body);
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
  ) async {
    final block = _qpack.encodeFieldSection(http3ResponseHeaders(resp));
    final frames = BytesBuilder(copy: false);
    frames.add(Http3Frame(type: http3FrameHeaders, payload: block).encode());
    if (resp.body.isNotEmpty) {
      frames.add(Http3Frame(type: http3FrameData, payload: resp.body).encode());
    }
    return conn.writeStream(streamId, frames.takeBytes(), fin: true);
  }

  Future<Result<(List<HpackHeader>, Uint8List), PqTransportError>> _collect(
    int streamId,
    Duration timeout,
  ) async {
    final deadline = DateTime.now().add(timeout);
    final buf = BytesBuilder(copy: false);
    List<HpackHeader>? headers;
    final body = BytesBuilder(copy: false);
    while (DateTime.now().isBefore(deadline)) {
      await _poll();
      buf.add(conn.readStream(streamId));
      final wire = buf.takeBytes();
      var off = 0;
      while (off < wire.length) {
        final one = Http3Frame.tryDecode(slice(wire, off, wire.length));
        if (one.isFailure) break;
        final (frame, n) = one.valueOrNull!;
        off += n;
        if (frame.type == http3FrameHeaders) {
          if (headers != null) {
            return Result.failure(
              PqTransportError.decodeFailure('h3 trailers unsupported'),
            );
          }
          final dec = _qpack.decodeFieldSection(frame.payload);
          if (dec.isFailure) return Result.failure(dec.errorOrNull!);
          headers = dec.valueOrNull!;
          continue;
        }
        if (frame.type == http3FrameData) {
          if (headers == null) {
            return Result.failure(
              PqTransportError.decodeFailure('h3 data before headers'),
            );
          }
          body.add(frame.payload);
          continue;
        }
        if (frame.type == http3FrameSettings ||
            frame.type == http3FrameGoaway ||
            frame.type == http3FrameCancelPush ||
            frame.type == http3FrameMaxPushId) {
          return Result.failure(
            PqTransportError.decodeFailure('h3 frame unexpected'),
          );
        }
      }
      if (off < wire.length) buf.add(slice(wire, off, wire.length));
      if (headers != null && conn.streamFin(streamId) && buf.length == 0) {
        return Result.success((headers, body.takeBytes()));
      }
      if (conn.streamFin(streamId) && !conn.streamHasData(streamId)) {
        return Result.failure(
          PqTransportError.decodeFailure(
            headers == null ? 'h3 no headers' : 'h3 incomplete',
          ),
        );
      }
      await _waitUntil(
        () => conn.streamHasData(streamId) || conn.streamFin(streamId),
        const Duration(milliseconds: 50),
      );
    }
    return Result.failure(PqTransportError.decodeFailure('h3 collect timeout'));
  }

  Future<void> _poll() async {
    for (final id in conn.streams.streams.keys.toList()) {
      if (!quicStreamIsUnidirectional(id)) continue;
      if (id == _controlId || id == _encoderId || id == _decoderId) continue;
      final data = conn.readStream(id);
      if (data.isEmpty) continue;
      await _onUni(id, data);
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
    }
    final rest = slice(wire, off, wire.length);
    if (type == http3StreamTypeControl) {
      final leftover = _onControl(rest);
      if (leftover.isNotEmpty) buf.add(leftover);
      return;
    }
    if (type == http3StreamTypeQpackEncoder) {
      final r = _qpack.ingestEncoderStream(rest);
      if (r.isFailure) {
        buf.add(rest);
        return;
      }
      return;
    }
    if (type == http3StreamTypeQpackDecoder) {
      final r = _qpack.ingestDecoderStream(rest);
      if (r.isFailure) {
        buf.add(rest);
        return;
      }
      return;
    }
  }

  Uint8List _onControl(Uint8List data) {
    var off = 0;
    while (off < data.length) {
      final one = Http3Frame.tryDecode(slice(data, off, data.length));
      if (one.isFailure) {
        return slice(data, off, data.length);
      }
      final (frame, n) = one.valueOrNull!;
      off += n;
      if (!_sawPeerSettings) {
        if (frame.type != http3FrameSettings) {
          _error = PqTransportError.decodeFailure('h3 missing settings');
          _wake();
          return Uint8List(0);
        }
        final s = decodeHttp3Settings(frame.payload);
        if (s.isFailure) {
          _error = s.errorOrNull;
          _wake();
          return Uint8List(0);
        }
        _sawPeerSettings = true;
        _wake();
        continue;
      }
      if (frame.type == http3FrameSettings) {
        _error = PqTransportError.decodeFailure('h3 settings twice');
        _wake();
        return Uint8List(0);
      }
    }
    return Uint8List(0);
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

Uint8List _varintBytes(int v) {
  final b = BytesBuilder(copy: false);
  writeQuicVarint(b, v);
  return b.takeBytes();
}
