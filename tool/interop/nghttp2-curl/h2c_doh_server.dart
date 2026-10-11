import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:pqtransport/pqtransport.dart';

/// Cleartext HTTP/2 DoH peer for curl --http2-prior-knowledge (libnghttp2).
///
/// Prints `ready <port>` on stdout, then serves [requests] RFC 8484
/// POST or GET exchanges. The DNS answer is A 9.9.9.9, TTL 15, with
/// the query id copied through. This is not a TLS server: curl cannot
/// complete this package's hybrid handshake.
Future<void> main(List<String> args) async {
  final requests = args.isEmpty ? 2 : int.parse(args[0]);
  final trace = Platform.environment['PQ_H2C_TRACE'] == '1';
  final server = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
  stdout.writeln('ready ${server.port}');
  await stdout.flush();
  var left = requests;
  try {
    await for (final socket in server) {
      try {
        await _handle(socket, trace: trace);
      } catch (e, st) {
        stderr.writeln('h2c error: $e\n$st');
        exitCode = 1;
        break;
      }
      left--;
      if (left <= 0) break;
    }
  } finally {
    await server.close();
  }
}

Uint8List answerFor(Uint8List query) {
  final msg = decodeDnsMessage(query);
  if (msg.isFailure) {
    throw StateError('dns ${msg.errorOrNull}');
  }
  final decoded = msg.valueOrNull!;
  return encodeDnsMessage(
    DnsMessage(
      id: decoded.id,
      flags: 0x8180,
      questions: decoded.questions,
      answers: [
        DnsA(
          name: decoded.questions.single.name,
          address: Uint8List.fromList([9, 9, 9, 9]),
          ttl: 15,
        ),
      ],
    ),
  ).valueOrNull!;
}

Future<void> _handle(Socket socket, {required bool trace}) async {
  final acc = _Acc();
  final sub = socket.listen(acc.add, onDone: acc.close, onError: acc.fail);
  final decode = HpackCodec();
  final encode = HpackCodec();
  try {
    final preface = await acc.take(http2PrefaceBytes);
    if (ascii.decode(preface) != http2ConnectionPreface) {
      throw StateError('bad connection preface');
    }
    socket.add(encodeHttp2Settings(http2ServerSettings));
    await socket.flush();

    final headerBlock = BytesBuilder(copy: false);
    final body = BytesBuilder(copy: false);
    var endHeaders = false;
    var endStream = false;
    List<HpackHeader>? headers;
    var streamId = 0;

    while (!endHeaders || !endStream) {
      final header = await acc.take(http2FrameHeaderBytes);
      final length = readUint24(header, 0);
      if (length > http2DefaultMaxFrameSize) {
        throw StateError('frame length $length');
      }
      final payload = length == 0 ? Uint8List(0) : await acc.take(length);
      final frame = Http2Frame(
        type: header[3],
        flags: header[4],
        streamId: readUint32(header, 5) & http2StreamIdMask,
        payload: payload,
      );
      if (trace) {
        stderr.writeln(
          'frame type=${frame.type} flags=${frame.flags} '
          'id=${frame.streamId} len=${payload.length}',
        );
      }
      if (frame.type == http2FrameSettings) {
        if (!frame.ack) {
          final settings = decodeHttp2Settings(frame.payload);
          if (settings.isFailure) throw StateError('${settings.errorOrNull}');
          final table = settings.valueOrNull![http2SettingsHeaderTableSize];
          if (table != null && table < encode.tableSize) {
            encode.setMaxTableSize(table);
          }
          socket.add(encodeHttp2Settings(const {}, ack: true));
          await socket.flush();
        }
      } else if (frame.type == http2FramePing) {
        if (!frame.ack && frame.payload.length == http2PingPayloadBytes) {
          socket.add(
            Http2Frame(
              type: http2FramePing,
              flags: http2FlagAck,
              streamId: 0,
              payload: frame.payload,
            ).encode(),
          );
          await socket.flush();
        }
      } else if (frame.type == http2FrameHeaders ||
          frame.type == http2FrameContinuation) {
        final bare = http2Unpad(
          frame,
          allowPriority: frame.type == http2FrameHeaders,
        );
        if (bare.isFailure) throw StateError('${bare.errorOrNull}');
        headerBlock.add(bare.valueOrNull!);
        streamId = frame.streamId;
        if (frame.endHeaders) {
          endHeaders = true;
          final decoded = decode.decode(headerBlock.takeBytes());
          if (decoded.isFailure) {
            throw StateError('hpack ${decoded.errorOrNull}');
          }
          headers = decoded.valueOrNull;
        }
        if (frame.type == http2FrameHeaders && frame.endStream) {
          endStream = true;
        }
      } else if (frame.type == http2FrameData) {
        final bare = http2Unpad(frame);
        if (bare.isFailure) throw StateError('${bare.errorOrNull}');
        body.add(bare.valueOrNull!);
        if (frame.endStream) endStream = true;
      }
    }

    if (headers == null || streamId == 0) {
      throw StateError('no request headers');
    }
    final req = http2ParseRequest(headers, body.takeBytes());
    if (req.isFailure) throw StateError('${req.errorOrNull}');
    final dns = dohQueryFromRequest(req.valueOrNull!);
    if (dns.isFailure) throw StateError('${dns.errorOrNull}');
    final resp = dohResponse(
      answerFor(dns.valueOrNull!),
      version: HttpVersion.h2,
    );
    socket.add(
      Http2Frame(
        type: http2FrameHeaders,
        flags: http2FlagEndHeaders,
        streamId: streamId,
        payload: encode.encode(http2ResponseHeaders(resp)),
      ).encode(),
    );
    socket.add(
      Http2Frame(
        type: http2FrameData,
        flags: http2FlagEndStream,
        streamId: streamId,
        payload: resp.body,
      ).encode(),
    );
    await socket.flush();
    await acc.settle();
  } finally {
    await sub.cancel();
    await socket.close();
  }
}

final class _Acc {
  final List<int> _buf = [];
  Completer<void>? _wake;
  var _closed = false;
  Object? _error;

  void add(List<int> chunk) {
    _buf.addAll(chunk);
    _pulse();
  }

  void close() {
    _closed = true;
    _pulse();
  }

  void fail(Object error) {
    _error = error;
    _closed = true;
    _pulse();
  }

  void _pulse() {
    final wake = _wake;
    _wake = null;
    if (wake != null && !wake.isCompleted) wake.complete();
  }

  Future<void> settle() async {
    while (!_closed) {
      final n = _buf.length;
      _wake = Completer<void>();
      try {
        await _wake!.future.timeout(const Duration(milliseconds: 200));
      } on TimeoutException {
        if (_buf.length == n) return;
      }
    }
  }

  Future<Uint8List> take(int n) async {
    while (_buf.length < n) {
      if (_error != null) throw StateError('$_error');
      if (_closed) {
        throw StateError('eof want $n have ${_buf.length}');
      }
      _wake = Completer<void>();
      await _wake!.future.timeout(const Duration(seconds: 8));
    }
    final out = Uint8List.fromList(_buf.sublist(0, n));
    _buf.removeRange(0, n);
    return out;
  }
}
