import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'package:swissarmyknife/swissarmyknife.dart';

import '../core/bytes.dart';
import '../core/errors.dart';
import '../core/lengths.dart';
import '../quic/connection.dart';
import '../tls/pq_tls_socket.dart';
import 'http1.dart';
import 'http2.dart';
import 'http3.dart';

enum HttpVersion { h1, h2, h3 }

final class PqHttpRequest {
  const PqHttpRequest({
    required this.method,
    required this.uri,
    this.headers = const {},
    this.body = const [],
    this.trailers = const {},
    this.protocol,
  });

  final String method;
  final Uri uri;
  final Map<String, String> headers;
  final List<int> body;
  final Map<String, String> trailers;

  /// RFC 8441 / RFC 9220 `:protocol` on an extended CONNECT.
  /// Null is an ordinary request, or a classic CONNECT tunnel.
  final String? protocol;
}

final class PqHttpResponse {
  const PqHttpResponse({
    required this.status,
    required this.headers,
    required this.body,
    required this.version,
    this.trailers = const {},
  });

  final int status;
  final Map<String, String> headers;
  final Uint8List body;
  final HttpVersion version;
  final Map<String, String> trailers;
}

/// HTTP/1.1 request encoder / response parser.
Uint8List encodeHttp1Request(PqHttpRequest req) {
  final b = StringBuffer();
  final path = req.uri.hasQuery
      ? '${req.uri.path}?${req.uri.query}'
      : (req.uri.path.isEmpty ? '/' : req.uri.path);
  b.write('${req.method} $path HTTP/1.1\r\n');
  b.write('Host: ${req.uri.host}\r\n');
  req.headers.forEach((k, v) => b.write('$k: $v\r\n'));
  if (req.body.isNotEmpty) {
    b.write('Content-Length: ${req.body.length}\r\n');
  }
  b.write('\r\n');
  return concatBytes([
    Uint8List.fromList(utf8.encode(b.toString())),
    Uint8List.fromList(req.body),
  ]);
}

Result<PqHttpResponse, PqTransportError> decodeHttp1Response(Uint8List wire) {
  final parsed = tryParseHttp1Response(wire, closed: true);
  if (parsed.isFailure) return Result.failure(parsed.errorOrNull!);
  final message = parsed.valueOrNull!;
  if (message.incomplete || message.response == null) {
    return Result.failure(PqTransportError.decodeFailure('http1 headers'));
  }
  return Result.success(message.response!);
}

Uint8List encodeHttp1Response(PqHttpResponse resp) {
  final headers = <String, String>{};
  resp.headers.forEach((key, value) {
    final name = key.toLowerCase();
    if (name == 'content-length' || name == 'transfer-encoding') return;
    headers[name] = value;
  });
  final chunked = resp.headers.entries.any(
    (entry) =>
        entry.key.toLowerCase() == 'transfer-encoding' &&
        entry.value.toLowerCase().split(',').last.trim() == 'chunked',
  );
  final b = BytesBuilder(copy: false);
  void add(String text) => b.add(utf8.encode(text));
  add('HTTP/1.1 ${resp.status} ${http1ReasonPhrase(resp.status)}\r\n');
  headers.forEach((key, value) => add('$key: $value\r\n'));
  if (chunked) {
    add('transfer-encoding: chunked\r\n\r\n');
    add('${resp.body.length.toRadixString(16)}\r\n');
    b.add(resp.body);
    add('\r\n0\r\n');
    resp.trailers.forEach((key, value) => add('$key: $value\r\n'));
    add('\r\n');
    return b.takeBytes();
  }
  add('content-length: ${resp.body.length}\r\n\r\n');
  b.add(resp.body);
  return b.takeBytes();
}

Result<PqHttpRequest, PqTransportError> decodeHttp1Request(Uint8List wire) {
  final parsed = tryParseHttp1Request(wire);
  if (parsed.isFailure) return Result.failure(parsed.errorOrNull!);
  final message = parsed.valueOrNull!;
  if (message.incomplete || message.request == null) {
    return Result.failure(PqTransportError.decodeFailure('http1 request'));
  }
  return Result.success(message.request!);
}

final class PqHttpClient {
  PqHttpClient({this.prefer = HttpVersion.h1, this.allowDowngrade = false});

  final HttpVersion prefer;
  final bool allowDowngrade;
  PqHttp2Session? _h2;
  PqHttp3Session? _h3;

  /// Version-negotiated entry. Uses ALPN; refuses silent h2/h3→h1 unless
  /// [allowDowngrade] is true.
  Future<Result<PqHttpResponse, PqTransportError>> roundTrip({
    required PqTlsSocket tls,
    required PqHttpRequest request,
    Duration timeout = const Duration(seconds: 10),
  }) async {
    if (!tls.isComplete) {
      return Result.failure(
        PqTransportError.handshakeFailure('tls not complete'),
      );
    }
    final alpn = tls.alpn;
    if (alpn == httpAlpnH2) {
      if (prefer == HttpVersion.h3 && !allowDowngrade) {
        return Result.failure(
          PqTransportError.handshakeFailure('h3 not negotiated'),
        );
      }
      return roundTripH2(tls: tls, request: request, timeout: timeout);
    }
    if (alpn == httpAlpnH3) {
      return Result.failure(
        PqTransportError.unsupported(
          'HTTP/3 runs on PqQuicConn; use roundTripH3',
        ),
      );
    }
    if (prefer == HttpVersion.h2 && !allowDowngrade) {
      return Result.failure(
        PqTransportError.handshakeFailure('silent h2 downgrade refused'),
      );
    }
    if (prefer == HttpVersion.h3 && !allowDowngrade) {
      return Result.failure(
        PqTransportError.handshakeFailure('silent h3 downgrade refused'),
      );
    }
    return roundTripH1(tls: tls, request: request, timeout: timeout);
  }

  Future<Result<PqHttpResponse, PqTransportError>> roundTripH2({
    required PqTlsSocket tls,
    required PqHttpRequest request,
    Duration timeout = const Duration(seconds: 10),
  }) async {
    if (!tls.isComplete) {
      return Result.failure(
        PqTransportError.handshakeFailure('tls not complete'),
      );
    }
    if (tls.alpn != httpAlpnH2) {
      return Result.failure(
        PqTransportError.handshakeFailure('alpn is not h2'),
      );
    }
    _h2 ??= PqHttp2Session.client(tls);
    final started = await _h2!.ensureStarted(timeout: timeout);
    if (started.isFailure) return Result.failure(started.errorOrNull!);
    return _h2!.request(request, timeout: timeout);
  }

  Future<Result<PqHttpResponse, PqTransportError>> roundTripH3({
    required PqQuicConn conn,
    required PqHttpRequest request,
    Duration timeout = const Duration(seconds: 10),
  }) async {
    if (!conn.isComplete) {
      return Result.failure(
        PqTransportError.handshakeFailure('quic not complete'),
      );
    }
    if (conn.alpn != httpAlpnH3) {
      return Result.failure(
        PqTransportError.handshakeFailure('alpn is not h3'),
      );
    }
    _h3 ??= PqHttp3Session.client(conn);
    final started = await _h3!.ensureStarted(timeout: timeout);
    if (started.isFailure) return Result.failure(started.errorOrNull!);
    return _h3!.request(request, timeout: timeout);
  }

  Future<Result<PqHttpResponse, PqTransportError>> roundTripH1({
    required PqTlsSocket tls,
    required PqHttpRequest request,
    Duration timeout = const Duration(seconds: 10),
  }) async {
    if (!tls.isComplete) {
      return Result.failure(
        PqTransportError.handshakeFailure('tls not complete'),
      );
    }
    final buf = BytesBuilder(copy: false);
    final done = Completer<Result<PqHttpResponse, PqTransportError>>();
    late final StreamSubscription<Uint8List> sub;
    void consider(Uint8List raw, {required bool closed}) {
      if (done.isCompleted) return;
      final parsed = tryParseHttp1Response(raw, closed: closed);
      if (parsed.isFailure) {
        done.complete(Result.failure(parsed.errorOrNull!));
        return;
      }
      final message = parsed.valueOrNull!;
      if (!message.incomplete && message.response != null) {
        done.complete(Result.success(message.response!));
      } else if (closed) {
        done.complete(
          Result.failure(PqTransportError.decodeFailure('http1 headers')),
        );
      }
    }

    sub = tls.applicationData.listen(
      (chunk) {
        buf.add(chunk);
        consider(buf.toBytes(), closed: false);
      },
      onDone: () => consider(buf.toBytes(), closed: true),
      onError: (Object e) {
        if (!done.isCompleted) {
          done.complete(
            Result.failure(
              PqTransportError.decodeFailure('http1 wait ${e.runtimeType}'),
            ),
          );
        }
      },
    );
    final sent = await tls.send(encodeHttp1Request(request));
    if (sent.isFailure) {
      if (!done.isCompleted) {
        done.complete(Result.failure(sent.errorOrNull!));
      }
      return done.future;
    }
    try {
      return await done.future.timeout(timeout);
    } on TimeoutException {
      return Result.failure(PqTransportError.decodeFailure('http1 wait'));
    } finally {
      await sub.cancel();
    }
  }
}
