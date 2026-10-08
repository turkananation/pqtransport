import 'dart:convert';
import 'dart:typed_data';

import 'package:swissarmyknife/swissarmyknife.dart';

import '../core/bytes.dart';
import '../core/errors.dart';
import '../core/lengths.dart';
import '../quic/connection.dart';
import '../tls/pq_tls_socket.dart';
import 'http2.dart';
import 'http3.dart';

enum HttpVersion { h1, h2, h3 }

final class PqHttpRequest {
  const PqHttpRequest({
    required this.method,
    required this.uri,
    this.headers = const {},
    this.body = const [],
  });

  final String method;
  final Uri uri;
  final Map<String, String> headers;
  final List<int> body;
}

final class PqHttpResponse {
  const PqHttpResponse({
    required this.status,
    required this.headers,
    required this.body,
    required this.version,
  });

  final int status;
  final Map<String, String> headers;
  final Uint8List body;
  final HttpVersion version;
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
  final text = utf8.decode(wire, allowMalformed: true);
  final split = text.split('\r\n\r\n');
  if (split.length < 2) {
    return Result.failure(PqTransportError.decodeFailure('http1 headers'));
  }
  final lines = split[0].split('\r\n');
  if (lines.isEmpty) {
    return Result.failure(PqTransportError.decodeFailure('http1 status'));
  }
  final statusParts = lines.first.split(' ');
  if (statusParts.length < 2) {
    return Result.failure(PqTransportError.decodeFailure('http1 status line'));
  }
  final status = int.tryParse(statusParts[1]);
  if (status == null) {
    return Result.failure(PqTransportError.decodeFailure('http1 status int'));
  }
  final headers = <String, String>{};
  for (final line in lines.skip(1)) {
    final i = line.indexOf(':');
    if (i <= 0) continue;
    headers[line.substring(0, i).toLowerCase()] = line.substring(i + 1).trim();
  }
  final bodyText = split.sublist(1).join('\r\n\r\n');
  return Result.success(
    PqHttpResponse(
      status: status,
      headers: headers,
      body: Uint8List.fromList(utf8.encode(bodyText)),
      version: HttpVersion.h1,
    ),
  );
}

Uint8List encodeHttp1Response(PqHttpResponse resp) {
  final b = StringBuffer();
  b.write('HTTP/1.1 ${resp.status} OK\r\n');
  resp.headers.forEach((k, v) => b.write('$k: $v\r\n'));
  b.write('Content-Length: ${resp.body.length}\r\n');
  b.write('\r\n');
  return concatBytes([
    Uint8List.fromList(utf8.encode(b.toString())),
    resp.body,
  ]);
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
    final pending = tls.applicationData.first;
    final sent = await tls.send(encodeHttp1Request(request));
    if (sent.isFailure) return Result.failure(sent.errorOrNull!);
    try {
      final raw = await pending.timeout(timeout);
      return decodeHttp1Response(raw);
    } on Object catch (e) {
      return Result.failure(
        PqTransportError.decodeFailure('http1 wait ${e.runtimeType}'),
      );
    }
  }
}
