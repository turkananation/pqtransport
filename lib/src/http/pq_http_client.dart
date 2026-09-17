import 'dart:convert';
import 'dart:typed_data';

import 'package:swissarmyknife/swissarmyknife.dart';

import '../core/bytes.dart';
import '../core/errors.dart';
import '../core/lengths.dart';
import '../tls/pq_tls_socket.dart';

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

/// HTTP/1.1 request encoder / response parser (ALPN later).
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

final class Http3Frame {
  const Http3Frame({required this.type, required this.payload});
  final int type;
  final Uint8List payload;

  Uint8List encode() {
    final b = BytesBuilder(copy: false);
    b.addByte(type);
    _len(b, payload.length);
    b.add(payload);
    return b.takeBytes();
  }

  static Result<Http3Frame, PqTransportError> decode(Uint8List wire) {
    if (wire.isEmpty) {
      return Result.failure(PqTransportError.decodeFailure('empty h3'));
    }
    final type = wire[0];
    var i = 1;
    if (i >= wire.length) {
      return Result.failure(PqTransportError.decodeFailure('h3 len'));
    }
    final first = wire[i];
    final prefix = first >> 6;
    final lenLen = 1 << prefix;
    if (i + lenLen > wire.length) {
      return Result.failure(PqTransportError.decodeFailure('h3 len'));
    }
    var length = first & 0x3f;
    i++;
    for (var n = 1; n < lenLen; n++) {
      length = (length << 8) | wire[i++];
    }
    if (i + length > wire.length) {
      return Result.failure(PqTransportError.decodeFailure('h3 payload'));
    }
    if (length > httpMaxHeaderBytes && type == http3FrameHeaders) {
      return Result.failure(PqTransportError.decodeFailure('h3 headers huge'));
    }
    return Result.success(
      Http3Frame(type: type, payload: slice(wire, i, i + length)),
    );
  }

  static void _len(BytesBuilder b, int v) {
    if (v < 64) {
      b.addByte(v);
    } else if (v < 16384) {
      writeUint16(b, v | 0x4000);
    } else {
      writeUint32(b, v | 0x80000000);
    }
  }
}

final class PqHttpClient {
  PqHttpClient({this.prefer = HttpVersion.h1, this.allowDowngrade = false});

  final HttpVersion prefer;
  final bool allowDowngrade;

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
    if (prefer == HttpVersion.h3 && !allowDowngrade) {
      // Still serve h1 when the caller explicitly used roundTripH1; refuse
      // silent h3→h1 only on the version-negotiated entry point.
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
