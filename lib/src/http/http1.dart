import 'dart:convert';
import 'dart:typed_data';

import 'package:swissarmyknife/swissarmyknife.dart';

import '../core/errors.dart';
import '../core/lengths.dart';
import 'pq_http_client.dart';

/// Registered reason phrases from RFC 9110 §15. Unknown codes use the
/// code itself. The reason phrase is not the status.
String http1ReasonPhrase(int status) {
  return switch (status) {
    100 => 'Continue',
    101 => 'Switching Protocols',
    200 => 'OK',
    201 => 'Created',
    202 => 'Accepted',
    204 => 'No Content',
    301 => 'Moved Permanently',
    302 => 'Found',
    304 => 'Not Modified',
    400 => 'Bad Request',
    401 => 'Unauthorized',
    403 => 'Forbidden',
    404 => 'Not Found',
    405 => 'Method Not Allowed',
    408 => 'Request Timeout',
    411 => 'Length Required',
    413 => 'Content Too Large',
    414 => 'URI Too Long',
    431 => 'Request Header Fields Too Large',
    500 => 'Internal Server Error',
    501 => 'Not Implemented',
    502 => 'Bad Gateway',
    503 => 'Service Unavailable',
    505 => 'HTTP Version Not Supported',
    _ => '$status',
  };
}

/// One parsed HTTP/1.1 message, or a signal that more bytes are required.
final class Http1Parse {
  const Http1Parse.incomplete()
    : incomplete = true,
      consumed = 0,
      close = false,
      request = null,
      response = null;

  const Http1Parse._({
    required this.consumed,
    required this.close,
    this.request,
    this.response,
  }) : incomplete = false;

  final bool incomplete;
  final int consumed;
  final bool close;
  final PqHttpRequest? request;
  final PqHttpResponse? response;
}

/// RFC 9112 request. No Content-Length and no chunked means an empty body.
Result<Http1Parse, PqTransportError> tryParseHttp1Request(Uint8List buf) {
  return _parse(buf, request: true, closed: false);
}

/// RFC 9112 response. Without Content-Length or chunked, the body runs
/// until the connection closes. [closed] takes the bytes already buffered.
Result<Http1Parse, PqTransportError> tryParseHttp1Response(
  Uint8List buf, {
  required bool closed,
}) {
  return _parse(buf, request: false, closed: closed);
}

Result<Http1Parse, PqTransportError> _parse(
  Uint8List buf, {
  required bool request,
  required bool closed,
}) {
  final head = _headerEnd(buf);
  if (head == null) {
    if (buf.length > httpMaxHeaderBytes) {
      return Result.failure(PqTransportError.decodeFailure('http1 headers'));
    }
    return const Result.success(Http1Parse.incomplete());
  }
  if (head < 0) {
    return Result.failure(PqTransportError.decodeFailure('http1 line'));
  }
  final String text;
  try {
    text = utf8.decode(buf.sublist(0, head), allowMalformed: false);
  } on FormatException {
    return Result.failure(PqTransportError.decodeFailure('http1 utf8'));
  }
  final lines = text.split('\r\n');
  // The block ends in CRLF CRLF, so split yields two trailing empty
  // strings. The blank line is the separator, not a field.
  if (lines.length < 3 ||
      lines.last.isNotEmpty ||
      lines[lines.length - 2].isNotEmpty) {
    return Result.failure(PqTransportError.decodeFailure('http1 headers'));
  }
  final start = lines.first;
  final fields = _fields(lines.sublist(1, lines.length - 2));
  if (fields.isFailure) return Result.failure(fields.errorOrNull!);
  final headers = fields.valueOrNull!;
  final framing = _framing(headers);
  if (framing.isFailure) return Result.failure(framing.errorOrNull!);
  final frame = framing.valueOrNull!;
  final bodyEnd = _body(
    buf,
    head,
    frame: frame,
    request: request,
    closed: closed,
  );
  if (bodyEnd.isFailure) return Result.failure(bodyEnd.errorOrNull!);
  final taken = bodyEnd.valueOrNull;
  if (taken == null) return const Result.success(Http1Parse.incomplete());
  final close = _connectionClose(headers);
  if (request) {
    final req = _request(start, headers, taken.body, taken.trailers);
    if (req.isFailure) return Result.failure(req.errorOrNull!);
    return Result.success(
      Http1Parse._(
        consumed: taken.consumed,
        close: close,
        request: req.valueOrNull,
      ),
    );
  }
  final resp = _response(start, headers, taken.body, taken.trailers);
  if (resp.isFailure) return Result.failure(resp.errorOrNull!);
  return Result.success(
    Http1Parse._(
      consumed: taken.consumed,
      close: close,
      response: resp.valueOrNull,
    ),
  );
}

int? _headerEnd(Uint8List buf) {
  for (var i = 0; i + 3 < buf.length; i++) {
    final b = buf[i];
    if (b == 10 && (i == 0 || buf[i - 1] != 13)) return -1;
    if (b == 13 && buf[i + 1] == 10 && buf[i + 2] == 13 && buf[i + 3] == 10) {
      return i + 4;
    }
  }
  if (buf.isNotEmpty &&
      buf.last == 10 &&
      (buf.length == 1 || buf[buf.length - 2] != 13)) {
    return -1;
  }
  return null;
}

Result<Map<String, String>, PqTransportError> _fields(List<String> lines) {
  final headers = <String, String>{};
  final lengths = <String, List<String>>{};
  for (final line in lines) {
    if (line.isEmpty) {
      return Result.failure(PqTransportError.decodeFailure('http1 headers'));
    }
    if (line.startsWith(' ') || line.startsWith('\t')) {
      return Result.failure(PqTransportError.decodeFailure('http1 obs-fold'));
    }
    final i = line.indexOf(':');
    if (i <= 0) {
      return Result.failure(PqTransportError.decodeFailure('http1 header'));
    }
    final name = line.substring(0, i).toLowerCase();
    if (name.contains(' ') || name.contains('\t')) {
      return Result.failure(PqTransportError.decodeFailure('http1 header'));
    }
    final value = line.substring(i + 1).trim();
    if (name == 'content-length') {
      lengths.putIfAbsent(name, () => []).add(value);
    }
    if (name == 'host' && headers.containsKey(name)) {
      return Result.failure(PqTransportError.decodeFailure('http1 host'));
    }
    final previous = headers[name];
    headers[name] = previous == null ? value : '$previous, $value';
  }
  final cl = lengths['content-length'];
  if (cl != null && cl.toSet().length != 1) {
    return Result.failure(PqTransportError.decodeFailure('http1 length'));
  }
  if (cl != null) headers['content-length'] = cl.first;
  return Result.success(headers);
}

final class _Frame {
  const _Frame({this.length, required this.chunked});
  final int? length;
  final bool chunked;
}

Result<_Frame, PqTransportError> _framing(Map<String, String> headers) {
  final te = headers['transfer-encoding'];
  var chunked = false;
  if (te != null) {
    final tokens = [
      for (final part in te.split(',')) part.trim().toLowerCase(),
    ].where((part) => part.isNotEmpty);
    final list = tokens.toList();
    if (list.isEmpty || list.last != 'chunked' || list.length != 1) {
      return Result.failure(
        PqTransportError.decodeFailure('http1 transfer-encoding'),
      );
    }
    chunked = true;
  }
  final raw = headers['content-length'];
  int? length;
  if (raw != null) {
    if (chunked) {
      return Result.failure(PqTransportError.decodeFailure('http1 length'));
    }
    length = int.tryParse(raw);
    if (length == null || length < 0) {
      return Result.failure(PqTransportError.decodeFailure('http1 length'));
    }
  }
  return Result.success(_Frame(length: length, chunked: chunked));
}

final class _Taken {
  const _Taken(this.consumed, this.body, this.trailers);
  final int consumed;
  final Uint8List body;
  final Map<String, String> trailers;
}

Result<_Taken?, PqTransportError> _body(
  Uint8List buf,
  int head, {
  required _Frame frame,
  required bool request,
  required bool closed,
}) {
  if (frame.chunked) return _chunks(buf, head);
  if (frame.length != null) {
    final end = head + frame.length!;
    if (buf.length < end) return const Result.success(null);
    if (frame.length! > _http1MaxBody) {
      return Result.failure(PqTransportError.decodeFailure('http1 body'));
    }
    return Result.success(
      _Taken(end, Uint8List.sublistView(buf, head, end), const {}),
    );
  }
  if (request) {
    return Result.success(_Taken(head, Uint8List(0), const {}));
  }
  if (!closed) return const Result.success(null);
  if (buf.length - head > _http1MaxBody) {
    return Result.failure(PqTransportError.decodeFailure('http1 body'));
  }
  return Result.success(
    _Taken(buf.length, Uint8List.sublistView(buf, head), const {}),
  );
}

Result<_Taken?, PqTransportError> _chunks(Uint8List buf, int offset) {
  final body = BytesBuilder(copy: false);
  var i = offset;
  while (true) {
    final line = _crlf(buf, i);
    if (line == null) return const Result.success(null);
    if (line < 0) {
      return Result.failure(PqTransportError.decodeFailure('http1 chunk'));
    }
    final sizeText = utf8.decode(buf.sublist(i, line)).split(';').first.trim();
    final size = int.tryParse(sizeText, radix: 16);
    if (size == null || size < 0) {
      return Result.failure(PqTransportError.decodeFailure('http1 chunk'));
    }
    i = line + 2;
    if (size == 0) {
      final trailers = _trailer(buf, i);
      if (trailers.isFailure) return Result.failure(trailers.errorOrNull!);
      final taken = trailers.valueOrNull;
      if (taken == null) return const Result.success(null);
      return Result.success(_Taken(taken.$1, body.takeBytes(), taken.$2));
    }
    if (body.length + size > _http1MaxBody) {
      return Result.failure(PqTransportError.decodeFailure('http1 body'));
    }
    if (buf.length < i + size + 2) return const Result.success(null);
    body.add(Uint8List.sublistView(buf, i, i + size));
    if (buf[i + size] != 13 || buf[i + size + 1] != 10) {
      return Result.failure(PqTransportError.decodeFailure('http1 chunk'));
    }
    i += size + 2;
  }
}

Result<(int, Map<String, String>)?, PqTransportError> _trailer(
  Uint8List buf,
  int offset,
) {
  final lines = <String>[];
  var i = offset;
  while (true) {
    final line = _crlf(buf, i);
    if (line == null) return const Result.success(null);
    if (line < 0) {
      return Result.failure(PqTransportError.decodeFailure('http1 trailer'));
    }
    if (line == i) {
      if (lines.isEmpty) return Result.success((i + 2, const {}));
      final fields = _fields(lines);
      if (fields.isFailure) return Result.failure(fields.errorOrNull!);
      return Result.success((i + 2, fields.valueOrNull!));
    }
    lines.add(utf8.decode(buf.sublist(i, line)));
    i = line + 2;
    if (lines.length > 64) {
      return Result.failure(PqTransportError.decodeFailure('http1 trailer'));
    }
  }
}

int? _crlf(Uint8List buf, int offset) {
  for (var i = offset; i + 1 < buf.length; i++) {
    if (buf[i] == 10 && (i == offset || buf[i - 1] != 13)) return -1;
    if (buf[i] == 13 && buf[i + 1] == 10) return i;
  }
  return null;
}

bool _hostField(String host) {
  if (host.isEmpty) return false;
  for (final unit in host.codeUnits) {
    if (unit < 0x21 || unit > 0x7e) return false;
  }
  return true;
}

bool _connectionClose(Map<String, String> headers) {
  final raw = headers['connection'];
  if (raw == null) return false;
  return raw
      .split(',')
      .map((part) => part.trim().toLowerCase())
      .contains('close');
}

Result<PqHttpRequest, PqTransportError> _request(
  String start,
  Map<String, String> headers,
  Uint8List body,
  Map<String, String> trailers,
) {
  final parts = start.split(' ');
  if (parts.length != 3 || !parts[2].startsWith('HTTP/1.')) {
    return Result.failure(PqTransportError.decodeFailure('http1 request'));
  }
  final method = parts[0];
  final target = parts[1];
  if (method.isEmpty || target.isEmpty) {
    return Result.failure(PqTransportError.decodeFailure('http1 request'));
  }
  final host = headers['host'];
  if (host != null && !_hostField(host)) {
    return Result.failure(PqTransportError.decodeFailure('http1 host'));
  }
  if (parts[2] == 'HTTP/1.1' && host == null) {
    return Result.failure(PqTransportError.decodeFailure('http1 host'));
  }
  final Uri uri;
  try {
    if (target.startsWith('/')) {
      uri = Uri.parse('https://${host ?? 'localhost'}$target');
    } else if (target == '*') {
      uri = Uri.parse('https://${host ?? 'localhost'}/*');
    } else {
      uri = Uri.parse(target);
    }
  } on FormatException {
    return Result.failure(PqTransportError.decodeFailure('http1 target'));
  }
  final regular = Map<String, String>.from(headers)..remove('host');
  return Result.success(
    PqHttpRequest(
      method: method,
      uri: uri,
      headers: regular,
      body: body,
      trailers: trailers,
    ),
  );
}

Result<PqHttpResponse, PqTransportError> _response(
  String start,
  Map<String, String> headers,
  Uint8List body,
  Map<String, String> trailers,
) {
  final parts = start.split(' ');
  if (parts.length < 2 || !parts[0].startsWith('HTTP/1.')) {
    return Result.failure(PqTransportError.decodeFailure('http1 status line'));
  }
  final status = int.tryParse(parts[1]);
  if (status == null || status < 100 || status > 599) {
    return Result.failure(PqTransportError.decodeFailure('http1 status int'));
  }
  return Result.success(
    PqHttpResponse(
      status: status,
      headers: headers,
      body: body,
      version: HttpVersion.h1,
      trailers: trailers,
    ),
  );
}

const int _http1MaxBody = 1 << 20;
