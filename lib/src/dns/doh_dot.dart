import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'package:swissarmyknife/swissarmyknife.dart';

import '../core/bytes.dart';
import '../core/errors.dart';
import '../core/lengths.dart';
import '../http/pq_http_client.dart';
import '../quic/connection.dart';
import '../tls/pq_tls_socket.dart';

/// RFC 8484 base64url (RFC 4648 §5) with padding stripped.
String dohBase64Url(Uint8List message) {
  final encoded = base64Url.encode(message);
  final pad = encoded.indexOf('=');
  return pad < 0 ? encoded : encoded.substring(0, pad);
}

/// Decode an unpadded base64url DNS query parameter. Padding and the
/// standard base64 alphabet fail closed.
Result<Uint8List, PqTransportError> dohBase64UrlDecode(String text) {
  if (text.isEmpty ||
      text.contains('=') ||
      text.contains('+') ||
      text.contains('/') ||
      !RegExp(r'^[A-Za-z0-9_-]+$').hasMatch(text)) {
    return Result.failure(PqTransportError.decodeFailure('doh base64url'));
  }
  final rem = text.length % 4;
  if (rem == 1) {
    return Result.failure(PqTransportError.decodeFailure('doh base64url'));
  }
  final padded = rem == 0 ? text : text + ('=' * (4 - rem));
  try {
    return Result.success(base64Url.decode(padded));
  } on FormatException {
    return Result.failure(PqTransportError.decodeFailure('doh base64url'));
  }
}

/// RFC 8484 URI template. Accepts an absolute URI, or that URI plus a
/// single trailing `{?dns}` expression. Anything else fails closed.
final class DohUriTemplate {
  DohUriTemplate._(this.postUri);

  /// Target for POST (the template with `{?dns}` removed).
  final Uri postUri;

  static Result<DohUriTemplate, PqTransportError> parse(String template) {
    if (template.isEmpty) {
      return Result.failure(PqTransportError.decodeFailure('doh template'));
    }
    var base = template;
    if (template.contains('{')) {
      if ('{'.allMatches(template).length != 1 ||
          !template.endsWith(dohTemplateQuery)) {
        return Result.failure(PqTransportError.decodeFailure('doh template'));
      }
      base = template.substring(0, template.length - dohTemplateQuery.length);
    }
    final uri = Uri.tryParse(base);
    if (uri == null || !uri.hasScheme || uri.host.isEmpty) {
      return Result.failure(PqTransportError.decodeFailure('doh template'));
    }
    return Result.success(DohUriTemplate._(uri));
  }

  /// GET target. `dns` is unpadded base64url of the DNS message.
  Uri getUri(Uint8List message) {
    final params = Map<String, String>.from(postUri.queryParameters);
    params['dns'] = dohBase64Url(message);
    return postUri.replace(queryParameters: params);
  }
}

String? _mediaType(String? header) {
  if (header == null) return null;
  final semi = header.indexOf(';');
  final raw = (semi < 0 ? header : header.substring(0, semi)).trim();
  return raw.toLowerCase();
}

/// Pull the DNS message out of an RFC 8484 request.
/// POST requires `content-type: application/dns-message` and a body.
/// GET requires an unpadded `dns` query parameter.
Result<Uint8List, PqTransportError> dohQueryFromRequest(PqHttpRequest req) {
  final method = req.method.toUpperCase();
  if (method == 'POST') {
    if (_mediaType(req.headers['content-type']) != dnsMessageMediaType) {
      return Result.failure(PqTransportError.decodeFailure('doh content-type'));
    }
    if (req.body.isEmpty) {
      return Result.failure(PqTransportError.decodeFailure('doh empty body'));
    }
    return Result.success(Uint8List.fromList(req.body));
  }
  if (method == 'GET') {
    final dns = req.uri.queryParameters['dns'];
    if (dns == null) {
      return Result.failure(PqTransportError.decodeFailure('doh missing dns'));
    }
    return dohBase64UrlDecode(dns);
  }
  return Result.failure(PqTransportError.decodeFailure('doh method'));
}

/// RFC 8484 response. `cache-control: max-age=0` so an HTTP cache is not
/// a second DNS TTL.
PqHttpResponse dohResponse(
  Uint8List message, {
  required HttpVersion version,
  int status = 200,
}) {
  return PqHttpResponse(
    status: status,
    headers: const {
      'content-type': dnsMessageMediaType,
      'cache-control': 'max-age=0',
    },
    body: message,
    version: version,
  );
}

typedef DohHttp =
    Future<Result<PqHttpResponse, PqTransportError>> Function(PqHttpRequest);

/// Production DNS-over-HTTPS (RFC 8484) over a caller-supplied HTTP exchange.
/// Use [DohClient.h2] (ALPN `h2`) or [DohClient.h3] (ALPN `h3`).
final class DohClient {
  DohClient({
    required this.template,
    required this.roundTrip,
    this.useGet = false,
  });

  factory DohClient.h2(
    PqTlsSocket tls, {
    required DohUriTemplate template,
    PqHttpClient? http,
    bool useGet = false,
  }) {
    final client = http ?? PqHttpClient(prefer: HttpVersion.h2);
    return DohClient(
      template: template,
      useGet: useGet,
      roundTrip: (req) => client.roundTripH2(tls: tls, request: req),
    );
  }

  factory DohClient.h3(
    PqQuicConn conn, {
    required DohUriTemplate template,
    PqHttpClient? http,
    bool useGet = false,
  }) {
    final client = http ?? PqHttpClient(prefer: HttpVersion.h3);
    return DohClient(
      template: template,
      useGet: useGet,
      roundTrip: (req) => client.roundTripH3(conn: conn, request: req),
    );
  }

  final DohUriTemplate template;
  final DohHttp roundTrip;
  final bool useGet;

  Uri get postUri => template.postUri;

  /// Exchange for [PqDnsResolver]. Failures throw so the breaker opens.
  Future<Uint8List> Function(Uint8List query) get exchange => (query) async {
    final r = await this.query(query);
    if (r.isFailure) {
      throw StateError(r.errorOrNull.toString());
    }
    return r.valueOrNull!;
  };

  Future<Result<Uint8List, PqTransportError>> query(Uint8List message) async {
    if (message.isEmpty || message.length > dnsMessageMaxBytes) {
      return Result.failure(PqTransportError.decodeFailure('doh query len'));
    }
    final PqHttpRequest req;
    if (useGet) {
      req = PqHttpRequest(
        method: 'GET',
        uri: template.getUri(message),
        headers: const {'accept': dnsMessageMediaType},
      );
    } else {
      req = PqHttpRequest(
        method: 'POST',
        uri: template.postUri,
        headers: const {
          'accept': dnsMessageMediaType,
          'content-type': dnsMessageMediaType,
        },
        body: message,
      );
    }
    final resp = await roundTrip(req);
    if (resp.isFailure) return Result.failure(resp.errorOrNull!);
    final http = resp.valueOrNull!;
    if (http.status != 200) {
      return Result.failure(
        PqTransportError.decodeFailure('doh status ${http.status}'),
      );
    }
    if (_mediaType(http.headers['content-type']) != dnsMessageMediaType) {
      return Result.failure(
        PqTransportError.decodeFailure('doh response type'),
      );
    }
    if (http.body.isEmpty || http.body.length > dnsMessageMaxBytes) {
      return Result.failure(PqTransportError.decodeFailure('doh response len'));
    }
    return Result.success(http.body);
  }
}

/// RFC 1035 §4.2.2 / RFC 7858 2-byte length prefix.
Uint8List encodeDnsTcp(Uint8List message) {
  final b = BytesBuilder(copy: false)
    ..addByte((message.length >> 8) & 0xff)
    ..addByte(message.length & 0xff)
    ..add(message);
  return b.takeBytes();
}

/// Incremental reader for one or more length-prefixed DNS messages.
final class DnsTcpReader {
  final BytesBuilder _buf = BytesBuilder(copy: false);
  var _len = 0;
  PqTransportError? _error;

  PqTransportError? get error => _error;

  void add(Uint8List chunk) {
    if (_error != null || chunk.isEmpty) return;
    _buf.add(chunk);
    _len += chunk.length;
  }

  /// Returns the next full message, or null if more bytes are required.
  Uint8List? next() {
    if (_error != null || _len < 2) return null;
    final bytes = _buf.toBytes();
    final n = (bytes[0] << 8) | bytes[1];
    if (n == 0 || n > dnsMessageMaxBytes) {
      _error = PqTransportError.decodeFailure('dot length');
      return null;
    }
    if (_len < 2 + n) return null;
    final msg = slice(bytes, 2, 2 + n);
    final rest = slice(bytes, 2 + n, bytes.length);
    _buf.clear();
    _len = 0;
    if (rest.isNotEmpty) {
      _buf.add(rest);
      _len = rest.length;
    }
    return msg;
  }
}

/// Production DNS-over-TLS (RFC 7858). The socket must have completed
/// a handshake that selected ALPN `dot`.
final class DotClient {
  DotClient(this.tls);

  final PqTlsSocket tls;
  final DnsTcpReader _reader = DnsTcpReader();
  StreamSubscription<Uint8List>? _sub;
  final List<Completer<Result<Uint8List, PqTransportError>>> _waiters = [];

  void _ensureListen() {
    if (_sub != null) return;
    _sub = tls.applicationData.listen((chunk) {
      _reader.add(chunk);
      final err = _reader.error;
      if (err != null) {
        _failAll(err);
        return;
      }
      while (true) {
        final msg = _reader.next();
        final nextErr = _reader.error;
        if (nextErr != null) {
          _failAll(nextErr);
          return;
        }
        if (msg == null) return;
        if (_waiters.isEmpty) return;
        _waiters.removeAt(0).complete(Result.success(msg));
      }
    }, onDone: () => _failAll(PqTransportError.closed('dot closed')));
  }

  void _failAll(PqTransportError err) {
    final pending = List<Completer<Result<Uint8List, PqTransportError>>>.of(
      _waiters,
    );
    _waiters.clear();
    for (final c in pending) {
      if (!c.isCompleted) c.complete(Result.failure(err));
    }
  }

  /// Exchange for [PqDnsResolver].
  Future<Uint8List> Function(Uint8List query) get exchange => (query) async {
    final r = await this.query(query);
    if (r.isFailure) throw StateError(r.errorOrNull.toString());
    return r.valueOrNull!;
  };

  Future<Result<Uint8List, PqTransportError>> query(
    Uint8List message, {
    Duration timeout = const Duration(seconds: 10),
  }) async {
    if (!tls.isComplete) {
      return Result.failure(
        PqTransportError.handshakeFailure('tls not complete'),
      );
    }
    if (tls.alpn != dnsAlpnDot) {
      return Result.failure(
        PqTransportError.handshakeFailure('alpn is not dot'),
      );
    }
    if (message.isEmpty || message.length > dnsMessageMaxBytes) {
      return Result.failure(PqTransportError.decodeFailure('dot query len'));
    }
    _ensureListen();
    final waiter = Completer<Result<Uint8List, PqTransportError>>();
    _waiters.add(waiter);
    final sent = await tls.send(encodeDnsTcp(message));
    if (sent.isFailure) {
      _waiters.remove(waiter);
      return Result.failure(sent.errorOrNull!);
    }
    try {
      return await waiter.future.timeout(timeout);
    } on TimeoutException {
      _waiters.remove(waiter);
      return Result.failure(PqTransportError.decodeFailure('dot timeout'));
    }
  }

  Future<void> close() async {
    await _sub?.cancel();
    _sub = null;
    _failAll(PqTransportError.closed('dot closed'));
  }
}
