import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

import 'package:stream_channel/stream_channel.dart';
import 'package:swissarmyknife/swissarmyknife.dart';

import '../core/crypto.dart';
import '../core/errors.dart';
import '../core/hybrid.dart';
import '../core/lengths.dart';
import '../quic/connection.dart';
import '../socket/io_socket.dart';
import '../socket/pq_transport_socket.dart';
import '../tls/pq_tls_server.dart';
import '../tls/pq_tls_socket.dart';
import 'http1.dart';
import 'http2.dart';
import 'http3.dart';
import 'content_coding.dart';
import 'pq_http_client.dart';

typedef PqHttpHandler = Future<PqHttpResponse> Function(PqHttpRequest request);

/// Limits for a listener that is reachable by more than one client.
///
/// [idleTimeout] bounds a silent connection. [maxConnections] bounds
/// accepted sockets. [maxConcurrentStreams] is the HTTP/2 setting.
/// [maxBodyBytes] is the HTTP/1.1 body cap.
final class PqHttpServerConfig {
  const PqHttpServerConfig({
    this.idleTimeout = const Duration(seconds: 60),
    this.maxConnections = 256,
    this.maxConcurrentStreams = http2DefaultMaxConcurrentStreams,
    this.maxBodyBytes = http1DefaultMaxBodyBytes,
  });

  final Duration idleTimeout;
  final int maxConnections;
  final int maxConcurrentStreams;
  final int maxBodyBytes;
}

/// Zone slot Shelf uses to take the HTTP/1.1 connection.
final Object pqHttpHijackSlotKey = Object();

final class PqHttpHijackSlot {
  void Function(StreamChannel<List<int>> channel)? user;
}

/// TLS listener for HTTP/1.1 (`http/1.1`), HTTP/2 (`h2`), and, when
/// [bind] is called with `quic: true`, HTTP/3 (`h3`) on the same port.
///
/// This replaces `dart:io` [HttpServer] plus [SecurityContext]. Shelf
/// mounts through `package:pqtransport/shelf.dart`. Relic, which is
/// the web server Serverpod uses, mounts through
/// `package:pqtransport/relic.dart`. Neither path is a
/// [SecurityContext].
final class PqHttpServer {
  PqHttpServer._(this._tcp, this.config);

  final IoTcpServer _tcp;
  final PqHttpServerConfig config;
  IoDatagramChannel? _quic;
  StreamSubscription<IoTcpSocket>? _tcpSub;
  StreamSubscription<PqDatagramIn>? _quicSub;
  PqHttpHandler? _handler;
  var _closed = false;
  var _active = 0;
  var _inFlight = 0;
  final _quicConns = <String, PqQuicConn>{};
  final _live = <PqTlsSocket>{};
  final _h2 = <PqHttp2Session>{};
  final _h3 = <PqHttp3Session>{};
  final _waiters = <Completer<void>>{};

  int get port => _tcp.port;

  int get activeConnections => _active;

  static Future<PqHttpServer> bind(
    Object address,
    int port, {
    required PqTlsServerIdentity identity,
    PqTransportCrypto? crypto,
    HybridGroup group = HybridGroup.x25519MlKem768,
    bool quic = false,
    PqHttpServerConfig config = const PqHttpServerConfig(),
  }) async {
    final tcp = await IoTcpServer.bind(address, port);
    final server = PqHttpServer._(tcp, config);
    final used = crypto ?? const PqTransportCrypto();
    server._tcpSub = tcp.connections.listen((socket) {
      unawaited(
        server._tcpConnection(
          socket,
          identity: identity,
          crypto: used,
          group: group,
        ),
      );
    });
    if (quic) {
      final channel = await IoDatagramChannel.bind(
        tcp.address,
        tcp.port,
        reuseAddress: true,
      );
      server._quic = channel;
      server._quicSub = channel.incoming.listen((datagram) {
        unawaited(
          server._quicDatagram(
            channel,
            datagram,
            identity: identity,
            crypto: used,
            group: group,
          ),
        );
      });
    }
    return server;
  }

  /// Throws [StateError] if a handler is already mounted.
  void mount(PqHttpHandler handler) {
    if (_handler != null) {
      throw StateError('PqHttpServer already has a handler');
    }
    _handler = handler;
  }

  /// Stops accepting. HTTP/2 and HTTP/3 get GOAWAY. In-flight handlers
  /// finish, then the sockets close. [drain] caps how long close waits.
  Future<void> close({Duration? drain}) async {
    if (_closed) return;
    _closed = true;
    await _tcpSub?.cancel();
    await _quicSub?.cancel();
    _wake();
    for (final session in List<PqHttp2Session>.of(_h2)) {
      await session.close();
    }
    for (final session in List<PqHttp3Session>.of(_h3)) {
      await session.goAway(0);
    }
    final deadline = DateTime.now().add(drain ?? config.idleTimeout);
    while (_inFlight > 0 && DateTime.now().isBefore(deadline)) {
      await Future<void>.delayed(const Duration(milliseconds: 20));
    }
    for (final tls in List<PqTlsSocket>.of(_live)) {
      await tls.close();
    }
    await _tcp.close();
    await _quic?.close();
    for (final conn in _quicConns.values) {
      if (!conn.isClosed) {
        await conn.close(errorCode: 0, application: true);
      }
    }
    _quicConns.clear();
  }

  void _wake() {
    for (final waiter in List<Completer<void>>.of(_waiters)) {
      if (!waiter.isCompleted) waiter.complete();
    }
    _waiters.clear();
  }

  Future<void> _tcpConnection(
    IoTcpSocket socket, {
    required PqTlsServerIdentity identity,
    required PqTransportCrypto crypto,
    required HybridGroup group,
  }) async {
    if (_closed || _active >= config.maxConnections) {
      await socket.close();
      return;
    }
    final tls = PqTlsSocket.server(
      socket,
      crypto: crypto,
      identity: identity,
      group: group,
      alpnProtocols: const [httpAlpnH2, httpAlpnH1],
    );
    _active++;
    _live.add(tls);
    try {
      final hs = await tls.handshake();
      if (hs.isFailure || _closed) return;
      final handler = _handler;
      if (handler == null) return;
      if (tls.alpn == httpAlpnH2) {
        await _serveH2(tls, handler);
      } else {
        await _serveH1(tls, handler);
      }
    } finally {
      _live.remove(tls);
      _active--;
      await tls.close();
    }
  }

  Future<void> _serveH1(PqTlsSocket tls, PqHttpHandler handler) async {
    final pending = <Uint8List>[];
    var done = false;
    final sub = tls.applicationData.listen(
      (chunk) {
        pending.add(chunk);
        _wake();
      },
      onError: (Object _) {
        done = true;
        _wake();
      },
      onDone: () {
        done = true;
        _wake();
      },
    );
    final buf = BytesBuilder(copy: false);
    var continued = false;
    var took = false;
    try {
      while (!_closed) {
        if (pending.isEmpty && !done) {
          final waiter = Completer<void>();
          _waiters.add(waiter);
          try {
            await waiter.future.timeout(config.idleTimeout);
          } on TimeoutException {
            return;
          }
          continue;
        }
        if (pending.isEmpty && done) return;
        while (pending.isNotEmpty) {
          buf.add(pending.removeAt(0));
        }
        final raw = buf.toBytes();
        final expect = inspectHttp1Expect(raw, maxBody: config.maxBodyBytes);
        if (expect.isFailure) {
          await _sendStatus(tls, _statusFor(expect.errorOrNull!));
          return;
        }
        final look = expect.valueOrNull;
        if (look != null && look.rejected) {
          await _sendStatus(tls, 417);
          return;
        }
        if (look != null && look.sendContinue && !continued) {
          continued = true;
          final sent = await tls.send(
            Uint8List.fromList('HTTP/1.1 100 Continue\r\n\r\n'.codeUnits),
          );
          if (sent.isFailure) return;
        }
        final parsed = tryParseHttp1Request(raw, maxBody: config.maxBodyBytes);
        if (parsed.isFailure) {
          await _sendStatus(tls, _statusFor(parsed.errorOrNull!));
          return;
        }
        final message = parsed.valueOrNull!;
        if (message.incomplete || message.request == null) {
          if (done) return;
          continue;
        }
        continued = false;
        final rest = Uint8List.sublistView(raw, message.consumed);
        buf.clear();
        if (rest.isNotEmpty) buf.add(rest);
        final decoded = _inflateRequest(message.request!);
        if (decoded.isFailure) {
          await _sendStatus(tls, 400);
          return;
        }
        final request = decoded.valueOrNull!;
        final slot = PqHttpHijackSlot();
        _inFlight++;
        final PqHttpResponse response;
        try {
          response = await runZoned(
            () => handler(request),
            zoneValues: {pqHttpHijackSlotKey: slot},
          );
        } finally {
          _inFlight--;
        }
        if (response.hijacked) {
          if (slot.user == null) {
            await _sendStatus(tls, 500);
            return;
          }
          took = true;
          await _hijack(tls, sub, pending, buf, request, slot);
          return;
        }
        final sent = await tls.send(
          encodeHttp1Response(
            _http1Response(request, response, close: message.close),
            omitBody: _omitMessageBody(request, response),
          ),
        );
        if (sent.isFailure ||
            message.close ||
            _wantsClose(response) ||
            _closed) {
          return;
        }
      }
    } finally {
      if (!took) await sub.cancel();
    }
  }

  Future<void> _hijack(
    PqTlsSocket tls,
    StreamSubscription<Uint8List> sub,
    List<Uint8List> pending,
    BytesBuilder buf,
    PqHttpRequest request,
    PqHttpHijackSlot slot,
  ) async {
    final user = slot.user;
    if (user == null) return;
    final finished = Completer<void>();
    void finish() {
      if (!finished.isCompleted) finished.complete();
    }

    final incoming = StreamController<List<int>>();
    final outgoing = StreamController<List<int>>();
    var sends = Future<void>.value();
    final outSub = outgoing.stream.listen(
      (chunk) {
        final bytes = Uint8List.fromList(chunk);
        sends = sends.then((_) async {
          await tls.send(bytes);
        });
      },
      onDone: () {
        unawaited(sends.then((_) => finish()));
      },
      onError: (Object _) {
        finish();
      },
    );
    if (request.body.isNotEmpty) incoming.add(request.body);
    final already = buf.takeBytes();
    if (already.isNotEmpty) incoming.add(already);
    for (final chunk in pending) {
      incoming.add(chunk);
    }
    pending.clear();
    sub.onData((Uint8List chunk) {
      if (!incoming.isClosed) incoming.add(chunk);
    });
    sub.onDone(() {
      if (!incoming.isClosed) unawaited(incoming.close());
      finish();
    });
    sub.onError((Object _) {
      finish();
    });
    final waiter = Completer<void>();
    _waiters.add(waiter);
    unawaited(waiter.future.then((_) => finish()));
    user(StreamChannel(incoming.stream, outgoing.sink));
    try {
      await finished.future.timeout(config.idleTimeout);
    } on TimeoutException {
      // A hijack that never closes still hits the listener idle bound.
    } finally {
      _waiters.remove(waiter);
      await outSub.cancel();
      await sub.cancel();
      if (!incoming.isClosed) await incoming.close();
      if (!outgoing.isClosed) await outgoing.close();
    }
  }

  Future<void> _sendStatus(PqTlsSocket tls, int status) async {
    await tls.send(
      encodeHttp1Response(
        PqHttpResponse(
          status: status,
          headers: const {'connection': 'close'},
          body: Uint8List(0),
          version: HttpVersion.h1,
        ),
      ),
    );
  }

  int _statusFor(PqTransportError error) {
    return error.message.contains('body') ? 413 : 400;
  }

  Future<void> _serveH2(PqTlsSocket tls, PqHttpHandler handler) async {
    final session = PqHttp2Session.server(
      tls,
      maxConcurrentStreams: config.maxConcurrentStreams,
    );
    _h2.add(session);
    try {
      while (!_closed) {
        final accepted = await session.accept(timeout: config.idleTimeout);
        if (accepted.isFailure || _closed) return;
        final (id, request) = accepted.valueOrNull!;
        _inFlight++;
        final PqHttpResponse response;
        try {
          response = await handler(request);
        } finally {
          _inFlight--;
        }
        if (_closed && response.hijacked) return;
        final sent = await session.respond(id, response);
        if (sent.isFailure) return;
      }
    } finally {
      _h2.remove(session);
    }
  }

  Future<void> _quicDatagram(
    IoDatagramChannel channel,
    PqDatagramIn datagram, {
    required PqTlsServerIdentity identity,
    required PqTransportCrypto crypto,
    required HybridGroup group,
  }) async {
    final key = '${datagram.peer.host}:${datagram.peer.port}';
    final existing = _quicConns[key];
    if (existing != null && !existing.isClosed) {
      await existing.ingestDatagram(datagram.data);
      return;
    }
    if (_closed || _quicConns.length >= config.maxConnections) return;
    final conn = PqQuicConn.server(
      crypto: crypto,
      group: group,
      identity: identity,
      alpnProtocols: const [httpAlpnH3],
      idleTimeout: config.idleTimeout,
      deliver: (packet) => channel.send(packet, datagram.peer),
    );
    _quicConns[key] = conn;
    conn.bindLossTimer();
    await conn.ingestDatagram(datagram.data);
    unawaited(_serveH3(conn));
  }

  Future<void> _serveH3(PqQuicConn conn) async {
    final ready = DateTime.now().add(const Duration(seconds: 20));
    while (!conn.isComplete && DateTime.now().isBefore(ready) && !_closed) {
      await Future<void>.delayed(const Duration(milliseconds: 20));
    }
    if (!conn.isComplete || _closed) return;
    final handler = _handler;
    if (handler == null) return;
    final session = PqHttp3Session.server(conn);
    _h3.add(session);
    try {
      while (!_closed && !conn.isClosed) {
        final accepted = await session.accept(timeout: config.idleTimeout);
        if (accepted.isFailure || _closed) return;
        final (id, request) = accepted.valueOrNull!;
        _inFlight++;
        final PqHttpResponse response;
        try {
          response = await handler(request);
        } finally {
          _inFlight--;
        }
        final sent = await session.respond(id, response);
        if (sent.isFailure) return;
      }
    } finally {
      _h3.remove(session);
    }
  }

  bool _wantsClose(PqHttpResponse response) {
    final value = response.headers.entries
        .where((entry) => entry.key.toLowerCase() == 'connection')
        .map((entry) => entry.value)
        .join(',');
    return value.toLowerCase().split(',').any((part) => part.trim() == 'close');
  }
}

PqHttpResponse _http1Response(
  PqHttpRequest request,
  PqHttpResponse response, {
  required bool close,
}) {
  final headers = <String, String>{
    for (final entry in response.headers.entries)
      entry.key.toLowerCase(): entry.value,
  };
  if (close) {
    final connection = headers['connection'] ?? '';
    final already = connection
        .toLowerCase()
        .split(',')
        .any((part) => part.trim() == 'close');
    if (!already) {
      headers['connection'] = connection.isEmpty
          ? 'close'
          : '$connection, close';
    }
  }
  var body = response.body;
  final coding = headers['content-encoding'];
  final accept = request.headers['accept-encoding'];
  final head = request.method.toUpperCase() == 'HEAD';
  if (!head &&
      body.isNotEmpty &&
      coding == null &&
      accept != null &&
      response.status >= 200 &&
      response.status != 204 &&
      response.status != 304) {
    final picked = selectContentCoding(accept);
    if (picked != null) {
      final encoded = encodeContentCoding(picked, body);
      if (encoded.isSuccess) {
        body = encoded.valueOrNull!;
        headers['content-encoding'] = picked;
        final vary = headers['vary'];
        if (vary == null || vary.isEmpty) {
          headers['vary'] = 'accept-encoding';
        }
      }
    }
  }
  return PqHttpResponse(
    status: response.status,
    headers: headers,
    body: body,
    version: HttpVersion.h1,
    trailers: response.trailers,
    hijacked: response.hijacked,
    httpMinor: request.httpMinor,
  );
}

bool _omitMessageBody(PqHttpRequest request, PqHttpResponse response) {
  return request.method.toUpperCase() == 'HEAD';
}

Result<PqHttpRequest, PqTransportError> _inflateRequest(PqHttpRequest request) {
  final coding = request.headers['content-encoding'];
  if (coding == null || coding.isEmpty || request.body.isEmpty) {
    return Result.success(request);
  }
  final decoded = decodeContentCodingHeader(
    coding,
    Uint8List.fromList(request.body),
  );
  if (decoded.isFailure) return Result.failure(decoded.errorOrNull!);
  final headers = <String, String>{...request.headers}
    ..remove('content-encoding');
  headers['content-length'] = '${decoded.valueOrNull!.length}';
  return Result.success(
    PqHttpRequest(
      method: request.method,
      uri: request.uri,
      headers: headers,
      body: decoded.valueOrNull!,
      trailers: request.trailers,
      protocol: request.protocol,
      httpMinor: request.httpMinor,
    ),
  );
}
