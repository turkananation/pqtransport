import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

import '../core/crypto.dart';
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
import 'pq_http_client.dart';

typedef PqHttpHandler = Future<PqHttpResponse> Function(PqHttpRequest request);

/// TLS listener for HTTP/1.1 (`http/1.1`), HTTP/2 (`h2`), and, when
/// [bind] is called with `quic: true`, HTTP/3 (`h3`) on the same port.
///
/// This replaces `dart:io` [HttpServer] plus [SecurityContext]. Shelf
/// mounts through `package:pqtransport/shelf.dart`. Relic, which is
/// the web server Serverpod uses, mounts through
/// `package:pqtransport/relic.dart`. Neither path is a
/// [SecurityContext].
final class PqHttpServer {
  PqHttpServer._(this._tcp);

  final IoTcpServer _tcp;
  IoDatagramChannel? _quic;
  StreamSubscription<IoTcpSocket>? _tcpSub;
  StreamSubscription<PqDatagramIn>? _quicSub;
  PqHttpHandler? _handler;
  var _closed = false;
  var _active = 0;
  final _quicConns = <String, PqQuicConn>{};
  final _live = <PqTlsSocket>{};

  int get port => _tcp.port;

  int get activeConnections => _active;

  static Future<PqHttpServer> bind(
    Object address,
    int port, {
    required PqTlsServerIdentity identity,
    PqTransportCrypto? crypto,
    HybridGroup group = HybridGroup.x25519MlKem768,
    bool quic = false,
  }) async {
    final tcp = await IoTcpServer.bind(address, port);
    final server = PqHttpServer._(tcp);
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

  Future<void> close() async {
    _closed = true;
    await _tcpSub?.cancel();
    await _quicSub?.cancel();
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

  Future<void> _tcpConnection(
    IoTcpSocket socket, {
    required PqTlsServerIdentity identity,
    required PqTransportCrypto crypto,
    required HybridGroup group,
  }) async {
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
    final buf = BytesBuilder(copy: false);
    final incoming = StreamController<Uint8List>();
    final sub = tls.applicationData.listen(
      incoming.add,
      onError: incoming.addError,
      onDone: incoming.close,
    );
    try {
      await for (final chunk in incoming.stream.timeout(
        const Duration(minutes: 2),
      )) {
        buf.add(chunk);
        while (true) {
          final raw = buf.toBytes();
          final parsed = tryParseHttp1Request(raw);
          if (parsed.isFailure) {
            await tls.send(
              encodeHttp1Response(
                PqHttpResponse(
                  status: 400,
                  headers: const {'connection': 'close'},
                  body: Uint8List(0),
                  version: HttpVersion.h1,
                ),
              ),
            );
            return;
          }
          final message = parsed.valueOrNull!;
          if (message.incomplete || message.request == null) break;
          final rest = Uint8List.sublistView(raw, message.consumed);
          buf.clear();
          if (rest.isNotEmpty) buf.add(rest);
          final response = await handler(message.request!);
          final sent = await tls.send(encodeHttp1Response(response));
          if (sent.isFailure || message.close || _wantsClose(response)) {
            return;
          }
        }
      }
    } on TimeoutException {
      return;
    } finally {
      await sub.cancel();
      if (!incoming.isClosed) await incoming.close();
    }
  }

  Future<void> _serveH2(PqTlsSocket tls, PqHttpHandler handler) async {
    final session = PqHttp2Session.server(tls);
    while (!_closed) {
      final accepted = await session.accept(
        timeout: const Duration(minutes: 2),
      );
      if (accepted.isFailure) return;
      final (id, request) = accepted.valueOrNull!;
      final response = await handler(request);
      final sent = await session.respond(id, response);
      if (sent.isFailure) return;
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
    final conn = PqQuicConn.server(
      crypto: crypto,
      group: group,
      identity: identity,
      alpnProtocols: const [httpAlpnH3],
      deliver: (packet) => channel.send(packet, datagram.peer),
    );
    _quicConns[key] = conn;
    conn.bindLossTimer();
    await conn.ingestDatagram(datagram.data);
    unawaited(_serveH3(conn));
  }

  Future<void> _serveH3(PqQuicConn conn) async {
    final ready = DateTime.now().add(const Duration(seconds: 20));
    while (!conn.isComplete && DateTime.now().isBefore(ready)) {
      await Future<void>.delayed(const Duration(milliseconds: 20));
    }
    if (!conn.isComplete) return;
    final handler = _handler;
    if (handler == null) return;
    final session = PqHttp3Session.server(conn);
    while (!_closed && !conn.isClosed) {
      final accepted = await session.accept(
        timeout: const Duration(seconds: 20),
      );
      if (accepted.isFailure) return;
      final (id, request) = accepted.valueOrNull!;
      final response = await handler(request);
      final sent = await session.respond(id, response);
      if (sent.isFailure) return;
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
