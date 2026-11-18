/// Relic [Adapter] on [PqHttpServer].
///
/// Relic's own `IOAdapter.bind` takes a `dart:io` [SecurityContext].
/// [PqRelicAdapter.bind] is the same shape without that context.
/// Serverpod's web server is Relic (`RelicApp.run`). Pass this
/// adapter there instead of `IOAdapter`. Serverpod's API server and
/// insights server still construct a [SecurityContext] inside
/// Serverpod; this package does not pretend that object can hold a
/// post-quantum handshake.
library;

import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'package:relic_core/relic_core.dart';
import 'package:stream_channel/stream_channel.dart';
import 'package:web_socket/web_socket.dart';

import 'pqtransport_io.dart';

final class PqRelicAdapter implements Adapter {
  PqRelicAdapter._(this._server);

  final PqHttpServer _server;
  final _requests = StreamController<AdapterRequest>();

  static Future<PqRelicAdapter> bind(
    Object address,
    int port, {
    required PqTlsServerIdentity identity,
    bool quic = false,
    PqHttpServerConfig config = const PqHttpServerConfig(),
  }) async {
    final server = await PqHttpServer.bind(
      address,
      port,
      identity: identity,
      quic: quic,
      config: config,
    );
    final adapter = PqRelicAdapter._(server);
    server.mount(adapter._handle);
    return adapter;
  }

  @override
  int get port => _server.port;

  @override
  Stream<AdapterRequest> get requests => _requests.stream;

  @override
  ConnectionsInfo get connectionsInfo =>
      (active: _server.activeConnections, closing: 0, idle: 0);

  Future<PqHttpResponse> _handle(PqHttpRequest request) {
    final pending = Completer<PqHttpResponse>();
    final slot = Zone.current[pqHttpHijackSlotKey] as PqHttpHijackSlot?;
    _requests.add(_PqRelicRequest(request, pending, port, slot));
    return pending.future;
  }

  @override
  Future<void> respond(AdapterRequest request, Response response) async {
    final pending = (request as _PqRelicRequest).pending;
    final bytes = BytesBuilder(copy: false);
    await for (final chunk in response.body.read()) {
      bytes.add(chunk);
    }
    final headers = <String, String>{
      for (final entry in response.headers.entries)
        entry.key: entry.value.join(', '),
    };
    final type = response.body.bodyType;
    if (type != null && !headers.containsKey('content-type')) {
      headers['content-type'] = type.toHeaderValue();
    }
    pending.complete(
      PqHttpResponse(
        status: response.statusCode,
        headers: headers,
        body: bytes.takeBytes(),
        version: HttpVersion.h1,
      ),
    );
  }

  @override
  Future<void> hijack(AdapterRequest request, HijackCallback callback) async {
    final relic = request as _PqRelicRequest;
    final slot = relic.slot;
    if (slot == null) {
      throw UnsupportedError('PqRelicAdapter detaches only HTTP/1.1');
    }
    slot.user = callback;
    if (!relic.pending.isCompleted) {
      relic.pending.complete(
        PqHttpResponse(
          status: 0,
          headers: const {},
          body: Uint8List(0),
          version: HttpVersion.h1,
          hijacked: true,
          httpMinor: relic.http.httpMinor,
        ),
      );
    }
  }

  @override
  Future<void> connect(
    AdapterRequest request,
    WebSocketCallback callback,
  ) async {
    final relic = request as _PqRelicRequest;
    final slot = relic.slot;
    if (slot == null || relic.http.httpMinor != 1) {
      throw UnsupportedError(
        'PqRelicAdapter speaks WebSocket on HTTP/1.1 only',
      );
    }
    final opening = acceptWebSocketHandshake(relic.http.headers);
    if (opening.isFailure) {
      if (!relic.pending.isCompleted) {
        relic.pending.complete(
          PqHttpResponse(
            status: 400,
            headers: const {'connection': 'close'},
            body: Uint8List(0),
            version: HttpVersion.h1,
            httpMinor: relic.http.httpMinor,
          ),
        );
      }
      return;
    }
    final accepted = opening.valueOrNull!;
    slot.user = (channel) {
      channel.sink.add(utf8.encode(websocketSwitchingProtocols(accepted)));
      callback(_PqRelicWebSocket(channel, accepted));
    };
    if (!relic.pending.isCompleted) {
      relic.pending.complete(
        PqHttpResponse(
          status: 0,
          headers: const {},
          body: Uint8List(0),
          version: HttpVersion.h1,
          hijacked: true,
          httpMinor: relic.http.httpMinor,
        ),
      );
    }
  }

  @override
  Future<void> close({bool force = false}) async {
    await _server.close();
    if (!_requests.isClosed) await _requests.close();
  }
}

final class _PqRelicRequest extends AdapterRequest {
  _PqRelicRequest(this.http, this.pending, this.localPort, this.slot);

  final PqHttpRequest http;
  final Completer<PqHttpResponse> pending;
  final int localPort;
  final PqHttpHijackSlot? slot;

  @override
  Request toRequest() {
    return RequestInternal.create(
      Method.parse(http.method),
      http.uri,
      this,
      protocolVersion: http.httpMinor == 0 ? '1.0' : '1.1',
      headers: Headers.fromMap({
        for (final entry in http.headers.entries) entry.key: [entry.value],
        if (!http.headers.keys.any((name) => name.toLowerCase() == 'host'))
          'host': [http.uri.host],
      }),
      body: http.body.isEmpty
          ? Body.empty()
          : Body.fromData(Uint8List.fromList(http.body), mimeType: null),
      connectionInfo: ConnectionInfo(
        remote: SocketAddress(
          address: IPAddress.parse(
            http.uri.host.isEmpty ? '127.0.0.1' : '127.0.0.1',
          ),
          port: 0,
        ),
        localPort: localPort,
      ),
    );
  }
}

final class _PqRelicWebSocket implements RelicWebSocket {
  _PqRelicWebSocket(StreamChannel<List<int>> channel, WebSocketOpening opening)
    : protocol = opening.protocol,
      _endpoint = WebSocketEndpoint(
        channel,
        client: false,
        deflate: opening.deflate,
        protocol: opening.protocol,
      ) {
    _sub = _endpoint.events.listen((event) {
      switch (event) {
        case WebSocketInboundData(:final text, :final data):
          if (_events.isClosed) return;
          _events.add(
            text
                ? TextDataReceived(utf8.decode(data))
                : BinaryDataReceived(data),
          );
        case WebSocketInboundClose(:final code, :final reason):
          if (!_events.isClosed) {
            _events.add(CloseReceived(code, reason));
            unawaited(_events.close());
          }
        case WebSocketInboundPing() || WebSocketInboundPong():
          break;
      }
    });
  }

  final WebSocketEndpoint _endpoint;
  final _events = StreamController<WebSocketEvent>();
  StreamSubscription<WebSocketInbound>? _sub;
  Duration? _pingInterval;
  Timer? _pings;

  @override
  String protocol;

  @override
  Stream<WebSocketEvent> get events => _events.stream;

  @override
  bool get isClosed => _endpoint.isClosed;

  @override
  Duration? get pingInterval => _pingInterval;

  @override
  set pingInterval(Duration? value) {
    _pingInterval = value;
    _pings?.cancel();
    _pings = null;
    if (value == null || isClosed) return;
    _pings = Timer.periodic(value, (_) => _endpoint.ping());
  }

  @override
  void sendText(String s) {
    if (isClosed) throw WebSocketConnectionClosed();
    _endpoint.sendText(s);
  }

  @override
  void sendBytes(Uint8List b) {
    if (isClosed) throw WebSocketConnectionClosed();
    _endpoint.sendBytes(b);
  }

  @override
  bool trySendText(String s) {
    if (isClosed) return false;
    sendText(s);
    return true;
  }

  @override
  bool trySendBytes(Uint8List b) {
    if (isClosed) return false;
    sendBytes(b);
    return true;
  }

  @override
  Future<void> close([int? code, String? reason]) async {
    final done = await tryClose(code, reason);
    if (!done) throw WebSocketConnectionClosed();
  }

  @override
  Future<bool> tryClose([int? code, String? reason]) async {
    if (isClosed) return false;
    if (code != null && code != 1000 && (code < 3000 || code > 4999)) {
      throw ArgumentError.value(code, 'code');
    }
    if (reason != null && utf8.encode(reason).length > 123) {
      throw ArgumentError.value(reason, 'reason');
    }
    _pings?.cancel();
    final sent = _endpoint.close(code, reason);
    if (sent.isFailure) return false;
    await _sub?.cancel();
    _sub = null;
    return true;
  }
}
