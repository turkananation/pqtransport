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
import 'dart:typed_data';

import 'package:relic_core/relic_core.dart';

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
  }) async {
    final server = await PqHttpServer.bind(
      address,
      port,
      identity: identity,
      quic: quic,
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
    _requests.add(_PqRelicRequest(request, pending, port));
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
    throw UnsupportedError(
      'PqRelicAdapter does not detach the TLS record stream',
    );
  }

  @override
  Future<void> connect(
    AdapterRequest request,
    WebSocketCallback callback,
  ) async {
    throw UnsupportedError('PqRelicAdapter does not speak WebSocket');
  }

  @override
  Future<void> close({bool force = false}) async {
    await _server.close();
    if (!_requests.isClosed) await _requests.close();
  }
}

final class _PqRelicRequest extends AdapterRequest {
  _PqRelicRequest(this.http, this.pending, this.localPort);

  final PqHttpRequest http;
  final Completer<PqHttpResponse> pending;
  final int localPort;

  @override
  Request toRequest() {
    return RequestInternal.create(
      Method.parse(http.method),
      http.uri,
      this,
      protocolVersion: '1.1',
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
