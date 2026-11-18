/// Shelf handler on [PqHttpServer].
///
/// This is the replacement for `shelf_io.serve` plus a `dart:io`
/// [SecurityContext]. The handler is an ordinary Shelf [Handler].
/// TLS is the pqtransport handshake, not the platform stack.
library;

import 'dart:async';
import 'dart:typed_data';

import 'package:shelf/shelf.dart';

import 'pqtransport_io.dart';

/// Binds [handler] with pqtransport TLS. ALPN offers `h2` and
/// `http/1.1`. Pass [quic] to also accept HTTP/3 on the same port.
/// [config] is the listener limit. HTTP/1.1 can be hijacked. HTTP/2
/// cannot.
Future<PqHttpServer> serveShelf(
  Handler handler,
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
  server.mount((request) => _callShelf(handler, request));
  return server;
}

Future<PqHttpResponse> _callShelf(
  Handler handler,
  PqHttpRequest request,
) async {
  final slot = Zone.current[pqHttpHijackSlotKey] as PqHttpHijackSlot?;
  final shelfRequest = Request(
    request.method,
    request.uri,
    headers: request.headers,
    body: request.body.isEmpty ? null : Stream.value(request.body),
    onHijack: slot == null
        ? null
        : (user) {
            slot.user = user;
          },
  );
  try {
    final shelfResponse = await handler(shelfRequest);
    if (!shelfRequest.canHijack) {
      return PqHttpResponse(
        status: 0,
        headers: const {},
        body: Uint8List(0),
        version: HttpVersion.h1,
        hijacked: true,
      );
    }
    final bytes = BytesBuilder(copy: false);
    await for (final chunk in shelfResponse.read()) {
      bytes.add(chunk);
    }
    return PqHttpResponse(
      status: shelfResponse.statusCode,
      headers: {
        for (final entry in shelfResponse.headers.entries)
          entry.key: entry.value,
      },
      body: bytes.takeBytes(),
      version: HttpVersion.h1,
    );
  } on HijackException {
    if (!shelfRequest.canHijack) {
      return PqHttpResponse(
        status: 0,
        headers: const {},
        body: Uint8List(0),
        version: HttpVersion.h1,
        hijacked: true,
      );
    }
    return PqHttpResponse(
      status: 500,
      headers: const {},
      body: Uint8List(0),
      version: HttpVersion.h1,
    );
  }
}
