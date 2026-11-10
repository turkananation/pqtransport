@TestOn('vm')
library;

import 'dart:io';

import 'package:pqtransport/pqtransport_io.dart';
import 'package:pqtransport/relic.dart';
import 'package:pqtransport/shelf.dart';
import 'package:relic_core/relic_core.dart' hide Result;
import 'package:shelf/shelf.dart' as shelf;
import 'package:swissarmyknife/swissarmyknife.dart';
import 'package:test/test.dart';

void main() {
  test('a Shelf handler replaces SecurityContext', () async {
    final crypto = PqTransportCrypto();
    final identity = PqTlsServerIdentity.generate(crypto);
    final server = await serveShelf(
      (request) => shelf.Response.ok('shelf-ok ${request.requestedUri.path}'),
      InternetAddress.loopbackIPv4,
      0,
      identity: identity,
    );
    addTearDown(server.close);
    final response = await _get(crypto, server.port, '/shelf');
    expect(response.isSuccess, isTrue, reason: '${response.errorOrNull}');
    expect(response.valueOrNull!.status, 200);
    expect(String.fromCharCodes(response.valueOrNull!.body), 'shelf-ok /shelf');
  });

  test('a Relic adapter replaces IOAdapter SecurityContext', () async {
    final crypto = PqTransportCrypto();
    final identity = PqTlsServerIdentity.generate(crypto);
    final adapter = await PqRelicAdapter.bind(
      InternetAddress.loopbackIPv4,
      0,
      identity: identity,
    );
    final relic = RelicServer(() => adapter);
    await relic.mountAndStart(
      (request) =>
          Response.ok(body: Body.fromString('relic-ok ${request.url.path}')),
    );
    addTearDown(relic.close);
    final response = await _get(crypto, adapter.port, '/relic');
    expect(response.isSuccess, isTrue, reason: '${response.errorOrNull}');
    expect(response.valueOrNull!.status, 200);
    expect(String.fromCharCodes(response.valueOrNull!.body), 'relic-ok /relic');
  });
}

Future<Result<PqHttpResponse, PqTransportError>> _get(
  PqTransportCrypto crypto,
  int port,
  String path,
) async {
  final socket = await IoTcpSocket.connect(
    InternetAddress.loopbackIPv4.address,
    port,
  );
  final tls = PqTlsSocket.client(
    socket,
    crypto: crypto,
    alpnProtocols: const [httpAlpnH1],
  );
  final handshake = await tls.handshake();
  if (handshake.isFailure) return Result.failure(handshake.errorOrNull!);
  final response = await PqHttpClient().roundTripH1(
    tls: tls,
    request: PqHttpRequest(
      method: 'GET',
      uri: Uri.parse('https://localhost$path'),
    ),
  );
  await tls.close();
  return response;
}
