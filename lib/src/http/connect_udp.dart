import 'dart:convert';
import 'dart:typed_data';

import 'package:swissarmyknife/swissarmyknife.dart';

import '../core/bytes.dart';
import '../core/errors.dart';
import '../core/lengths.dart';
import '../quic/packet.dart';
import 'http3.dart';
import 'pq_http_client.dart';

/// RFC 9298. Context ID then the unmodified UDP payload.
/// Context ID 0 is the only context this RFC defines. A non-zero
/// identifier has no registration capsule in RFC 9298 and is dropped.
Uint8List encodeProxyDatagram(int contextId, Uint8List payload) {
  final b = BytesBuilder(copy: false);
  writeQuicVarint(b, contextId);
  b.add(payload);
  return b.takeBytes();
}

({int contextId, Uint8List payload})? decodeProxyDatagram(Uint8List wire) {
  final reader = ByteReader(wire);
  final id = readVarint(reader);
  if (id < 0) return null;
  return (contextId: id, payload: slice(wire, reader.offset, wire.length));
}

/// RFC 9298 §2. `target_host` and `target_port` for the default template.
Result<(String host, int port), PqTransportError> connectUdpTarget({
  required String targetHost,
  required int targetPort,
}) {
  if (targetHost.isEmpty ||
      targetHost.contains('%') ||
      targetHost.contains('/') ||
      targetHost.contains(' ') ||
      targetPort < 1 ||
      targetPort > 65535) {
    return Result.failure(PqTransportError.decodeFailure('connect-udp target'));
  }
  final host = targetHost.contains(':')
      ? Uri.encodeComponent(targetHost)
      : targetHost;
  return Result.success((host, targetPort));
}

/// `/.well-known/masque/udp/{target_host}/{target_port}/`
Result<String, PqTransportError> connectUdpPath({
  required String targetHost,
  required int targetPort,
}) {
  final target = connectUdpTarget(
    targetHost: targetHost,
    targetPort: targetPort,
  );
  if (target.isFailure) return Result.failure(target.errorOrNull!);
  final (host, port) = target.valueOrNull!;
  return Result.success('/.well-known/masque/udp/$host/$port/');
}

/// HTTP/2 and HTTP/3 extended CONNECT. HTTP/1.1 is [encodeHttp1Upgrade].
Result<PqHttpRequest, PqTransportError> connectUdpRequest({
  required String proxyHost,
  required String targetHost,
  required int targetPort,
  int? proxyPort,
  String scheme = 'https',
}) {
  final path = connectUdpPath(targetHost: targetHost, targetPort: targetPort);
  if (path.isFailure) return Result.failure(path.errorOrNull!);
  return Result.success(
    PqHttpRequest(
      method: 'CONNECT',
      uri: Uri(
        scheme: scheme,
        host: proxyHost,
        port: proxyPort,
        path: path.valueOrNull,
      ),
      protocol: 'connect-udp',
      headers: const {'capsule-protocol': '?1'},
    ),
  );
}

/// RFC 9298 HTTP/1.1: GET, Upgrade, Capsule-Protocol.
Uint8List encodeHttp1Upgrade({
  required String host,
  required String path,
  required String protocol,
}) {
  final text =
      'GET $path HTTP/1.1\r\n'
      'Host: $host\r\n'
      'Connection: Upgrade\r\n'
      'Upgrade: $protocol\r\n'
      'Capsule-Protocol: ?1\r\n'
      '\r\n';
  return Uint8List.fromList(ascii.encode(text));
}

/// Status and headers of an HTTP/1.1 response, before the capsule bytes.
({int status, Map<String, String> headers, int consumed})?
parseHttp1UpgradeResponse(Uint8List wire) {
  final text = ascii.decode(wire, allowInvalid: true);
  final split = text.indexOf('\r\n\r\n');
  if (split < 0) return null;
  final lines = text.substring(0, split).split('\r\n');
  if (lines.isEmpty || !lines.first.startsWith('HTTP/1.1 ')) return null;
  final status = int.tryParse(lines.first.split(' ')[1]);
  if (status == null) return null;
  final headers = <String, String>{};
  for (final line in lines.skip(1)) {
    final colon = line.indexOf(':');
    if (colon <= 0) return null;
    headers[line.substring(0, colon).trim().toLowerCase()] = line
        .substring(colon + 1)
        .trim();
  }
  return (status: status, headers: headers, consumed: split + 4);
}

bool http1UpgradeAccepted(
  ({int status, Map<String, String> headers, int consumed}) response,
  String protocol,
) {
  final upgrade = response.headers['upgrade']?.toLowerCase();
  return response.status >= 200 &&
      response.status < 300 &&
      response.headers['capsule-protocol'] == '?1' &&
      upgrade == protocol;
}

/// One CONNECT-UDP flow on an HTTP/3 session. Context ID 0 only.
/// A payload longer than 65527 bytes aborts the stream (RFC 9298).
final class PqConnectUdpTunnel {
  PqConnectUdpTunnel(this.session, this.streamId);

  final PqHttp3Session session;
  final int streamId;

  static const int maxPayload = 65527;

  Future<Result<void, PqTransportError>> send(Uint8List udpPayload) async {
    if (udpPayload.length > maxPayload) {
      await session.conn.resetStream(streamId, http3ErrorMessage);
      return Result.failure(PqTransportError.decodeFailure('udp payload'));
    }
    final body = encodeProxyDatagram(0, udpPayload);
    if (session.quicHttpDatagrams) {
      return session.sendHttpDatagram(streamId, body);
    }
    return session.sendDatagramCapsule(streamId, body);
  }

  /// Context ID 0 payloads. Other context IDs are dropped.
  List<Uint8List> take() {
    final out = <Uint8List>[];
    for (final payload in session.takeStreamDatagrams(streamId)) {
      final parsed = decodeProxyDatagram(payload);
      if (parsed == null || parsed.contextId != 0) continue;
      if (parsed.payload.length > maxPayload) continue;
      out.add(parsed.payload);
    }
    return out;
  }
}
