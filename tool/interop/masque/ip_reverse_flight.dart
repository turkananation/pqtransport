import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:pqtransport/pqtransport.dart';
import 'package:pqtransport/pqtransport_io.dart';
import 'package:swissarmyknife/swissarmyknife.dart';

import 'openssl_leaf.dart';

/// CONNECT-IP client against connect-ip-go v0.6.0.
///
/// The proxy assigns 192.0.2.11/32 and advertises every IPv4 route.
/// One context-ID-0 IPv4 packet is accepted by its filter and the
/// reply is addressed to that assignment. The leaf is ML-DSA-65.
Future<void> main(List<String> args) async {
  if (args.length != 1) {
    stderr.writeln(
      'usage: dart run tool/interop/masque/ip_reverse_flight.dart <ip-proxy>',
    );
    exitCode = 64;
    return;
  }
  final proxyBin = args.single;
  final leaf = await mintOpensslLeaf(
    openssl: 'tool/interop/openssl/.build/bin/openssl',
    conf: 'tool/interop/openssl/openssl.cnf',
    lib: 'tool/interop/openssl/.build/lib',
  );
  final process = await Process.start(proxyBin, [
    '-b',
    '127.0.0.1:0',
    '-c',
    leaf.certPath,
    '-k',
    leaf.keyPath,
  ]);
  final output = StringBuffer();
  final listening = Completer<int>();
  void note(List<int> bytes) {
    final text = utf8.decode(bytes, allowMalformed: true);
    stderr.write(text);
    output.write(text);
    if (!listening.isCompleted) {
      final match = RegExp(r'listening \S+:(\d+)').firstMatch(text);
      if (match != null) listening.complete(int.parse(match.group(1)!));
    }
  }

  process.stdout.listen(note);
  process.stderr.listen(note);
  IoDatagramChannel? channel;
  StreamSubscription<PqDatagramIn>? sub;
  QuicLossSubscription? loss;
  try {
    final port = await listening.future.timeout(const Duration(seconds: 10));
    channel = await IoDatagramChannel.bind(InternetAddress.loopbackIPv4, 0);
    final peer = PqEndpoint('127.0.0.1', port);
    final conn = PqQuicConn.client(
      alpnProtocols: const ['h3'],
      certificateTypes: const [TlsCertificateType.x509],
      trustAnchors: [leaf.caDer],
      serverName: 'localhost',
      signatureSchemes: const [tlsSignatureMldsa65],
      deliver: (packet) => channel!.send(packet, peer),
    );
    loss = conn.bindLossTimer();
    sub = channel.incoming.listen((datagram) {
      unawaited(conn.ingestDatagram(datagram.data));
    });
    final started = await conn.start();
    if (started.isFailure) {
      stderr.writeln('start ${started.errorOrNull}');
      exitCode = 1;
      return;
    }
    final deadline = DateTime.now().add(const Duration(seconds: 15));
    while (!conn.isComplete && DateTime.now().isBefore(deadline)) {
      await Future<void>.delayed(const Duration(milliseconds: 20));
    }
    if (!conn.isComplete ||
        !conn.peerAuthenticated ||
        conn.peerLeafAlgorithm != 'mlDsa65' ||
        conn.negotiatedGroupName != 'x25519MlKem768') {
      stderr.writeln(
        'handshake complete=${conn.isComplete} '
        'auth=${conn.peerAuthenticated} leaf=${conn.peerLeafAlgorithm} '
        'group=${conn.negotiatedGroupName} ${conn.connectionState}',
      );
      exitCode = 1;
      return;
    }
    final session = PqHttp3Session.client(conn);
    final request = connectIpRequest(
      proxyHost: '127.0.0.1',
      proxyPort: port,
      target: '*',
      ipProtocol: '*',
    );
    if (request.isFailure) {
      stderr.writeln('request ${request.errorOrNull}');
      exitCode = 1;
      return;
    }
    stderr.writeln('path ${request.valueOrNull!.uri.path}');
    final opened = await session.beginRequest(
      request.valueOrNull!,
      fin: false,
    );
    if (opened.isFailure) {
      stderr.writeln('begin ${opened.errorOrNull}');
      exitCode = 1;
      return;
    }
    final id = opened.valueOrNull!;
    final response = await session.readResponse(id, untilFin: false);
    if (response.isFailure || response.valueOrNull!.status != 200) {
      stderr.writeln(
        'status ${response.isSuccess ? response.valueOrNull!.status : response.errorOrNull}',
      );
      exitCode = 1;
      return;
    }
    final until = DateTime.now().add(const Duration(seconds: 8));
    AssignedAddress? assigned;
    IpRange? route;
    while (DateTime.now().isBefore(until) && (assigned == null || route == null)) {
      final pumped = await session.receive();
      if (pumped.isFailure) {
        stderr.writeln('receive ${pumped.errorOrNull}');
        exitCode = 1;
        return;
      }
      for (final capsule in session.takeCapsules(id)) {
        if (capsule.type == 0x01 && assigned == null) {
          final decoded = decodeAddressAssign(capsule.value);
          if (decoded.isSuccess && decoded.valueOrNull!.isNotEmpty) {
            assigned = decoded.valueOrNull!.first;
          }
        } else if (capsule.type == 0x03 && route == null) {
          final decoded = decodeRouteAdvertisement(capsule.value);
          if (decoded.isSuccess && decoded.valueOrNull!.isNotEmpty) {
            route = decoded.valueOrNull!.first;
          }
        }
      }
      await Future<void>.delayed(const Duration(milliseconds: 20));
    }
    final prefix = assigned?.prefix;
    if (prefix == null ||
        prefix.version != 4 ||
        prefix.prefixLength != 32 ||
        !_bytes(prefix.address, const [192, 0, 2, 11]) ||
        route == null ||
        route.protocol != 0) {
      stderr.writeln(
        'capsules assign=${prefix?.address} /${prefix?.prefixLength} '
        'route=${route?.protocol}',
      );
      exitCode = 1;
      return;
    }
    final sent = await session.sendHttpDatagram(
      id,
      encodeProxyDatagram(
        0,
        _ipv4(const [192, 0, 2, 11], const [198, 51, 100, 1], 17),
      ),
    );
    if (sent.isFailure) {
      stderr.writeln('send ${sent.errorOrNull}');
      exitCode = 1;
      return;
    }
    final replyUntil = DateTime.now().add(const Duration(seconds: 8));
    Uint8List? reply;
    while (DateTime.now().isBefore(replyUntil) && reply == null) {
      final pumped = await session.receive();
      if (pumped.isFailure) {
        stderr.writeln('receive ${pumped.errorOrNull}');
        break;
      }
      for (final payload in session.takeStreamDatagrams(id)) {
        final parsed = decodeProxyDatagram(payload);
        if (parsed != null && parsed.contextId == 0) reply = parsed.payload;
      }
      await Future<void>.delayed(const Duration(milliseconds: 20));
    }
    final text = output.toString();
    final echoed = reply != null &&
        reply.length >= 20 &&
        _bytes(reply.sublist(12, 16), const [198, 51, 100, 1]) &&
        _bytes(reply.sublist(16, 20), const [192, 0, 2, 11]);
    stderr.writeln(
      'reverse-ip leaf=${conn.peerLeafAlgorithm} group=${conn.negotiatedGroupName} '
      'echoed=$echoed quicDatagrams=${session.quicHttpDatagrams}',
    );
    if (!echoed ||
        !session.quicHttpDatagrams ||
        !text.contains('ip-got n=20 src=192.0.2.11 dst=198.51.100.1 proto=17') ||
        !text.contains('ip-echo n=20')) {
      exitCode = 1;
    }
  } finally {
    process.kill();
    await sub?.cancel();
    loss?.cancel();
    await channel?.close();
    await leaf.directory.delete(recursive: true);
  }
}

bool _bytes(List<int> got, List<int> want) {
  if (got.length != want.length) return false;
  for (var i = 0; i < got.length; i++) {
    if (got[i] != want[i]) return false;
  }
  return true;
}

Uint8List _ipv4(List<int> src, List<int> dst, int proto) {
  final h = Uint8List(20);
  h[0] = 0x45;
  h[3] = 20;
  h[8] = 64;
  h[9] = proto;
  h.setRange(12, 16, src);
  h.setRange(16, 20, dst);
  var sum = 0;
  for (var i = 0; i < 20; i += 2) {
    sum += (h[i] << 8) | h[i + 1];
  }
  while (sum > 0xffff) {
    sum = (sum & 0xffff) + (sum >> 16);
  }
  final checksum = ~sum & 0xffff;
  h[10] = (checksum >> 8) & 0xff;
  h[11] = checksum & 0xff;
  return h;
}
