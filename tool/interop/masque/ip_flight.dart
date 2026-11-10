import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

import 'package:pqforge/pqforge.dart';
import 'package:pqtransport/pqtransport.dart';
import 'package:pqtransport/pqtransport_io.dart';
import 'package:swissarmyknife/swissarmyknife.dart';

/// connect-ip-go CONNECT-IP client against [PqHttp3Session].
///
/// The proxy assigns 192.0.2.11/32, advertises every IPv4 route, and
/// echoes one context-ID-0 IP packet. connect-ip-go checks ML-DSA-65.
Future<void> main(List<String> args) async {
  if (args.length != 1) {
    stderr.writeln(
      'usage: dart run tool/interop/masque/ip_flight.dart <ip-client>',
    );
    exitCode = 64;
    return;
  }
  final clientBin = args.single;
  final crypto = const PqTransportCrypto();
  final minted = _mint(crypto);
  final dir = await Directory.systemTemp.createTemp('pq-connect-ip-');
  final caPath = '${dir.path}/ca.pem';
  await File(caPath).writeAsString(minted.caPem);
  final channel = await IoDatagramChannel.bind(InternetAddress.loopbackIPv4, 0);
  PqEndpoint? peer;
  final conn = PqQuicConn.server(
    crypto: crypto,
    identity: minted.identity,
    alpnProtocols: const ['h3'],
    deliver: (packet) {
      final to = peer;
      if (to == null) {
        return Future.value(Result.failure(PqTransportError.closed('quic')));
      }
      return channel.send(packet, to);
    },
  );
  final loss = conn.bindLossTimer();
  final sub = channel.incoming.listen((datagram) {
    peer = datagram.peer;
    unawaited(() async {
      final got = await conn.ingestDatagram(datagram.data);
      if (got.isFailure) stderr.writeln('ingest ${got.errorOrNull}');
    }());
  });
  final served = _serve(conn);
  final process = await Process.start(clientBin, [
    '-proxy',
    '127.0.0.1:${channel.port}',
    '-ca',
    caPath,
  ]);
  final output = StringBuffer();
  void note(List<int> bytes) {
    final text = String.fromCharCodes(bytes);
    stderr.write(text);
    output.write(text);
  }

  process.stdout.listen(note);
  process.stderr.listen(note);
  final timer = Timer(const Duration(seconds: 25), process.kill);
  final code = await process.exitCode;
  timer.cancel();
  final forwarded = await served;
  loss.cancel();
  await sub.cancel();
  await channel.close();
  await dir.delete(recursive: true);
  final text = output.toString();
  final line = text.contains(
    'connect-ip status=200 assign=192.0.2.11/32 echo=20 peer=ML-DSA-65',
  );
  stderr.writeln(
    'connect-ip-go exit $code forwarded=$forwarded line=$line '
    'complete=${conn.isComplete}',
  );
  if (code != 0 || !forwarded || !line || !conn.isComplete) exitCode = 1;
}

Future<bool> _serve(PqQuicConn conn) async {
  final deadline = DateTime.now().add(const Duration(seconds: 20));
  while (!conn.isComplete && DateTime.now().isBefore(deadline)) {
    await Future<void>.delayed(const Duration(milliseconds: 20));
  }
  if (!conn.isComplete) return false;
  final session = PqHttp3Session.server(conn);
  final accepted = await session.accept(
    untilFin: false,
    timeout: const Duration(seconds: 15),
  );
  if (accepted.isFailure) {
    stderr.writeln('accept ${accepted.errorOrNull}');
    return false;
  }
  final (id, request) = accepted.valueOrNull!;
  if (request.method != 'CONNECT' ||
      request.protocol != 'connect-ip' ||
      request.uri.path != '/.well-known/masque/ip/*/*/') {
    stderr.writeln(
      'unexpected ${request.method} ${request.protocol} ${request.uri}',
    );
    return false;
  }
  if (request.headers['capsule-protocol'] != '?1') {
    stderr.writeln('capsule-protocol ${request.headers}');
    return false;
  }
  final sent = await session.respond(
    id,
    PqHttpResponse(
      status: 200,
      headers: const {'capsule-protocol': '?1'},
      body: Uint8List(0),
      version: HttpVersion.h3,
    ),
    fin: false,
  );
  if (sent.isFailure) {
    stderr.writeln('respond ${sent.errorOrNull}');
    return false;
  }
  final assign = addressAssignCapsule([
    AssignedAddress(
      requestId: 0,
      prefix: IpPrefix(
        version: 4,
        address: Uint8List.fromList([192, 0, 2, 11]),
        prefixLength: 32,
      ),
    ),
  ]);
  final routes = routeAdvertisementCapsule([
    IpRange(
      version: 4,
      start: Uint8List.fromList([0, 0, 0, 0]),
      end: Uint8List.fromList([255, 255, 255, 255]),
      protocol: 0,
    ),
  ]);
  final policy = IpProxyPolicy()
    ..assign(assign.value)
    ..advertise(routes.value);
  final assigned = await session.sendCapsule(id, assign);
  if (assigned.isFailure) {
    stderr.writeln('assign ${assigned.errorOrNull}');
    return false;
  }
  final advertised = await session.sendCapsule(id, routes);
  if (advertised.isFailure) {
    stderr.writeln('routes ${advertised.errorOrNull}');
    return false;
  }
  final until = DateTime.now().add(const Duration(seconds: 10));
  while (DateTime.now().isBefore(until)) {
    final pumped = await session.receive();
    if (pumped.isFailure) {
      stderr.writeln('receive ${pumped.errorOrNull}');
      return false;
    }
    for (final payload in session.takeStreamDatagrams(id)) {
      final parsed = decodeProxyDatagram(payload);
      if (parsed == null || parsed.contextId != 0) continue;
      if (!policy.allow(parsed.payload)) {
        stderr.writeln('dropped ip packet');
        continue;
      }
      final reply = _reply(parsed.payload);
      final back = await session.sendHttpDatagram(
        id,
        encodeProxyDatagram(0, reply),
      );
      if (back.isFailure) {
        stderr.writeln('echo ${back.errorOrNull}');
        return false;
      }
      return true;
    }
    await Future<void>.delayed(const Duration(milliseconds: 10));
  }
  stderr.writeln('no connect-ip packet');
  return false;
}

/// A packet back to the assigned address. The source is the original
/// destination, so the client accepts it under RFC 9484.
Uint8List _reply(Uint8List packet) {
  final out = Uint8List.fromList(packet);
  final source = Uint8List.sublistView(out, 12, 16);
  final destination = Uint8List.sublistView(out, 16, 20);
  final swappedSource = Uint8List.fromList(destination);
  out.setRange(16, 20, source);
  out.setRange(12, 16, swappedSource);
  out[10] = 0;
  out[11] = 0;
  var sum = 0;
  for (var i = 0; i < 20; i += 2) {
    sum += (out[i] << 8) | out[i + 1];
  }
  while (sum > 0xffff) {
    sum = (sum & 0xffff) + (sum >> 16);
  }
  final checksum = ~sum & 0xffff;
  out[10] = (checksum >> 8) & 0xff;
  out[11] = checksum & 0xff;
  return out;
}

({PqTlsServerIdentity identity, String caPem}) _mint(PqTransportCrypto crypto) {
  final now = DateTime.now().toUtc();
  final notBefore = now.subtract(const Duration(hours: 1));
  final notAfter = now.add(const Duration(days: 1));
  final rootKeys = crypto.mlDsaKeyGen();
  final rootName = PqX509Name.commonName('pqtransport-ca');
  final rootKey = PqX509MlDsaKey(PqX509Algorithm.mlDsa65, rootKeys.publicKey);
  final root = PqX509.mint(
    issuer: rootName,
    subject: rootName,
    publicKey: rootKey,
    algorithm: PqX509Algorithm.mlDsa65,
    sign: (tbs) =>
        crypto.mlDsaSign(secretKey: rootKeys.secretKey, message: tbs),
    notBefore: notBefore,
    notAfter: notAfter,
    serial: Uint8List.fromList([1]),
    ca: true,
    keyCertSign: true,
    includeEku: false,
  );
  final leafKeys = crypto.mlDsaKeyGen();
  final leafKey = PqX509MlDsaKey(PqX509Algorithm.mlDsa65, leafKeys.publicKey);
  final leaf = PqX509.mint(
    issuer: rootName,
    subject: PqX509Name.commonName('localhost'),
    publicKey: leafKey,
    algorithm: PqX509Algorithm.mlDsa65,
    sign: (tbs) =>
        crypto.mlDsaSign(secretKey: rootKeys.secretKey, message: tbs),
    notBefore: notBefore,
    notAfter: notAfter,
    serial: Uint8List.fromList([2]),
    subjectAltNames: const [PqX509DnsName('localhost')],
  );
  return (
    identity: PqTlsServerIdentity.x509(
      leafKey: leafKey,
      sign: (content) =>
          crypto.mlDsaSign(secretKey: leafKeys.secretKey, message: content),
      chain: [leaf],
      certificateDnsName: 'localhost',
    ),
    caPem: PqX509.toPem(root),
  );
}
