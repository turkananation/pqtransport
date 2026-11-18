import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

import 'package:pqforge/pqforge.dart';
import 'package:pqtransport/pqtransport_io.dart';
import 'package:swissarmyknife/swissarmyknife.dart';

/// noq 1.5.0 client (`bb1c63ee`) against [PqQuicConn.server].
///
/// The peer is rustls 0.23.46 on aws-lc-rs. It verifies the ML-DSA-65
/// leaf. Multipath is `max_concurrent_multipath_paths(2)`, which sends
/// `initial_max_path_id` 1. Exit 0 only when that process prints a
/// completed handshake and an established path.
Future<void> main(List<String> args) async {
  if (args.length != 1) {
    stderr.writeln(
      'usage: dart run tool/interop/noq/quic_flight.dart <pq_noq_client>',
    );
    exitCode = 64;
    return;
  }
  final demo = args.single;
  final crypto = const PqTransportCrypto();
  final minted = _mint(crypto);
  final dir = await Directory.systemTemp.createTemp('pq-noq-');
  final caPath = '${dir.path}/ca.pem';
  await File(caPath).writeAsString(minted.caPem);
  final channel = await IoDatagramChannel.bind(InternetAddress.loopbackIPv4, 0);
  final peers = <int, PqEndpoint>{};
  PqQuicConn? conn;
  int pathOf(Uint8List data) {
    final paths = conn?.multipath;
    if (data.isEmpty || (data[0] & 0x80) != 0 || paths == null) return 0;
    final n = conn!.localCid.length;
    if (data.length < 1 + n) return 0;
    return paths.pathForCid(Uint8List.sublistView(data, 1, 1 + n)) ?? 0;
  }

  var packets = 0;
  var sent = 0;
  var errors = 0;
  String? firstError;
  conn = PqQuicConn.server(
    crypto: crypto,
    identity: minted.identity,
    alpnProtocols: const ['h3'],
    initialMaxPathId: 4,
    deliverOnPath: (packet, pathId) {
      sent++;
      final to = peers[pathId] ?? peers[0];
      if (to == null) {
        firstError ??= 'no peer for path $pathId';
        return Future.value(Result.failure(PqTransportError.closed('quic')));
      }
      return channel.send(packet, to);
    },
  );
  final loss = conn.bindLossTimer();
  final sub = channel.incoming.listen((datagram) {
    packets++;
    final path = pathOf(datagram.data);
    peers[path] = datagram.peer;
    unawaited(() async {
      final got = await conn!.ingestDatagram(datagram.data);
      if (got.isFailure) {
        final why = '${got.errorOrNull}';
        if (why.contains('peer close 0 ')) return;
        errors++;
        firstError ??= why;
        stderr.writeln('noq ingest $why');
      }
    }());
  });
  final process = await Process.start(demo, [
    '127.0.0.1:${channel.port}',
    caPath,
  ]);
  final output = StringBuffer();
  process.stdout.listen((bytes) {
    final text = String.fromCharCodes(bytes);
    stdout.write(text);
    output.write(text);
  });
  process.stderr.listen((bytes) {
    stderr.write(String.fromCharCodes(bytes));
  });
  final timer = Timer(const Duration(seconds: 12), process.kill);
  final code = await process.exitCode;
  timer.cancel();
  await Future<void>.delayed(const Duration(milliseconds: 300));
  loss.cancel();
  await sub.cancel();
  await channel.close();
  if (!conn.isClosed) {
    await conn.close(errorCode: 0, application: true);
  }
  await dir.delete(recursive: true);
  final text = output.toString();
  if (code != 0 || !text.contains('noq-mp handshake=ok multipath=1 path=')) {
    stderr.writeln(
      'noq exit $code packets=$packets sent=$sent errors=$errors '
      'complete=${conn.isComplete} group=${conn.negotiatedGroupName} '
      'alpn=${conn.alpn} issued=${conn.multipath?.issuedPathByCid.length} '
      'limit=${conn.multipath?.openLimit} '
      'peerPath=${conn.peerInitialMaxPathId} ${firstError ?? ''}',
    );
    exitCode = 1;
  }
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
