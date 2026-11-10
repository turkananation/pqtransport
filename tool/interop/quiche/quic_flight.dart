import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

import 'package:pqforge/pqforge.dart';
import 'package:pqtransport/pqtransport_io.dart';
import 'package:swissarmyknife/swissarmyknife.dart';

/// quiche client against [PqQuicConn.server].
///
/// The client chooses both connection IDs. This process does not tell
/// it those values. The certificate is an ML-DSA-65 leaf for localhost.
/// quiche verifies it. Group is X25519MLKEM768. Not HTTP/3.
Future<void> main(List<String> args) async {
  if (args.length != 1) {
    stderr.writeln(
      'usage: dart run tool/interop/quiche/quic_flight.dart <quiche_peer>',
    );
    exitCode = 64;
    return;
  }
  final peerBin = args.single;
  final crypto = const PqTransportCrypto();
  final minted = _mint(crypto);
  final dir = await Directory.systemTemp.createTemp('pq-quiche-');
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
    final wire = datagram.data;
    unawaited(() async {
      final got = await conn.ingestDatagram(wire);
      stderr.writeln(
        got.isFailure
            ? 'ingest ${got.errorOrNull}'
            : 'ingest ok complete=${conn.isComplete} ${conn.connectionState}',
      );
    }());
  });
  final process = await Process.start(peerBin, [
    'client',
    '127.0.0.1:${channel.port}',
    caPath,
  ]);
  var established = false;
  void note(List<int> bytes) {
    final text = String.fromCharCodes(bytes);
    stderr.write(text);
    if (text.contains('established peer_cert=')) {
      final match = RegExp(r'established peer_cert=(\d+)').firstMatch(text);
      final length = int.tryParse(match?.group(1) ?? '') ?? 0;
      if (length > 0) established = true;
    }
  }

  process.stdout.listen(note);
  process.stderr.listen(note);
  final poll = Timer.periodic(const Duration(milliseconds: 50), (_) {
    if (conn.isComplete && established) process.kill();
  });
  final timer = Timer(const Duration(seconds: 20), process.kill);
  final code = await process.exitCode;
  poll.cancel();
  timer.cancel();
  final handshakeOk = conn.isComplete && established;
  stderr.writeln(
    'quiche exit $code complete=${conn.isComplete} '
    '${conn.connectionState} verified=$established',
  );
  loss.cancel();
  await sub.cancel();
  await channel.close();
  await dir.delete(recursive: true);
  if (!handshakeOk) exitCode = 1;
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
