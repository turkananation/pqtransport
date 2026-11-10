import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

import 'package:pqforge/pqforge.dart';
import 'package:pqtransport/pqtransport.dart';
import 'package:pqtransport/pqtransport_io.dart';
import 'package:swissarmyknife/swissarmyknife.dart';

/// picoquic 1.1.54.0 client against [PqQuicConn.server].
///
/// Observed result, not a claim. The demo's ClientHello offers
/// ed25519, ECDSA, and RSA-PSS (0x0807, 0x0403, 0x0503, 0x0603,
/// 0x0806, 0x0805, 0x0804). It does not offer ML-DSA-65 (0x0905).
/// This server answers unsupported_certificate. With `-M` the demo
/// prints `Enable multipath: Refused` and uses one client port.
/// Exit 1 is that observation. The demo process status is not proof
/// either way. Do not mint a classical certificate to force a
/// handshake, and do not add this script to `run_all.sh`.
/// Picotls in that tree has no ML-DSA.
Future<void> main(List<String> args) async {
  if (args.length != 1) {
    stderr.writeln(
      'usage: dart run tool/interop/picoquic/quic_flight.dart <picoquicdemo>',
    );
    exitCode = 64;
    return;
  }
  final demo = args.single;
  final crypto = const PqTransportCrypto();
  final minted = _mint(crypto);
  final dir = await Directory.systemTemp.createTemp('pq-picoquic-');
  final caPath = '${dir.path}/ca.pem';
  await File(caPath).writeAsString(minted.caPem);
  final single = await _flight(
    demo: demo,
    caPath: caPath,
    identity: minted.identity,
    crypto: crypto,
    multipath: false,
  );
  final multi = await _flight(
    demo: demo,
    caPath: caPath,
    identity: minted.identity,
    crypto: crypto,
    multipath: true,
  );
  await dir.delete(recursive: true);
  stderr.writeln(
    'picoquic single complete=${single.complete} version=${single.sawVersion} '
    'ports=${single.ports} errors=${single.errors}',
  );
  stderr.writeln(
    'picoquic multi complete=${multi.complete} negotiated=${multi.negotiated} '
    'enable=${multi.enableLine} ports=${multi.ports} errors=${multi.errors}',
  );
  if (!single.complete || !single.sawVersion) exitCode = 1;
  if (!multi.complete || multi.enableLine != 'Success' || multi.ports < 2) {
    exitCode = 1;
  }
}

class _Result {
  var complete = false;
  var negotiated = false;
  var sawVersion = false;
  var ports = 0;
  var errors = 0;
  String? enableLine;
}

Future<_Result> _flight({
  required String demo,
  required String caPath,
  required PqTlsServerIdentity identity,
  required PqTransportCrypto crypto,
  required bool multipath,
}) async {
  final result = _Result();
  final channel = await IoDatagramChannel.bind(InternetAddress.loopbackIPv4, 0);
  final ports = <int>{};
  PqEndpoint? peer;
  final conn = PqQuicConn.server(
    crypto: crypto,
    identity: identity,
    alpnProtocols: const ['h3'],
    initialMaxPathId: multipath ? 4 : null,
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
    ports.add(datagram.peer.port);
    unawaited(() async {
      final got = await conn.ingestDatagram(datagram.data);
      if (got.isFailure) {
        result.errors++;
        if (result.errors == 1) {
          stderr.writeln(
            'pico ingest ${got.errorOrNull} '
            'len=${datagram.data.length} '
            'first=0x${datagram.data[0].toRadixString(16)}',
          );
        }
      }
    }());
  });
  final process = await Process.start(demo, [
    '-n',
    'localhost',
    '-a',
    'h3',
    '-t',
    caPath,
    '-l',
    '-',
    '-d',
    '2000',
    if (multipath) ...['-M', '-A', '0.0.0.0/0'],
    '127.0.0.1',
    '${channel.port}',
  ]);
  final output = StringBuffer();
  void note(List<int> bytes) {
    final text = String.fromCharCodes(bytes);
    stderr.write(text);
    output.write(text);
  }

  process.stdout.listen(note);
  process.stderr.listen(note);
  final timer = Timer(const Duration(seconds: 8), process.kill);
  await process.exitCode;
  timer.cancel();
  result.complete = conn.isComplete;
  result.negotiated = conn.multipathNegotiated;
  result.ports = ports.length;
  final text = output.toString();
  result.sawVersion = text.contains('Starting Picoquic (v1.1.54.0)');
  final enable = RegExp(r'Enable multipath: (\w+)').firstMatch(text);
  result.enableLine = enable?.group(1);
  loss.cancel();
  await sub.cancel();
  await channel.close();
  if (!conn.isClosed) {
    await conn.close(errorCode: 0, application: true);
  }
  return result;
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
        crypto.mlDsaSign(secretKey: leafKeys.secretKey, message: tbs),
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
