import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

import 'package:pqforge/pqforge.dart';
import 'package:pqtransport/pqtransport_io.dart';
import 'package:swissarmyknife/swissarmyknife.dart';

/// OpenSSL 3.5 `s_client -quic` against [PqQuicConn].
///
/// The client chooses both connection IDs. This process does not tell
/// it those values. The certificate is an ML-DSA-65 leaf for localhost.
Future<void> main(List<String> args) async {
  if (args.length != 1) {
    stderr.writeln(
      'usage: dart run tool/interop/openssl/quic_flight.dart <openssl>',
    );
    exitCode = 64;
    return;
  }
  final openssl = args.single;
  final crypto = const PqTransportCrypto();
  final minted = _mint(crypto);
  final dir = await Directory.systemTemp.createTemp('pq-quic-');
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
      final first = packet.isEmpty ? 0 : packet[0];
      stderr.writeln(
        'send ${packet.length} first=0x${first.toRadixString(16)} '
        'to ${to?.port} head=${_hex(packet, 24)}',
      );
      if (to == null) {
        return Future.value(Result.failure(PqTransportError.closed('quic')));
      }
      return channel.send(packet, to);
    },
  );
  final sub = channel.incoming.listen((datagram) {
    peer = datagram.peer;
    final wire = datagram.data;
    final first = wire.isEmpty ? 0 : wire[0];
    stderr.writeln(
      'udp ${wire.length} first=0x${first.toRadixString(16)} '
      'from ${datagram.peer.port} '
      'head=${_hex(wire, 24)}',
    );
    unawaited(() async {
      final got = await conn.ingestDatagram(wire);
      stderr.writeln(
        got.isFailure
            ? 'ingest ${got.errorOrNull}'
            : 'ingest ok complete=${conn.isComplete} ${conn.connectionState}',
      );
    }());
  });
  final process = await Process.start(
    openssl,
    [
      's_client',
      '-quic',
      '-connect',
      '127.0.0.1:${channel.port}',
      '-servername',
      'localhost',
      '-alpn',
      'h3',
      '-groups',
      'X25519MLKEM768',
      '-sigalgs',
      'mldsa65',
      '-CAfile',
      caPath,
      '-verify_return_error',
      '-brief',
    ],
    environment: {...Platform.environment, 'LD_LIBRARY_PATH': _libDir(openssl)},
  );
  var verified = false;
  void note(List<int> bytes) {
    final text = String.fromCharCodes(bytes);
    stderr.write(text);
    if (text.contains('Verification: OK')) verified = true;
  }

  process.stdout.listen(note);
  process.stderr.listen(note);
  final poll = Timer.periodic(const Duration(milliseconds: 50), (_) {
    if (conn.isComplete && verified) process.kill();
  });
  final timer = Timer(const Duration(seconds: 8), process.kill);
  final code = await process.exitCode;
  poll.cancel();
  timer.cancel();
  final handshakeOk = conn.isComplete && verified;
  stderr.writeln(
    'openssl exit $code complete=${conn.isComplete} '
    '${conn.connectionState} verified=$verified',
  );
  await sub.cancel();
  await channel.close();
  await dir.delete(recursive: true);
  if (!handshakeOk) {
    exitCode = 1;
  }
}

String _hex(Uint8List bytes, int n) {
  final end = bytes.length < n ? bytes.length : n;
  return [
    for (var i = 0; i < end; i++) bytes[i].toRadixString(16).padLeft(2, '0'),
  ].join();
}

String _libDir(String opensslBin) {
  final bin = File(opensslBin).absolute.path;
  return '${bin.substring(0, bin.lastIndexOf('/bin/'))}/lib';
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
