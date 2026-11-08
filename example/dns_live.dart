import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

import 'package:pqtransport/pqtransport.dart';
import 'package:swissarmyknife/swissarmyknife.dart';

/// Ask 1.1.1.1, then validate from the IANA root DS set.
///
/// Not run in CI. The root anchors below are the two digest-type-2
/// records in https://data.iana.org/root-anchors/root-anchors.xml
/// (tags 20326 and 38696). Replace them when IANA retires one.
///
/// `lookup` does not validate. `authenticateDns` does. The AD bit is
/// not read. A CNAME into an unsigned zone fails closed.
Future<void> main(List<String> args) async {
  final server = args.isEmpty ? '1.1.1.1' : args.first;
  final dns = PqDnsClient(
    exchange: (query) => _udp(server, query),
    tcp: (query) => _tcp(server, query),
  );
  const names = ['yardenah.com', 'www.yardenah.com', 'hardware.yardenah.com'];
  for (final name in names) {
    for (final type in const [DnsType.a, DnsType.aaaa]) {
      final got = await dns.lookup(name, type);
      if (got.isFailure) {
        stderr.writeln('$name ${type.name}: ${got.errorOrNull}');
        exitCode = 1;
        continue;
      }
      final msg = got.valueOrNull!;
      final ad = (msg.flags & 0x0020) != 0;
      stdout.writeln(
        '$name ${type.name}: rcode=${msg.rcode} ad=$ad '
        '${msg.answers.isEmpty ? 'nodata' : msg.answers.map(_show).join(' | ')}',
      );
    }
  }

  final anchor = DnsTrustAnchor.dsSet(
    zone: '.',
    ds: [_root(20326, _ksk2017), _root(38696, _ksk2024)],
  );
  for (final name in names) {
    final auth = await authenticateDns(
      name: name,
      type: DnsType.a,
      anchor: anchor,
      lookup: dns.lookup,
      now: DateTime.now().toUtc(),
    );
    stdout.writeln('$name A: ${_verdict(auth)}');
    if (name == 'yardenah.com' && auth.isFailure) exitCode = 1;
  }
}

const _ksk2017 =
    'E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D';
const _ksk2024 =
    '683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16';

DnsDs _root(int tag, String hex) {
  final digest = Uint8List(hex.length ~/ 2);
  for (var i = 0; i < digest.length; i++) {
    digest[i] = int.parse(hex.substring(i * 2, i * 2 + 2), radix: 16);
  }
  return DnsDs(
    name: '.',
    keyTag: tag,
    algorithm: dnssecAlgorithmRsaSha256,
    digestType: dnssecDigestSha256,
    digest: digest,
  );
}

String _v6(Uint8List address) {
  final parts = <String>[];
  for (var i = 0; i < 16; i += 2) {
    parts.add(((address[i] << 8) | address[i + 1]).toRadixString(16));
  }
  return parts.join(':');
}

String _verdict(Result<DnsAuth, PqTransportError> result) {
  if (result.isFailure) return 'not authenticated (${result.errorOrNull})';
  return switch (result.valueOrNull!) {
    DnsAuthData(:final records) => 'secure ${records.map(_show).join(' | ')}',
    DnsAuthDenial(:final nameError) =>
      nameError ? 'secure nxdomain' : 'secure nodata',
  };
}

String _show(DnsRecord rr) => switch (rr) {
  DnsA(:final address) => address.join('.'),
  DnsAaaa(:final address) => _v6(address),
  DnsCname(:final canonical) => 'cname $canonical',
  DnsRrsig(:final algorithm, :final keyTag) => 'rrsig $algorithm/$keyTag',
  _ => rr.type.name,
};

Future<Uint8List> _udp(String host, Uint8List query) async {
  final socket = await RawDatagramSocket.bind(InternetAddress.anyIPv4, 0);
  socket.send(query, InternetAddress(host), 53);
  final done = Completer<Uint8List>();
  socket.listen((event) {
    if (event != RawSocketEvent.read || done.isCompleted) return;
    final packet = socket.receive();
    if (packet != null) done.complete(Uint8List.fromList(packet.data));
  });
  try {
    return await done.future.timeout(const Duration(seconds: 8));
  } finally {
    socket.close();
  }
}

Future<Uint8List> _tcp(String host, Uint8List query) async {
  final socket = await Socket.connect(
    host,
    53,
    timeout: const Duration(seconds: 8),
  );
  final prefix = Uint8List(2);
  ByteData.sublistView(prefix).setUint16(0, query.length);
  socket.add([...prefix, ...query]);
  final got = BytesBuilder();
  await for (final chunk in socket.timeout(const Duration(seconds: 8))) {
    got.add(chunk);
    final bytes = got.toBytes();
    if (bytes.length < 2) continue;
    final size = ByteData.sublistView(bytes).getUint16(0);
    if (bytes.length >= 2 + size) {
      socket.destroy();
      return Uint8List.sublistView(bytes, 2, 2 + size);
    }
  }
  socket.destroy();
  throw StateError('short tcp dns from $host');
}
