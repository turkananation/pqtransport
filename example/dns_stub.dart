import 'dart:io';
import 'dart:typed_data';

import 'package:pqtransport/pqtransport.dart';

/// In-memory DNS stub. No sockets.
///
/// `exchange` and `tcp` return the raw DNS message. The client sets RD,
/// DO, and CD, matches the id, retries TC over `tcp`, and retries
/// BADCOOKIE. `lookup` returns that one message. `resolve` follows
/// CNAME. Neither checks a signature. That is `example/dns_validate.dart`.
/// A live resolver is `example/dns_live.dart`.
Future<void> main() async {
  var tcpCalls = 0;
  final dns = PqDnsClient(
    exchange: _udp,
    tcp: (query) async {
      tcpCalls++;
      return _reply(query, truncated: false);
    },
  );

  final one = await dns.lookup('alias.example.', DnsType.a);
  final cname = one.valueOrNull?.answers.whereType<DnsCname>().singleOrNull;
  if (one.isFailure || cname?.canonical != 'target.example.') {
    stderr.writeln('lookup should stop at the CNAME: ${one.errorOrNull}');
    exitCode = 1;
    return;
  }

  final chased = await dns.resolve('alias.example.', DnsType.a);
  final address = chased.valueOrNull?.answers.whereType<DnsA>().singleOrNull;
  if (chased.isFailure || address?.address.toString() != '[192, 0, 2, 1]') {
    stderr.writeln('resolve should follow the CNAME: ${chased.errorOrNull}');
    exitCode = 1;
    return;
  }

  final wide = await dns.lookup('wide.example.', DnsType.a);
  final wideA = wide.valueOrNull?.answers.whereType<DnsA>().singleOrNull;
  if (wide.isFailure || tcpCalls != 1 || wideA == null) {
    stderr.writeln('TC must be retried once over TCP: ${wide.errorOrNull}');
    exitCode = 1;
    return;
  }

  stdout.writeln(
    'dns stub: lookup stopped at ${cname!.canonical}; '
    'resolve returned ${address!.address}; tcp retries $tcpCalls',
  );
}

Future<Uint8List> _udp(Uint8List query) async =>
    _reply(query, truncated: dnsNamesEqual(_name(query), 'wide.example.'));

Uint8List _reply(Uint8List query, {required bool truncated}) {
  final msg = decodeDnsMessage(query).valueOrNull!;
  final name = msg.questions.single.name;
  final answers = <DnsRecord>[];
  if (!truncated && name == 'alias.example.') {
    answers.add(DnsCname(name: name, canonical: 'target.example.', ttl: 30));
  } else if (!truncated) {
    answers.add(
      DnsA(
        name: name,
        address: Uint8List.fromList(const [192, 0, 2, 1]),
        ttl: 30,
      ),
    );
  }
  return encodeDnsMessage(
    DnsMessage(
      id: msg.id,
      flags: 0x8000 | msg.flags | (truncated ? dnsFlagTc : 0),
      questions: msg.questions,
      answers: answers,
    ),
  ).valueOrNull!;
}

String _name(Uint8List query) =>
    decodeDnsMessage(query).valueOrNull!.questions.single.name;
