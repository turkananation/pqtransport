import 'dart:io';
import 'dart:typed_data';

import 'package:pqtransport/pqtransport.dart';

/// Writes the DoH fixture used by [run.sh].
///
/// `query`  — DNS query bytes on stdout
/// `answer` — the A 9.9.9.9 response the h2c server must return
/// `b64`    — unpadded base64url of the query, plus a newline
void main(List<String> args) {
  final query = encodeDnsMessage(
    const DnsMessage(
      id: 0x4411,
      questions: [DnsQuestion(name: 'curl.example.', type: DnsType.a)],
    ),
  ).valueOrNull!;
  switch (args.single) {
    case 'query':
      stdout.add(query);
    case 'answer':
      stdout.add(
        encodeDnsMessage(
          DnsMessage(
            id: 0x4411,
            flags: 0x8180,
            questions: const [
              DnsQuestion(name: 'curl.example.', type: DnsType.a),
            ],
            answers: [
              DnsA(
                name: 'curl.example.',
                address: Uint8List.fromList([9, 9, 9, 9]),
                ttl: 15,
              ),
            ],
          ),
        ).valueOrNull!,
      );
    case 'b64':
      stdout.writeln(dohBase64Url(query));
    default:
      stderr.writeln('usage: doh_fixture.dart query|answer|b64');
      exitCode = 2;
  }
}
