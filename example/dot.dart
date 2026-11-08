import 'dart:io';
import 'dart:typed_data';

import 'package:pqtransport/pqtransport.dart';
import 'package:swissarmyknife/swissarmyknife.dart';

/// DNS-over-TLS. The handshake must select ALPN `dot`.
///
/// The DNS message is prefixed with a 2-byte length (`encodeDnsTcp`).
/// `DotClient` reads that framing. The same prefix is the TCP retry
/// under `PqDnsClient`. A socket whose ALPN is not `dot` fails closed.
Future<void> main() async {
  final crypto = PqTransportCrypto();
  final identity = PqTlsServerIdentity.generate(crypto);
  final (a, b) = MemoryByteSocket.pair();
  final client = PqTlsSocket.client(
    a,
    crypto: crypto,
    alpnProtocols: const [dnsAlpnDot],
  );
  final server = PqTlsSocket.server(
    b,
    crypto: crypto,
    identity: identity,
    alpnProtocols: const [dnsAlpnDot],
  );
  final query = encodeDnsMessage(
    DnsMessage(
      id: 0x0d07,
      questions: [DnsQuestion(name: 'www.example.', type: DnsType.a)],
    ),
  ).valueOrNull!;
  final serving = () async {
    final reader = DnsTcpReader();
    await for (final chunk in server.applicationData) {
      reader.add(chunk);
      final q = reader.next();
      if (q == null) continue;
      return server.send(encodeDnsTcp(answerFor(q)));
    }
    return Result<void, PqTransportError>.failure(
      PqTransportError.decodeFailure('dot request'),
    );
  }();

  final hs = await Future.wait([server.handshake(), client.handshake()]);
  final dot = DotClient(client);
  final got = await dot.query(query);
  final served = await serving;
  final msg = got.isSuccess ? decodeDnsMessage(got.valueOrNull!) : null;
  final address = msg?.valueOrNull?.answers.whereType<DnsA>().singleOrNull;
  if (hs.any((r) => r.isFailure) ||
      client.alpn != dnsAlpnDot ||
      got.isFailure ||
      served.isFailure ||
      address == null) {
    stderr.writeln('dot failed: ${got.errorOrNull ?? served.errorOrNull}');
    exitCode = 1;
  } else {
    stdout.writeln('dot: A ${address.address}');
  }
  await dot.close();
  await client.close();
  await server.close();
}

Uint8List answerFor(Uint8List query) {
  final msg = decodeDnsMessage(query).valueOrNull!;
  return encodeDnsMessage(
    DnsMessage(
      id: msg.id,
      flags: 0x8180,
      questions: msg.questions,
      answers: [
        DnsA(
          name: msg.questions.single.name,
          address: Uint8List.fromList(const [192, 0, 2, 20]),
          ttl: 30,
        ),
      ],
    ),
  ).valueOrNull!;
}
