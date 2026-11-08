import 'dart:io';
import 'dart:typed_data';

import 'package:pqtransport/pqtransport.dart';
import 'package:swissarmyknife/swissarmyknife.dart';

/// DNS-over-HTTPS, POST and GET, then `PqDnsResolver`.
///
/// The handshake selects ALPN `h2`. The template may end in `{?dns}`.
/// Any other `{` fails. `DohClient.h2(...).exchange` is what
/// `PqDnsResolver` calls. `lookup` still does not validate.
/// HTTP/3 is `DohClient.h3` on a `PqQuicConn` whose ALPN is `h3`.
Future<void> main() async {
  final crypto = PqTransportCrypto();
  final identity = PqTlsServerIdentity.generate(crypto);
  final (a, b) = MemoryByteSocket.pair();
  final client = PqTlsSocket.client(
    a,
    crypto: crypto,
    alpnProtocols: const [httpAlpnH2],
  );
  final server = PqTlsSocket.server(
    b,
    crypto: crypto,
    identity: identity,
    alpnProtocols: const [httpAlpnH2],
  );
  final hs = await Future.wait([server.handshake(), client.handshake()]);
  final h2 = PqHttp2Session.server(server);
  final serving = () async {
    for (var i = 0; i < 3; i++) {
      final accepted = await h2.accept(timeout: const Duration(seconds: 20));
      if (accepted.isFailure) return accepted;
      final (id, req) = accepted.valueOrNull!;
      final query = dohQueryFromRequest(req);
      if (query.isFailure) return query;
      final sent = await h2.respond(
        id,
        dohResponse(answerFor(query.valueOrNull!), version: HttpVersion.h2),
      );
      if (sent.isFailure) return sent;
    }
    return const Result<void, PqTransportError>.success(null);
  }();

  final template = DohUriTemplate.parse(
    'https://dns.example/dns-query{?dns}',
  ).valueOrNull!;
  final http = PqHttpClient(prefer: HttpVersion.h2);
  final post = DohClient.h2(client, template: template, http: http);
  final get = DohClient.h2(
    client,
    template: template,
    http: http,
    useGet: true,
  );
  final query = encodeDnsMessage(
    DnsMessage(
      id: 0x0d07,
      questions: [DnsQuestion(name: 'www.example.', type: DnsType.a)],
    ),
  ).valueOrNull!;
  final posted = await post.query(query);
  final gotten = await get.query(query);
  final looked = await PqDnsResolver(
    doh: post.exchange,
  ).lookup('www.example.', DnsType.a);
  final address = looked.valueOrNull?.answers.whereType<DnsA>().singleOrNull;
  final served = await serving;
  if (hs.any((r) => r.isFailure) ||
      posted.isFailure ||
      gotten.isFailure ||
      looked.isFailure ||
      served.isFailure ||
      address == null) {
    stderr.writeln(
      'doh failed: ${posted.errorOrNull ?? gotten.errorOrNull ?? looked.errorOrNull ?? served.errorOrNull}',
    );
    exitCode = 1;
  } else {
    stdout.writeln('doh: post and get, resolver A ${address.address}');
  }
  await h2.close();
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
          address: Uint8List.fromList(const [192, 0, 2, 10]),
          ttl: 30,
        ),
      ],
    ),
  ).valueOrNull!;
}
