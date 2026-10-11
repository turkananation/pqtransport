import 'dart:typed_data';

import 'package:pqtransport/pqtransport.dart';
import 'package:swissarmyknife/swissarmyknife.dart';
import 'package:test/test.dart';

void main() {
  final crypto = PqTransportCrypto();

  Uint8List queryFor(String name) {
    return encodeDnsMessage(
      DnsMessage(
        id: 0x0d07,
        questions: [DnsQuestion(name: name, type: DnsType.a)],
      ),
    ).valueOrNull!;
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
            address: Uint8List.fromList([1, 2, 3, 4]),
            ttl: 30,
          ),
        ],
      ),
    ).valueOrNull!;
  }

  test('RFC 8484 URI template and unpadded base64url', () {
    final parsed = DohUriTemplate.parse('https://dns.example/dns-query{?dns}');
    expect(parsed.isSuccess, isTrue, reason: '${parsed.errorOrNull}');
    final t = parsed.valueOrNull!;
    expect(t.postUri.toString(), 'https://dns.example/dns-query');
    final msg = Uint8List.fromList([0, 1, 2, 250, 255]);
    final get = t.getUri(msg);
    expect(get.queryParameters['dns'], 'AAEC-v8');
    expect(get.queryParameters['dns']!.contains('='), isFalse);
    expect(dohBase64UrlDecode(get.queryParameters['dns']!).valueOrNull, msg);
    expect(dohBase64UrlDecode('AAEC+v8').isFailure, isTrue);
    expect(dohBase64UrlDecode('AAEC-v8=').isFailure, isTrue);

    expect(
      DohUriTemplate.parse(
        'https://dns.example/dns-query{?dns,extra}',
      ).isFailure,
      isTrue,
    );
    expect(DohUriTemplate.parse('https://dns.example/{dns}').isFailure, isTrue);
    expect(DohUriTemplate.parse('/dns-query{?dns}').isFailure, isTrue);
    expect(
      DohUriTemplate.parse('https://dns.example/dns-query').isSuccess,
      isTrue,
    );
  });

  test('dohQueryFromRequest POST and GET fail closed', () {
    final msg = Uint8List.fromList([9, 8, 7]);
    final post = dohQueryFromRequest(
      PqHttpRequest(
        method: 'POST',
        uri: Uri.parse('https://dns.example/dns-query'),
        headers: const {'content-type': dnsMessageMediaType},
        body: msg,
      ),
    );
    expect(post.valueOrNull, msg);
    expect(
      dohQueryFromRequest(
        PqHttpRequest(
          method: 'POST',
          uri: Uri.parse('https://dns.example/dns-query'),
          headers: const {'content-type': 'text/plain'},
          body: msg,
        ),
      ).isFailure,
      isTrue,
    );

    final get = dohQueryFromRequest(
      PqHttpRequest(
        method: 'GET',
        uri: Uri.parse('https://dns.example/dns-query?dns=CQgH'),
      ),
    );
    expect(get.valueOrNull, msg);
    expect(
      dohQueryFromRequest(
        PqHttpRequest(
          method: 'GET',
          uri: Uri.parse('https://dns.example/dns-query'),
        ),
      ).isFailure,
      isTrue,
    );
  });

  test('DoT framing reassembles a split length prefix', () {
    final msg = Uint8List.fromList([1, 2, 3, 4, 5]);
    final wire = encodeDnsTcp(msg);
    final reader = DnsTcpReader();
    reader.add(wire.sublist(0, 1));
    expect(reader.next(), isNull);
    reader.add(wire.sublist(1, 3));
    expect(reader.next(), isNull);
    reader.add(wire.sublist(3));
    expect(reader.next(), msg);
    expect(reader.next(), isNull);

    final bad = DnsTcpReader()..add(Uint8List.fromList([0x00, 0x00]));
    expect(bad.next(), isNull);
    expect(bad.error, isNotNull);
  });

  test('DoT over PqTlsSocket ALPN dot; wrong ALPN fails closed', () async {
    final identity = PqTlsServerIdentity.generate(crypto);
    final (cSock, sSock) = MemoryByteSocket.pair();
    final client = PqTlsSocket.client(
      cSock,
      crypto: crypto,
      alpnProtocols: const [dnsAlpnDot],
    );
    final server = PqTlsSocket.server(
      sSock,
      crypto: crypto,
      identity: identity,
      alpnProtocols: const [dnsAlpnDot],
    );
    final hs = await Future.wait([server.handshake(), client.handshake()]);
    expect(hs[0].isSuccess && hs[1].isSuccess, isTrue);
    expect(client.alpn, dnsAlpnDot);

    final query = queryFor('dot.example.');
    final serverTask = () async {
      final reader = DnsTcpReader();
      final done = reader.next();
      expect(done, isNull);
      await for (final chunk in server.applicationData) {
        reader.add(chunk);
        final q = reader.next();
        if (q == null) continue;
        expect(q, query);
        final sent = await server.send(encodeDnsTcp(answerFor(q)));
        expect(sent.isSuccess, isTrue);
        break;
      }
    }();

    final dot = DotClient(client);
    final got = await dot.query(query);
    expect(got.isSuccess, isTrue, reason: '${got.errorOrNull}');
    final decoded = decodeDnsMessage(got.valueOrNull!);
    expect(decoded.valueOrNull!.id, 0x0d07);
    expect(decoded.valueOrNull!.answers.whereType<DnsA>().single.address, [
      1,
      2,
      3,
      4,
    ]);
    await serverTask;
    await dot.close();

    final (a, b) = MemoryByteSocket.pair();
    final h2c = PqTlsSocket.client(
      a,
      crypto: crypto,
      alpnProtocols: const [httpAlpnH2],
    );
    final h2s = PqTlsSocket.server(
      b,
      crypto: crypto,
      identity: identity,
      alpnProtocols: const [httpAlpnH2],
    );
    final hs2 = await Future.wait([h2s.handshake(), h2c.handshake()]);
    expect(hs2[0].isSuccess && hs2[1].isSuccess, isTrue);
    final refused = await DotClient(h2c).query(query);
    expect(refused.isFailure, isTrue);
    expect(refused.errorOrNull!.code, PqTransportErrorCode.handshakeFailure);
    await h2c.close();
    await h2s.close();
    await client.close();
    await server.close();
  }, timeout: const Timeout(Duration(seconds: 40)));

  test('DoH POST and GET over ALPN h2', () async {
    final identity = PqTlsServerIdentity.generate(crypto);
    final (cSock, sSock) = MemoryByteSocket.pair();
    final client = PqTlsSocket.client(
      cSock,
      crypto: crypto,
      alpnProtocols: const [httpAlpnH2],
    );
    final server = PqTlsSocket.server(
      sSock,
      crypto: crypto,
      identity: identity,
      alpnProtocols: const [httpAlpnH2],
    );
    final hs = await Future.wait([server.handshake(), client.handshake()]);
    expect(
      hs[0].isSuccess && hs[1].isSuccess,
      isTrue,
      reason: '${hs[0].errorOrNull}',
    );
    expect(client.alpn, httpAlpnH2);

    final h2s = PqHttp2Session.server(server);
    final serving = () async {
      for (var i = 0; i < 3; i++) {
        final accepted = await h2s.accept(timeout: const Duration(seconds: 20));
        expect(accepted.isSuccess, isTrue, reason: '${accepted.errorOrNull}');
        final (id, req) = accepted.valueOrNull!;
        final q = dohQueryFromRequest(req);
        expect(q.isSuccess, isTrue, reason: '${q.errorOrNull}');
        final sent = await h2s.respond(
          id,
          dohResponse(answerFor(q.valueOrNull!), version: HttpVersion.h2),
        );
        expect(sent.isSuccess, isTrue, reason: '${sent.errorOrNull}');
      }
    }();

    final template = DohUriTemplate.parse(
      'https://example.test/dns-query{?dns}',
    ).valueOrNull!;
    final http = PqHttpClient(prefer: HttpVersion.h2);
    final post = DohClient.h2(client, template: template, http: http);
    final get = DohClient.h2(
      client,
      template: template,
      http: http,
      useGet: true,
    );
    final query = queryFor('doh.example.');
    final posted = await post.query(query);
    expect(posted.isSuccess, isTrue, reason: '${posted.errorOrNull}');
    expect(decodeDnsMessage(posted.valueOrNull!).valueOrNull!.id, 0x0d07);
    final gotten = await get.query(query);
    expect(gotten.isSuccess, isTrue, reason: '${gotten.errorOrNull}');
    expect(
      decodeDnsMessage(gotten.valueOrNull!).valueOrNull!.answers.length,
      1,
    );

    final resolver = PqDnsResolver(doh: post.exchange);
    final looked = await resolver.lookup('doh.example.', DnsType.a);
    expect(looked.isSuccess, isTrue, reason: '${looked.errorOrNull}');
    expect(looked.valueOrNull!.answers.whereType<DnsA>().single.address, [
      1,
      2,
      3,
      4,
    ]);
    await serving;
    await h2s.close();
    await client.close();
    await server.close();
  }, timeout: const Timeout(Duration(seconds: 40)));

  test('DoH POST over ALPN h3 and bad media type fails closed', () async {
    final (client, server) = PqQuicConn.pair(
      crypto: crypto,
      alpnProtocols: const [httpAlpnH3],
    );
    final hs = await Future.wait([client.handshake(), server.handshake()]);
    expect(hs[0].isSuccess && hs[1].isSuccess, isTrue);
    expect(client.alpn, httpAlpnH3);

    final h3s = PqHttp3Session.server(server);
    final query = queryFor('h3.example.');
    final serving = () async {
      final accepted = await h3s.accept(timeout: const Duration(seconds: 20));
      expect(accepted.isSuccess, isTrue, reason: '${accepted.errorOrNull}');
      final (id, req) = accepted.valueOrNull!;
      expect(req.method, 'POST');
      expect(req.headers['content-type'], dnsMessageMediaType);
      final q = dohQueryFromRequest(req);
      expect(q.valueOrNull, query);
      return h3s.respond(
        id,
        dohResponse(answerFor(query), version: HttpVersion.h3),
      );
    }();

    final doh = DohClient.h3(
      client,
      template: DohUriTemplate.parse(
        'https://example.test/dns-query{?dns}',
      ).valueOrNull!,
    );
    final got = await doh.query(query);
    expect(got.isSuccess, isTrue, reason: '${got.errorOrNull}');
    expect(decodeDnsMessage(got.valueOrNull!).valueOrNull!.id, 0x0d07);
    expect((await serving).isSuccess, isTrue);

    final bad = await DohClient(
      template: DohUriTemplate.parse(
        'https://example.test/dns-query',
      ).valueOrNull!,
      roundTrip: (req) async => Result.success(
        PqHttpResponse(
          status: 200,
          headers: const {'content-type': 'text/plain'},
          body: Uint8List.fromList([1]),
          version: HttpVersion.h2,
        ),
      ),
    ).query(query);
    expect(bad.isFailure, isTrue);
    expect(bad.errorOrNull!.code, PqTransportErrorCode.decodeFailure);
  }, timeout: const Timeout(Duration(seconds: 40)));
}
