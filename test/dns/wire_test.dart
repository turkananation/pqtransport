import 'dart:typed_data';

import 'package:pqtransport/pqtransport.dart';
import 'package:test/test.dart';

void main() {
  DnsMessage roundTrip(DnsMessage m) {
    final enc = encodeDnsMessage(m);
    expect(enc.isSuccess, isTrue, reason: '${enc.errorOrNull}');
    final dec = decodeDnsMessage(enc.valueOrNull!);
    expect(dec.isSuccess, isTrue, reason: '${dec.errorOrNull}');
    return dec.valueOrNull!;
  }

  test('A/AAAA/CNAME/MX/TXT/SRV/CAA/HTTPS/SVCB/OPT/PTR/NS round trip', () {
    final msg = DnsMessage(
      id: 0x1234,
      flags: 0x8180,
      questions: [const DnsQuestion(name: 'example.com.', type: DnsType.a)],
      answers: [
        DnsA(name: 'example.com.', address: Uint8List.fromList([1, 2, 3, 4])),
        DnsAaaa(name: 'example.com.', address: Uint8List(16)..[15] = 1),
        DnsCname(name: 'www.example.com.', canonical: 'example.com.'),
        DnsMx(
          name: 'example.com.',
          preference: 10,
          exchange: 'mail.example.com.',
        ),
        DnsTxt(name: 'example.com.', strings: ['hello', 'pq']),
        DnsSrv(
          name: '_pq._tcp.example.com.',
          priority: 0,
          weight: 5,
          port: 443,
          target: 'svc.example.com.',
        ),
        DnsCaa(
          name: 'example.com.',
          flags: 0,
          tag: 'issue',
          value: 'letsencrypt.org',
        ),
        DnsHttps(
          name: 'example.com.',
          priority: 1,
          target: '.',
          params: {
            1: Uint8List.fromList([0x02, 0x68, 0x33]),
          },
        ),
        DnsSvcb(name: 'example.com.', priority: 0, target: 'svc.example.com.'),
        DnsPtr(name: '4.3.2.1.in-addr.arpa.', pointer: 'example.com.'),
        DnsNs(name: 'example.com.', nameserver: 'ns1.example.com.'),
      ],
      additional: [DnsOpt()],
    );
    final out = roundTrip(msg);
    expect(out.answers.whereType<DnsA>().single.address, [1, 2, 3, 4]);
    expect(out.answers.whereType<DnsTxt>().single.strings, ['hello', 'pq']);
    expect(out.answers.whereType<DnsMx>().single.preference, 10);
    expect(out.answers.whereType<DnsHttps>().single.priority, 1);
    expect(out.answers.whereType<DnsPtr>().single.pointer, 'example.com.');
    expect(
      out.answers.whereType<DnsNs>().single.nameserver,
      'ns1.example.com.',
    );
    expect(out.additional.whereType<DnsOpt>(), isNotEmpty);
  });

  test('compression pointer cycle is rejected', () {
    final body = BytesBuilder(copy: false);
    body.add([0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0]); // header qd=1
    body.addByte(0xC0);
    body.addByte(12); // pointer to offset 12
    body.add([0, 1, 0, 1]); // type A class IN
    final r = decodeDnsMessage(body.takeBytes());
    expect(r.isFailure, isTrue);
  });

  test('label too long is rejected', () {
    final r = encodeDnsMessage(
      DnsMessage(
        id: 1,
        questions: [DnsQuestion(name: '${'a' * 64}.example.', type: DnsType.a)],
      ),
    );
    expect(r.isFailure, isTrue);
  });

  test(
    'circuit breaker opens after threshold and cache respects TTL',
    () async {
      var calls = 0;
      var now = DateTime.utc(2026, 1, 1);
      final client = PqDnsClient(
        clock: () => now,
        failureThreshold: 2,
        exchange: (q) async {
          calls++;
          throw StateError('down');
        },
      );
      final a = await client.lookup('a.example.', DnsType.a);
      expect(a.isFailure, isTrue);
      final b = await client.lookup('a.example.', DnsType.a);
      expect(b.isFailure, isTrue);
      final c = await client.lookup('a.example.', DnsType.a);
      expect(c.errorOrNull!.code, PqTransportErrorCode.circuitOpen);
      expect(calls, 2);

      var n = 0;
      final cached = PqDnsClient(
        clock: () => now,
        exchange: (q) async {
          n++;
          return encodeDnsMessage(
            DnsMessage(
              id: 1,
              flags: 0x8180,
              answers: [
                DnsA(
                  name: 'b.example.',
                  address: Uint8List.fromList([9, 9, 9, 9]),
                  ttl: 1,
                ),
              ],
            ),
          ).valueOrNull!;
        },
      );
      await cached.lookup('b.example.', DnsType.a);
      await cached.lookup('b.example.', DnsType.a);
      expect(n, 1);
      now = now.add(const Duration(seconds: 2));
      await cached.lookup('b.example.', DnsType.a);
      expect(n, 2);
    },
  );

  test('PqDnsResolver failovers DoH to UDP', () async {
    var udpCalls = 0;
    final resolver = PqDnsResolver(
      doh: (q) async => throw StateError('doh down'),
      udp: (q) async {
        udpCalls++;
        return encodeDnsMessage(
          DnsMessage(
            id: 1,
            flags: 0x8180,
            answers: [
              DnsA(
                name: 'c.example.',
                address: Uint8List.fromList([8, 8, 8, 8]),
              ),
            ],
          ),
        ).valueOrNull!;
      },
    );
    // DoH breaker threshold is 2; first two fail, third skip-fails, then UDP.
    await resolver.lookup('c.example.', DnsType.a);
    await resolver.lookup('c.example.', DnsType.a);
    final r = await resolver.lookup('c.example.', DnsType.a);
    expect(r.isSuccess, isTrue, reason: '${r.errorOrNull}');
    expect(udpCalls, greaterThan(0));
    expect(r.valueOrNull!.answers.whereType<DnsA>().single.address, [
      8,
      8,
      8,
      8,
    ]);
  });
}
