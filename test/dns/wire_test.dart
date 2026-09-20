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

  test('OPEN-08 CNAME rdata pointer into QNAME is resolved', () {
    final wire = _foreignMessage(
      answers: [_rr(owner: _ptr(12), type: dnsTypeCname, rdata: _ptr(12))],
    );
    final r = decodeDnsMessage(wire);
    expect(r.isSuccess, isTrue, reason: '${r.errorOrNull}');
    final cname = r.valueOrNull!.answers.whereType<DnsCname>().single;
    expect(cname.name, 'example.com.');
    expect(cname.canonical, 'example.com.');
  });

  test('OPEN-08 MX/NS/PTR/SRV rdata pointers into the outer message', () {
    final wire = _foreignMessage(
      answers: [
        _rr(
          owner: _ptr(12),
          type: dnsTypeMx,
          rdata: Uint8List.fromList([0, 10, ..._ptr(12)]),
        ),
        _rr(owner: _ptr(12), type: dnsTypeNs, rdata: _ptr(12)),
        _rr(owner: _ptr(12), type: dnsTypePtr, rdata: _ptr(12)),
        _rr(
          owner: _ptr(12),
          type: dnsTypeSrv,
          rdata: Uint8List.fromList([0, 1, 0, 2, 1, 187, ..._ptr(12)]),
        ),
      ],
    );
    final r = decodeDnsMessage(wire);
    expect(r.isSuccess, isTrue, reason: '${r.errorOrNull}');
    final msg = r.valueOrNull!;
    expect(msg.answers.whereType<DnsMx>().single.exchange, 'example.com.');
    expect(msg.answers.whereType<DnsMx>().single.preference, 10);
    expect(msg.answers.whereType<DnsNs>().single.nameserver, 'example.com.');
    expect(msg.answers.whereType<DnsPtr>().single.pointer, 'example.com.');
    final srv = msg.answers.whereType<DnsSrv>().single;
    expect(srv.target, 'example.com.');
    expect(srv.port, 443);
  });

  test('OPEN-08 rdata suffix pointer: www + QNAME → www.example.com.', () {
    final wire = _foreignMessage(
      answers: [
        _rr(
          owner: _ptr(12),
          type: dnsTypeCname,
          rdata: Uint8List.fromList([3, ...'www'.codeUnits, ..._ptr(12)]),
        ),
      ],
    );
    final r = decodeDnsMessage(wire);
    expect(r.isSuccess, isTrue, reason: '${r.errorOrNull}');
    expect(
      r.valueOrNull!.answers.whereType<DnsCname>().single.canonical,
      'www.example.com.',
    );
  });

  test('OPEN-08 truncated rdata name does not consume the next RR', () {
    final wire = _foreignMessage(
      answers: [
        _rr(
          owner: _ptr(12),
          type: dnsTypeCname,
          rdata: Uint8List.fromList([0xC0]), // truncated pointer
        ),
        _rr(
          owner: _ptr(12),
          type: dnsTypeA,
          rdata: Uint8List.fromList([1, 2, 3, 4]),
        ),
      ],
    );
    final r = decodeDnsMessage(wire);
    expect(r.isFailure, isTrue);
    expect(r.errorOrNull!.message.toLowerCase(), contains('truncat'));
  });

  test('OPEN-08 HTTPS target name may pointer into QNAME', () {
    final wire = _foreignMessage(
      answers: [
        _rr(
          owner: _ptr(12),
          type: dnsTypeHttps,
          rdata: Uint8List.fromList([0, 1, ..._ptr(12)]),
        ),
      ],
    );
    final r = decodeDnsMessage(wire);
    expect(r.isSuccess, isTrue, reason: '${r.errorOrNull}');
    final https = r.valueOrNull!.answers.whereType<DnsHttps>().single;
    expect(https.target, 'example.com.');
    expect(https.priority, 1);
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

/// RFC 1035 compression pointer. Offset is from the start of the message.
Uint8List _ptr(int offset) => Uint8List.fromList([
  dnsPointerMask | ((offset >> 8) & 0x3f),
  offset & 0xff,
]);

Uint8List _qnameExampleCom() =>
    Uint8List.fromList([7, ...'example'.codeUnits, 3, ...'com'.codeUnits, 0]);

Uint8List _rr({
  required Uint8List owner,
  required int type,
  required Uint8List rdata,
  int ttl = 60,
}) {
  final b = BytesBuilder(copy: false)
    ..add(owner)
    ..addByte(type >> 8)
    ..addByte(type & 0xff)
    ..addByte(0)
    ..addByte(dnsClassIn)
    ..addByte((ttl >> 24) & 0xff)
    ..addByte((ttl >> 16) & 0xff)
    ..addByte((ttl >> 8) & 0xff)
    ..addByte(ttl & 0xff)
    ..addByte((rdata.length >> 8) & 0xff)
    ..addByte(rdata.length & 0xff)
    ..add(rdata);
  return b.takeBytes();
}

/// One question `example.com. IN A` at offset 12, then [answers].
Uint8List _foreignMessage({required List<Uint8List> answers}) {
  final q = BytesBuilder(copy: false)
    ..add(_qnameExampleCom())
    ..addByte(0)
    ..addByte(dnsTypeA)
    ..addByte(0)
    ..addByte(dnsClassIn);
  final b = BytesBuilder(copy: false)
    ..add([0, 1, 0x81, 0x80, 0, 1, 0, answers.length, 0, 0, 0, 0])
    ..add(q.takeBytes());
  for (final rr in answers) {
    b.add(rr);
  }
  return b.takeBytes();
}
