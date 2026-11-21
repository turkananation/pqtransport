import 'dart:typed_data';

import 'package:pqtransport/pqtransport.dart';
import 'package:test/test.dart';

void main() {
  final soa = DnsSoa(
    name: 'example.com.',
    mname: 'ns1.example.com.',
    rname: 'hostmaster.example.com.',
    serial: 1,
    refresh: 100,
    retry: 50,
    expire: 1000,
    minimum: 60,
  );
  final zone = DnsAuthoritativeZone(
    origin: 'example.com',
    soa: soa,
    nameservers: [DnsNs(name: 'example.com.', nameserver: 'ns1.example.com.')],
    records: [
      DnsA(
        name: 'www.example.com.',
        address: Uint8List.fromList([192, 0, 2, 1]),
      ),
      DnsA(
        name: 'ns1.example.com.',
        address: Uint8List.fromList([192, 0, 2, 53]),
      ),
      DnsNs(name: 'child.example.com.', nameserver: 'ns.child.example.com.'),
      DnsA(
        name: 'ns.child.example.com.',
        address: Uint8List.fromList([192, 0, 2, 9]),
      ),
      DnsCname(name: 'alias.example.com.', canonical: 'www.example.com.'),
    ],
  );

  DnsMessage ask(String name, DnsType type) => zone.answer(
    DnsMessage(
      id: 7,
      questions: [DnsQuestion(name: name, type: type)],
    ),
  );

  test('authoritative answers, NODATA, NXDOMAIN, and a referral', () {
    final www = ask('www.example.com', DnsType.a);
    expect(www.flags & dnsFlagAa, dnsFlagAa);
    expect(www.rcode, 0);
    expect((www.answers.single as DnsA).address, [192, 0, 2, 1]);

    final nodata = ask('www.example.com', DnsType.aaaa);
    expect(nodata.flags & dnsFlagAa, dnsFlagAa);
    expect(nodata.rcode, 0);
    expect(nodata.answers, isEmpty);
    expect(nodata.authority.single, isA<DnsSoa>());

    final missing = ask('no.example.com', DnsType.a);
    expect(missing.rcode, dnsRcodeNxDomain);
    expect(missing.flags & dnsFlagAa, dnsFlagAa);

    final referral = ask('www.child.example.com', DnsType.a);
    expect(referral.flags & dnsFlagAa, 0);
    expect(referral.answers, isEmpty);
    expect(
      (referral.authority.single as DnsNs).nameserver,
      'ns.child.example.com.',
    );
    expect((referral.additional.single as DnsA).address, [192, 0, 2, 9]);

    final outside = ask('other.test', DnsType.a);
    expect(outside.rcode, dnsRcodeRefused);
    expect(outside.flags & dnsFlagAa, 0);

    final alias = ask('alias.example.com', DnsType.a);
    expect(alias.answers.single, isA<DnsCname>());

    final two = zone.answer(const DnsMessage(id: 1, questions: []));
    expect(two.rcode, dnsRcodeFormErr);
  });
}
