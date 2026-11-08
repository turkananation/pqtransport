import 'dart:math';
import 'dart:typed_data';

import 'package:pqforge/pqforge.dart';
import 'package:pqtransport/pqtransport.dart';
import 'package:swissarmyknife/swissarmyknife.dart';
import 'package:test/test.dart';

void main() {
  final now = DateTime.utc(2026, 11, 8);

  test('a revoked DNSKEY does not verify', () {
    final zone = _zone('.', 1);
    final revoked = DnsDnskey(
      name: '.',
      flags: dnssecZoneKeyFlag | dnssecRevokedKeyFlag,
      protocol: dnssecProtocol,
      algorithm: dnssecAlgorithmEd25519,
      publicKey: zone.key.publicKey,
    );
    final a = [
      DnsA(name: 'example.', address: Uint8List.fromList(const [1, 1, 1, 1])),
    ];
    expect(
      verifyDnssecRrset(
        rrset: a,
        rrsig: _sign(a, revoked, zone.secret),
        dnskey: revoked,
        now: now,
      ).isFailure,
      isTrue,
    );
  });

  test(
    'NSEC3 iteration policy is the caller ceiling, not a protocol constant',
    () {
      final rr = DnsNsec3(
        name: 'a.example.',
        hashAlgorithm: dnssecNsec3HashSha1,
        flags: 0,
        iterations: 1,
        salt: Uint8List(0),
        next: Uint8List(dnssecSha1DigestBytes),
        types: Uint8List(0),
      );
      expect(
        dnsNsec3ProvesNameError(
          qname: 'b.example.',
          zone: 'example.',
          nsecs: [rr],
          maxIterations: 0,
        ).isFailure,
        isTrue,
      );
      expect(
        dnsNsec3Hash(
          name: 'example.',
          algorithm: dnssecNsec3HashSha1,
          iterations: 12,
          salt: Uint8List.fromList(const [0xaa, 0xbb, 0xcc, 0xdd]),
        ).isSuccess,
        isTrue,
      );
    },
  );

  test('iterative resolver validates, caches, and follows cuts', () async {
    final root = _zone('.', 1);
    final com = _zone('com.', 2);
    final example = _zone('example.com.', 3);
    final rootDs = _ds(com.key);
    final comDs = _ds(example.key);
    final www = DnsA(
      name: 'www.example.com.',
      address: Uint8List.fromList(const [192, 0, 2, 9]),
    );
    final alias = DnsCname(
      name: 'alias.example.com.',
      canonical: 'www.example.com.',
    );
    final dname = DnsDname(
      name: 'foo.example.com.',
      target: 'bar.example.com.',
    );
    final bar = DnsA(
      name: 'www.bar.example.com.',
      address: Uint8List.fromList(const [192, 0, 2, 10]),
    );
    final insecureA = DnsA(
      name: 'insecure.example.com.',
      address: Uint8List.fromList(const [192, 0, 2, 11]),
    );
    final bad = DnsA(
      name: 'bad.example.com.',
      address: Uint8List.fromList(const [192, 0, 2, 12]),
    );
    final wwwNsec = DnsNsec(
      name: 'www.example.com.',
      next: 'example.com.',
      types: dnsTypeBitmap(const [dnsTypeA]),
    );
    final noDs = DnsNsec(
      name: 'insecure.example.com.',
      next: 'www.example.com.',
      types: dnsTypeBitmap(const [dnsTypeNs]),
    );
    final sends = <String>[];

    Future<Result<DnsMessage, PqTransportError>> send(
      DnsMessage query,
      String nameserver,
      List<Uint8List> addresses,
    ) async {
      expect(query.flags & dnsFlagCd, dnsFlagCd);
      final opt = query.additional.whereType<DnsOpt>().single;
      expect(opt.flags & ednsFlagDo, ednsFlagDo);
      final cookie = opt.options[ednsOptionCookie]!;
      sends.add(
        '$nameserver ${query.questions.single.name} ${query.questions.single.type.name}',
      );
      if (dnsNamesEqual(nameserver, 'a.root-servers.net.') &&
          cookie.length == 8) {
        final server = Uint8List(8)..[0] = 0x22;
        return Result.success(
          DnsMessage(
            id: query.id,
            flags: 0x8000 | 0x7,
            questions: query.questions,
            additional: [
              DnsOpt(
                extendedRcode: 1,
                options: {
                  ednsOptionCookie: Uint8List.fromList([...cookie, ...server]),
                },
              ),
            ],
          ),
        );
      }
      final qname = query.questions.single.name;
      final qtype = query.questions.single.type;
      if (dnsNamesEqual(nameserver, 'a.root-servers.net.')) {
        if (qtype == DnsType.dnskey) {
          return Result.success(
            _aa(query, [
              root.key,
              _sign([root.key], root.key, root.secret),
            ]),
          );
        }
        if (dnsNamesEqual(qname, 'com.') && qtype == DnsType.ns) {
          final ns = DnsNs(name: 'com.', nameserver: 'ns.com.');
          return Result.success(
            _ref(
              query,
              [
                ns,
                _sign([ns], root.key, root.secret),
              ],
              [
                DnsA(
                  name: 'ns.com.',
                  address: Uint8List.fromList(const [192, 0, 2, 1]),
                ),
              ],
            ),
          );
        }
        if (dnsNamesEqual(qname, 'com.') && qtype == DnsType.ds) {
          return Result.success(
            _aa(query, [
              rootDs,
              _sign([rootDs], root.key, root.secret),
            ]),
          );
        }
      }
      if (dnsNamesEqual(nameserver, 'ns.com.')) {
        if (qtype == DnsType.dnskey) {
          return Result.success(
            _aa(query, [
              com.key,
              _sign([com.key], com.key, com.secret),
            ]),
          );
        }
        if (dnsNamesEqual(qname, 'example.com.') && qtype == DnsType.ns) {
          final ns = DnsNs(name: 'example.com.', nameserver: 'ns.example.com.');
          return Result.success(
            _ref(
              query,
              [
                ns,
                _sign([ns], com.key, com.secret),
              ],
              [
                DnsA(
                  name: 'ns.example.com.',
                  address: Uint8List.fromList(const [192, 0, 2, 2]),
                ),
              ],
            ),
          );
        }
        if (dnsNamesEqual(qname, 'example.com.') && qtype == DnsType.ds) {
          return Result.success(
            _aa(query, [
              comDs,
              _sign([comDs], com.key, com.secret),
            ]),
          );
        }
      }
      if (dnsNamesEqual(nameserver, 'ns.example.com.')) {
        if (qtype == DnsType.dnskey) {
          return Result.success(
            _aa(query, [
              example.key,
              _sign([example.key], example.key, example.secret),
            ]),
          );
        }
        if (dnsNamesEqual(qname, 'www.example.com.') && qtype == DnsType.a) {
          return Result.success(
            _aa(query, [
              www,
              _sign([www], example.key, example.secret),
            ]),
          );
        }
        if (dnsNamesEqual(qname, 'alias.example.com.') && qtype == DnsType.a) {
          return Result.success(
            _aa(query, [
              alias,
              _sign([alias], example.key, example.secret),
            ]),
          );
        }
        if (qtype == DnsType.ns) {
          return Result.success(_aa(query, const []));
        }
        if (dnsNamesEqual(qname, 'www.foo.example.com.') &&
            qtype == DnsType.a) {
          return Result.success(
            _aa(query, [
              dname,
              _sign([dname], example.key, example.secret),
            ]),
          );
        }
        if (dnsNamesEqual(qname, 'www.bar.example.com.') &&
            qtype == DnsType.a) {
          return Result.success(
            _aa(query, [
              bar,
              _sign([bar], example.key, example.secret),
            ]),
          );
        }
        if (dnsNamesEqual(qname, 'left.example.com.') ||
            dnsNamesEqual(qname, 'right.example.com.')) {
          return Result.success(
            DnsMessage(
              id: query.id,
              flags: 0x8403,
              questions: query.questions,
              authority: [
                wwwNsec,
                _sign([wwwNsec], example.key, example.secret),
                noDs,
                _sign([noDs], example.key, example.secret),
              ],
            ),
          );
        }
        if (dnsNamesEqual(qname, 'insecure.example.com.') &&
            qtype == DnsType.a) {
          final ns = DnsNs(
            name: 'insecure.example.com.',
            nameserver: 'ns.insecure.example.com.',
          );
          return Result.success(
            _ref(
              query,
              [
                ns,
                _sign([ns], example.key, example.secret),
              ],
              [
                DnsA(
                  name: 'ns.insecure.example.com.',
                  address: Uint8List.fromList(const [192, 0, 2, 3]),
                ),
              ],
            ),
          );
        }
        if (dnsNamesEqual(qname, 'insecure.example.com.') &&
            qtype == DnsType.ds) {
          return Result.success(
            DnsMessage(
              id: query.id,
              flags: 0x8400,
              questions: query.questions,
              authority: [
                noDs,
                _sign([noDs], example.key, example.secret),
              ],
            ),
          );
        }
        if (dnsNamesEqual(qname, 'bad.example.com.') && qtype == DnsType.a) {
          final sig = _sign([bad], example.key, example.secret);
          final broken = DnsRrsig(
            name: sig.name,
            typeCovered: sig.typeCovered,
            algorithm: sig.algorithm,
            labels: sig.labels,
            originalTtl: sig.originalTtl,
            expiration: sig.expiration,
            inception: sig.inception,
            keyTag: sig.keyTag,
            signer: sig.signer,
            signature: Uint8List(dnssecEd25519SignatureBytes),
          );
          return Result.success(_aa(query, [bad, broken]));
        }
      }
      if (dnsNamesEqual(nameserver, 'ns.insecure.example.com.') &&
          qtype == DnsType.a) {
        expect(addresses.single, [192, 0, 2, 3]);
        return Result.success(_aa(query, [insecureA]));
      }
      return Result.failure(
        PqTransportError.unsupported('fixture $nameserver $qname $qtype'),
      );
    }

    final resolver = DnsIterativeResolver(
      hints: [
        DnsHint('a.root-servers.net.', [
          Uint8List.fromList(const [198, 41, 0, 4]),
        ]),
      ],
      anchor: DnsTrustAnchor.dnskey(zone: '.', dnskey: root.key),
      send: send,
      clock: () => now,
      random: Random(1),
    );

    final address = await resolver.lookup('www.example.com.', DnsType.a);
    expect(address.isSuccess, isTrue, reason: '${address.errorOrNull}');
    expect(address.valueOrNull!.security, DnsSecurity.secure);
    expect(address.valueOrNull!.records.single, isA<DnsA>());
    final afterAddress = sends.length;
    final again = await resolver.lookup('www.example.com.', DnsType.a);
    expect(again.valueOrNull!.security, DnsSecurity.secure);
    expect(sends.length, afterAddress);

    final cname = await resolver.lookup('alias.example.com.', DnsType.a);
    expect(cname.isSuccess, isTrue, reason: '${cname.errorOrNull}');
    expect(cname.valueOrNull!.security, DnsSecurity.secure);
    expect((cname.valueOrNull!.records.single as DnsA).address[3], 9);

    final synthesized = await resolver.lookup(
      'www.foo.example.com.',
      DnsType.a,
    );
    expect(synthesized.isSuccess, isTrue, reason: '${synthesized.errorOrNull}');
    expect(synthesized.valueOrNull!.security, DnsSecurity.secure);
    expect((synthesized.valueOrNull!.records.single as DnsA).address[3], 10);

    final bogus = await resolver.lookup('bad.example.com.', DnsType.a);
    expect(bogus.isSuccess, isTrue, reason: '${bogus.errorOrNull}');
    expect(bogus.valueOrNull!.security, DnsSecurity.bogus);
    final afterBogus = sends.length;
    await resolver.lookup('bad.example.com.', DnsType.a);
    expect(sends.length, greaterThan(afterBogus));

    final missing = await resolver.lookup('left.example.com.', DnsType.a);
    expect(missing.isSuccess, isTrue, reason: '${missing.errorOrNull}');
    expect(missing.valueOrNull!.nameError, isTrue);
    expect(missing.valueOrNull!.security, DnsSecurity.secure);
    final afterMissing = sends.length;
    final covered = await resolver.lookup('right.example.com.', DnsType.a);
    expect(
      covered.valueOrNull!.nameError,
      isTrue,
      reason: '${covered.errorOrNull}',
    );
    expect(sends.length, afterMissing);

    final open = await resolver.lookup('insecure.example.com.', DnsType.a);
    expect(open.isSuccess, isTrue, reason: '${open.errorOrNull}');
    expect(open.valueOrNull!.security, DnsSecurity.insecure);
    expect((open.valueOrNull!.records.single as DnsA).address[3], 11);
  });
}

DnsMessage _aa(DnsMessage query, List<DnsRecord> answers) => DnsMessage(
  id: query.id,
  flags: 0x8400,
  questions: query.questions,
  answers: answers,
);

DnsMessage _ref(
  DnsMessage query,
  List<DnsRecord> authority,
  List<DnsRecord> additional,
) => DnsMessage(
  id: query.id,
  flags: 0x8000,
  questions: query.questions,
  authority: authority,
  additional: additional,
);

typedef _ZoneKey = ({DnsDnskey key, Uint8List secret});

_ZoneKey _zone(String name, int mark) {
  final secret = Uint8List(32)..[31] = mark;
  return (
    secret: secret,
    key: DnsDnskey(
      name: name,
      flags: dnssecZoneKeyFlag,
      protocol: dnssecProtocol,
      algorithm: dnssecAlgorithmEd25519,
      publicKey: PqEd25519.publicKeyFromSeed(secret),
    ),
  );
}

DnsDs _ds(DnsDnskey key) {
  final rdata = dnskeyWireRdata(key);
  final owner = dnsCanonicalName(key.name).valueOrNull!;
  return DnsDs(
    name: key.name,
    keyTag: dnssecKeyTag(rdata),
    algorithm: key.algorithm,
    digestType: dnssecDigestSha256,
    digest: PqBytes.sha256(concatBytes([owner, rdata])),
  );
}

DnsRrsig _sign(List<DnsRecord> rrset, DnsDnskey key, Uint8List secret) {
  final unsigned = DnsRrsig(
    name: rrset.first.name,
    typeCovered: dnsRecordType(rrset.first),
    algorithm: key.algorithm,
    labels: dnsLabelCount(rrset.first.name),
    originalTtl: rrset.first.ttl,
    expiration: 1893456000,
    inception: 1730419200,
    keyTag: dnssecKeyTag(dnskeyWireRdata(key)),
    signer: key.name,
    signature: Uint8List(dnssecEd25519SignatureBytes),
  );
  final material = dnssecSignedMaterial(rrset: rrset, rrsig: unsigned);
  if (material.isFailure) throw StateError('${material.errorOrNull}');
  return DnsRrsig(
    name: unsigned.name,
    typeCovered: unsigned.typeCovered,
    algorithm: unsigned.algorithm,
    labels: unsigned.labels,
    originalTtl: unsigned.originalTtl,
    expiration: unsigned.expiration,
    inception: unsigned.inception,
    keyTag: unsigned.keyTag,
    signer: unsigned.signer,
    signature: PqEd25519.sign(
      secretKey: secret,
      message: material.valueOrNull!,
    ),
  );
}
