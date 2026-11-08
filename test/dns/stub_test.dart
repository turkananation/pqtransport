import 'dart:typed_data';

import 'package:pqforge/pqforge.dart';
import 'package:pqtransport/pqtransport.dart';
import 'package:swissarmyknife/swissarmyknife.dart';
import 'package:test/test.dart';

void main() {
  const inception = 1730419200;
  const expiration = 1893456000;
  final now = DateTime.utc(2026, 11, 8);

  test('SOA and an unknown RR round-trip', () {
    final msg = DnsMessage(
      id: 4,
      flags: 0x8403,
      authority: [
        DnsSoa(
          name: 'example.com.',
          mname: 'ns.example.com.',
          rname: 'hostmaster.example.com.',
          serial: 1,
          refresh: 2,
          retry: 3,
          expire: 4,
          minimum: 5,
        ),
        DnsOpaque(
          name: 'example.com.',
          typeCode: 52,
          rdata: Uint8List.fromList(const [1, 2, 3]),
        ),
      ],
    );
    final decoded = decodeDnsMessage(encodeDnsMessage(msg).valueOrNull!);
    expect(decoded.isSuccess, isTrue, reason: '${decoded.errorOrNull}');
    expect(decoded.valueOrNull!.authority[0], isA<DnsSoa>());
    final opaque = decoded.valueOrNull!.authority[1] as DnsOpaque;
    expect(opaque.typeCode, 52);
    expect(opaque.rdata, [1, 2, 3]);
  });

  test(
    'the query sets DO, the id must match, and TC retries over TCP',
    () async {
      Uint8List? seen;
      final client = PqDnsClient(
        exchange: (q) async {
          seen = Uint8List.fromList(q);
          return encodeDnsMessage(
            DnsMessage(
              id: (q[0] << 8) | q[1],
              flags: 0x8400 | dnsFlagTc,
              questions: [
                const DnsQuestion(name: 'a.example.', type: DnsType.a),
              ],
            ),
          ).valueOrNull!;
        },
        tcp: (q) async => encodeDnsMessage(
          DnsMessage(
            id: (q[0] << 8) | q[1],
            flags: 0x8400,
            answers: [
              DnsA(
                name: 'a.example.',
                address: Uint8List.fromList(const [1, 2, 3, 4]),
              ),
            ],
          ),
        ).valueOrNull!,
      );
      final got = await client.lookup('a.example.', DnsType.a);
      expect(got.isSuccess, isTrue, reason: '${got.errorOrNull}');
      final query = decodeDnsMessage(seen!).valueOrNull!;
      final opt = query.additional.whereType<DnsOpt>().single;
      expect(opt.flags & ednsFlagDo, ednsFlagDo);
      expect(got.valueOrNull!.answers.whereType<DnsA>().single.address, [
        1,
        2,
        3,
        4,
      ]);

      final mismatched = PqDnsClient(
        exchange: (q) async => encodeDnsMessage(
          DnsMessage(id: (((q[0] << 8) | q[1]) + 1) & 0xffff, flags: 0x8400),
        ).valueOrNull!,
      );
      expect(
        (await mismatched.lookup('a.example.', DnsType.a)).isFailure,
        isTrue,
      );
    },
  );

  test('resolve follows CNAME and stops on a loop', () async {
    final client = PqDnsClient(
      exchange: (q) async {
        final asked = decodeDnsMessage(q).valueOrNull!;
        final name = asked.questions.single.name;
        final id = asked.id;
        if (dnsNamesEqual(name, 'alias.example.')) {
          return encodeDnsMessage(
            DnsMessage(
              id: id,
              flags: 0x8400,
              answers: [
                DnsCname(name: 'alias.example.', canonical: 'target.example.'),
              ],
            ),
          ).valueOrNull!;
        }
        return encodeDnsMessage(
          DnsMessage(
            id: id,
            flags: 0x8400,
            answers: [
              DnsA(
                name: 'target.example.',
                address: Uint8List.fromList(const [9, 9, 9, 9]),
              ),
            ],
          ),
        ).valueOrNull!;
      },
    );
    final got = await client.resolve('alias.example.', DnsType.a);
    expect(got.isSuccess, isTrue, reason: '${got.errorOrNull}');
    expect(got.valueOrNull!.answers.whereType<DnsA>().single.address, [
      9,
      9,
      9,
      9,
    ]);

    final loop = PqDnsClient(
      exchange: (q) async {
        final id = (q[0] << 8) | q[1];
        return encodeDnsMessage(
          DnsMessage(
            id: id,
            flags: 0x8400,
            answers: [DnsCname(name: 'a.example.', canonical: 'A.example.')],
          ),
        ).valueOrNull!;
      },
    );
    expect((await loop.resolve('a.example.', DnsType.a)).isFailure, isTrue);
  });

  test('Ed25519, P-384, and a wildcard verify', () {
    final seed = Uint8List(32)..[31] = 4;
    final key = DnsDnskey(
      name: 'example.com.',
      flags: dnssecZoneKeyFlag,
      protocol: dnssecProtocol,
      algorithm: dnssecAlgorithmEd25519,
      publicKey: PqEd25519.publicKeyFromSeed(seed),
    );
    final expanded = [
      DnsA(
        name: 'www.example.com.',
        address: Uint8List.fromList(const [192, 0, 2, 1]),
      ),
    ];
    final sig = _sign(expanded, key, seed, labels: 2);
    expect(
      verifyDnssecRrset(
        rrset: expanded,
        rrsig: sig,
        dnskey: key,
        now: now,
      ).isSuccess,
      isTrue,
    );

    final scalar = Uint8List(48)..[47] = 3;
    final point = PqEcdsaP384.publicKeyFromPrivate(scalar);
    final p384 = DnsDnskey(
      name: 'example.com.',
      flags: dnssecZoneKeyFlag,
      protocol: dnssecProtocol,
      algorithm: dnssecAlgorithmEcdsaP384Sha384,
      publicKey: Uint8List.sublistView(point, 1),
    );
    final a = [
      DnsA(
        name: 'example.com.',
        address: Uint8List.fromList(const [1, 0, 0, 1]),
      ),
    ];
    final signed = _sign(a, p384, scalar);
    expect(
      verifyDnssecRrset(
        rrset: a,
        rrsig: signed,
        dnskey: p384,
        now: now,
      ).isSuccess,
      isTrue,
    );
  });

  test('NSEC covers the gap and proves NODATA', () {
    expect(
      dnsNsecCovers('a.example.com.', 'c.example.com.', 'b.example.com.'),
      isTrue,
    );
    expect(
      dnsNsecCovers('a.example.com.', 'c.example.com.', 'a.example.com.'),
      isFalse,
    );
    final nodata = DnsNsec(
      name: 'www.example.com.',
      next: 'z.example.com.',
      types: dnsTypeBitmap(const [dnsTypeAaaa]),
    );
    expect(dnsNsecProvesNoData(nodata, 'www.example.com.', dnsTypeA), isTrue);
    expect(
      dnsNsecProvesNoData(nodata, 'www.example.com.', dnsTypeAaaa),
      isFalse,
    );
    final proved = dnsNsecProvesNameError(
      qname: 'b.example.com.',
      zone: 'example.com.',
      nsecs: [
        DnsNsec(
          name: 'a.example.com.',
          next: 'c.example.com.',
          types: dnsTypeBitmap(const [dnsTypeA]),
        ),
        DnsNsec(
          name: '\x00.example.com.',
          next: 'a.example.com.',
          types: dnsTypeBitmap(const [dnsTypeA]),
        ),
      ],
    );
    expect(proved.isSuccess, isTrue, reason: '${proved.errorOrNull}');
  });

  test(
    'a trust anchor authenticates a delegation and an NSEC denial',
    () async {
      final com = _zoneKey('com.', 1);
      final example = _zoneKey('example.com.', 2);
      final ds = _ds(example.key);
      final dsSig = _sign([ds], com.key, com.secret, signer: 'com.');
      final comSig = _sign([com.key], com.key, com.secret);
      final exampleSig = _sign([example.key], example.key, example.secret);
      final address = DnsA(
        name: 'www.example.com.',
        address: Uint8List.fromList(const [192, 0, 2, 9]),
      );
      final addressSig = _sign([address], example.key, example.secret);
      final cover = DnsNsec(
        name: 'a.example.com.',
        next: 'c.example.com.',
        types: dnsTypeBitmap(const [dnsTypeA]),
      );
      final wild = DnsNsec(
        name: '\x00.example.com.',
        next: 'a.example.com.',
        types: dnsTypeBitmap(const [dnsTypeA]),
      );

      Future<Result<DnsMessage, PqTransportError>> lookup(
        String name,
        DnsType type,
      ) async {
        DnsMessage message;
        if (dnsNamesEqual(name, 'com.') && type == DnsType.dnskey) {
          message = _msg([com.key, comSig]);
        } else if (dnsNamesEqual(name, 'example.com.') && type == DnsType.ds) {
          message = _msg([ds, dsSig]);
        } else if (dnsNamesEqual(name, 'example.com.') &&
            type == DnsType.dnskey) {
          message = _msg([example.key, exampleSig]);
        } else if (dnsNamesEqual(name, 'www.example.com.') &&
            type == DnsType.a) {
          message = _msg([address, addressSig]);
        } else if (dnsNamesEqual(name, 'b.example.com.')) {
          message = DnsMessage(
            id: 1,
            flags: 0x8403,
            authority: [
              cover,
              _sign([cover], example.key, example.secret),
              wild,
              _sign([wild], example.key, example.secret),
            ],
          );
        } else if (dnsNamesEqual(name, 'www.example.com.') &&
            type == DnsType.aaaa) {
          final nsec = DnsNsec(
            name: 'www.example.com.',
            next: 'z.example.com.',
            types: dnsTypeBitmap(const [dnsTypeA]),
          );
          message = DnsMessage(
            id: 1,
            flags: 0x8400,
            authority: [
              nsec,
              _sign([nsec], example.key, example.secret),
            ],
          );
        } else {
          return Result.failure(PqTransportError.unsupported('fixture'));
        }
        return Result.success(message);
      }

      final anchor = DnsTrustAnchor.dnskey(zone: 'com.', dnskey: com.key);
      final data = await authenticateDns(
        name: 'www.example.com.',
        type: DnsType.a,
        anchor: anchor,
        lookup: lookup,
        now: now,
      );
      expect(data.isSuccess, isTrue, reason: '${data.errorOrNull}');
      expect((data.valueOrNull! as DnsAuthData).records.single, isA<DnsA>());

      final missing = await authenticateDns(
        name: 'b.example.com.',
        type: DnsType.a,
        anchor: anchor,
        lookup: lookup,
        now: now,
      );
      expect(missing.isSuccess, isTrue, reason: '${missing.errorOrNull}');
      expect((missing.valueOrNull! as DnsAuthDenial).nameError, isTrue);

      final nodata = await authenticateDns(
        name: 'www.example.com.',
        type: DnsType.aaaa,
        anchor: anchor,
        lookup: lookup,
        now: now,
      );
      expect(nodata.isSuccess, isTrue, reason: '${nodata.errorOrNull}');
      expect((nodata.valueOrNull! as DnsAuthDenial).nameError, isFalse);
    },
  );

  test('RSASHA256 verifies through pqforge', () {
    final pair = PqRsa.generateKeyPair();
    final pub = BytesBuilder(copy: false)
      ..addByte(pair.exponent.length)
      ..add(pair.exponent)
      ..add(pair.modulus);
    final key = DnsDnskey(
      name: 'example.com.',
      flags: dnssecZoneKeyFlag,
      protocol: dnssecProtocol,
      algorithm: dnssecAlgorithmRsaSha256,
      publicKey: pub.takeBytes(),
    );
    final rrset = [
      DnsA(
        name: 'example.com.',
        address: Uint8List.fromList(const [1, 2, 3, 4]),
      ),
    ];
    final unsigned = DnsRrsig(
      name: 'example.com.',
      typeCovered: dnsTypeA,
      algorithm: dnssecAlgorithmRsaSha256,
      labels: 2,
      originalTtl: 3600,
      expiration: expiration,
      inception: inception,
      keyTag: dnssecKeyTag(dnskeyWireRdata(key)),
      signer: 'example.com.',
      signature: Uint8List(pair.modulus.length),
    );
    final material = dnssecSignedMaterial(rrset: rrset, rrsig: unsigned);
    expect(material.isSuccess, isTrue, reason: '${material.errorOrNull}');
    final signature = PqRsa.signPkcs1(
      privateKey: pair.privateKey,
      message: material.valueOrNull!,
      hash: PqRsaHash.sha256,
    );
    final signed = DnsRrsig(
      name: unsigned.name,
      typeCovered: unsigned.typeCovered,
      algorithm: unsigned.algorithm,
      labels: unsigned.labels,
      originalTtl: unsigned.originalTtl,
      expiration: unsigned.expiration,
      inception: unsigned.inception,
      keyTag: unsigned.keyTag,
      signer: unsigned.signer,
      signature: signature,
    );
    expect(
      verifyDnssecRrset(
        rrset: rrset,
        rrsig: signed,
        dnskey: key,
        now: now,
      ).isSuccess,
      isTrue,
    );
  }, timeout: const Timeout(Duration(minutes: 2)));

  test('NSEC3 hash is the RFC 5155 appendix vector', () {
    final hash = dnsNsec3Hash(
      name: 'example.',
      algorithm: dnssecNsec3HashSha1,
      iterations: 12,
      salt: Uint8List.fromList(const [0xaa, 0xbb, 0xcc, 0xdd]),
    );
    expect(hash.isSuccess, isTrue, reason: '${hash.errorOrNull}');
    expect(
      dnsNsec3Base32Hex(hash.valueOrNull!),
      '0p9mhaveqvm6t7vbl5lop2u3t2rp3tom',
    );
    final owner = dnsNsec3OwnerName(hash.valueOrNull!, 'example.');
    expect(owner, '0p9mhaveqvm6t7vbl5lop2u3t2rp3tom.example.');
    expect(dnsNsec3OwnerHash(owner!, 'example.'), hash.valueOrNull);
    expect(
      dnsNsec3Hash(
        name: 'example.',
        algorithm: 2,
        iterations: 0,
        salt: Uint8List(0),
      ).isFailure,
      isTrue,
    );
    expect(
      dnsNsec3Hash(
        name: 'example.',
        algorithm: dnssecNsec3HashSha1,
        iterations: dnsNsec3MaxIterations + 1,
        salt: Uint8List(0),
      ).isFailure,
      isTrue,
    );
  });

  test('SHA-1 DS digest matches a DNSKEY', () {
    final zone = _zoneKey('example.com.', 7);
    final rdata = dnskeyWireRdata(zone.key);
    final owner = dnsCanonicalName(zone.key.name).valueOrNull!;
    final ds = DnsDs(
      name: zone.key.name,
      keyTag: dnssecKeyTag(rdata),
      algorithm: zone.key.algorithm,
      digestType: dnssecDigestSha1,
      digest: PqBytes.sha1(concatBytes([owner, rdata])),
    );
    expect(dnskeyMatchesDs(zone.key, ds), isTrue);
    ds.digest[0] ^= 0x01;
    expect(dnskeyMatchesDs(zone.key, ds), isFalse);
  });

  test('NSEC3 proves name error, NODATA, opt-out DS, and a wildcard', () async {
    final zone = _zoneKey('example.com.', 4);
    final zoneSig = _sign([zone.key], zone.key, zone.secret);
    final apex = dnsNsec3Hash(
      name: 'example.com.',
      algorithm: dnssecNsec3HashSha1,
      iterations: 0,
      salt: Uint8List(0),
    ).valueOrNull!;
    final only = DnsNsec3(
      name: dnsNsec3OwnerName(apex, 'example.com.')!,
      hashAlgorithm: dnssecNsec3HashSha1,
      flags: 0,
      iterations: 0,
      salt: Uint8List(0),
      next: apex,
      types: dnsTypeBitmap(const [dnsTypeA, dnsTypeNs, dnsTypeSoa]),
    );
    final opted = DnsNsec3(
      name: only.name,
      hashAlgorithm: dnssecNsec3HashSha1,
      flags: dnsNsec3OptOutFlag,
      iterations: 0,
      salt: Uint8List(0),
      next: apex,
      types: dnsTypeBitmap(const [dnsTypeNs, dnsTypeSoa]),
    );
    final expanded = DnsA(
      name: 'www.example.com.',
      address: Uint8List.fromList(const [192, 0, 2, 9]),
    );
    final expandedSig = _sign([expanded], zone.key, zone.secret, labels: 2);

    Future<Result<DnsMessage, PqTransportError>> lookup(
      String name,
      DnsType type,
    ) async {
      if (dnsNamesEqual(name, 'example.com.') && type == DnsType.dnskey) {
        return Result.success(_msg([zone.key, zoneSig]));
      }
      if (dnsNamesEqual(name, 'b.example.com.')) {
        return Result.success(
          DnsMessage(
            id: 1,
            flags: 0x8403,
            authority: [
              only,
              _sign([only], zone.key, zone.secret),
            ],
          ),
        );
      }
      if (dnsNamesEqual(name, 'example.com.') && type == DnsType.aaaa) {
        return Result.success(
          DnsMessage(
            id: 1,
            flags: 0x8400,
            authority: [
              only,
              _sign([only], zone.key, zone.secret),
            ],
          ),
        );
      }
      if (dnsNamesEqual(name, 'child.example.com.') && type == DnsType.ds) {
        return Result.success(
          DnsMessage(
            id: 1,
            flags: 0x8400,
            authority: [
              opted,
              _sign([opted], zone.key, zone.secret),
            ],
          ),
        );
      }
      if (dnsNamesEqual(name, 'child.example.com.') && type == DnsType.a) {
        return Result.success(
          DnsMessage(
            id: 1,
            flags: 0x8400,
            authority: [
              opted,
              _sign([opted], zone.key, zone.secret),
            ],
          ),
        );
      }
      if (dnsNamesEqual(name, 'www.example.com.') && type == DnsType.a) {
        return Result.success(
          DnsMessage(
            id: 1,
            flags: 0x8400,
            answers: [expanded, expandedSig],
            authority: [
              only,
              _sign([only], zone.key, zone.secret),
            ],
          ),
        );
      }
      return Result.failure(PqTransportError.unsupported('fixture'));
    }

    final anchor = DnsTrustAnchor.dnskey(
      zone: 'example.com.',
      dnskey: zone.key,
    );
    final missing = await authenticateDns(
      name: 'b.example.com.',
      type: DnsType.a,
      anchor: anchor,
      lookup: lookup,
      now: now,
    );
    expect(missing.isSuccess, isTrue, reason: '${missing.errorOrNull}');
    expect((missing.valueOrNull! as DnsAuthDenial).nameError, isTrue);

    final nodata = await authenticateDns(
      name: 'example.com.',
      type: DnsType.aaaa,
      anchor: anchor,
      lookup: lookup,
      now: now,
    );
    expect(nodata.isSuccess, isTrue, reason: '${nodata.errorOrNull}');
    expect((nodata.valueOrNull! as DnsAuthDenial).nameError, isFalse);

    final delegation = await authenticateDns(
      name: 'child.example.com.',
      type: DnsType.ds,
      anchor: anchor,
      lookup: lookup,
      now: now,
    );
    expect(delegation.isSuccess, isTrue, reason: '${delegation.errorOrNull}');
    expect((delegation.valueOrNull! as DnsAuthDenial).nameError, isFalse);

    final notOptOut = await authenticateDns(
      name: 'child.example.com.',
      type: DnsType.a,
      anchor: anchor,
      lookup: lookup,
      now: now,
    );
    expect(notOptOut.isFailure, isTrue);

    final wild = await authenticateDns(
      name: 'www.example.com.',
      type: DnsType.a,
      anchor: anchor,
      lookup: lookup,
      now: now,
    );
    expect(wild.isSuccess, isTrue, reason: '${wild.errorOrNull}');
    expect((wild.valueOrNull! as DnsAuthData).records.single, isA<DnsA>());
  });
}

DnsMessage _msg(List<DnsRecord> answers) =>
    DnsMessage(id: 1, flags: 0x8400, answers: answers);

typedef _Zone = ({DnsDnskey key, Uint8List secret});

_Zone _zoneKey(String name, int mark) {
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

DnsRrsig _sign(
  List<DnsRecord> rrset,
  DnsDnskey key,
  Uint8List secret, {
  String? signer,
  int? labels,
}) {
  final algorithm = key.algorithm;
  final sigLen = switch (algorithm) {
    dnssecAlgorithmEcdsaP384Sha384 => dnssecEcdsaP384SignatureBytes,
    dnssecAlgorithmRsaSha256 => secret.length,
    _ => dnssecEd25519SignatureBytes,
  };
  final unsigned = DnsRrsig(
    name: rrset.first.name,
    typeCovered: dnsRecordType(rrset.first),
    algorithm: algorithm,
    labels: labels ?? dnsLabelCount(rrset.first.name),
    originalTtl: 3600,
    expiration: 1893456000,
    inception: 1730419200,
    keyTag: dnssecKeyTag(dnskeyWireRdata(key)),
    signer: signer ?? key.name,
    signature: Uint8List(sigLen),
  );
  final material = dnssecSignedMaterial(rrset: rrset, rrsig: unsigned);
  if (material.isFailure) {
    throw StateError('${material.errorOrNull}');
  }
  final Uint8List signature;
  if (algorithm == dnssecAlgorithmEcdsaP384Sha384) {
    signature = PqEcdsaP384.sign(
      privateKey: secret,
      message: material.valueOrNull!,
    );
  } else {
    signature = PqEd25519.sign(
      secretKey: secret,
      message: material.valueOrNull!,
    );
  }
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
    signature: signature,
  );
}
