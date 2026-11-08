import 'dart:typed_data';

import 'package:pqforge/pqforge.dart';
import 'package:pqtransport/pqtransport.dart';
import 'package:test/test.dart';

void main() {
  const inception = 1730419200; // 2024-11-01T00:00:00Z
  const expiration = 1893456000; // 2030-01-01T00:00:00Z
  final now = DateTime.utc(2026, 11, 8);

  late Uint8List secret;
  late DnsDnskey dnskey;
  late List<DnsA> rrset;
  late DnsRrsig rrsig;

  setUp(() {
    secret = Uint8List(32)..[31] = 7;
    final point = PqEcdsaP256.publicKeyFromPrivate(secret);
    dnskey = DnsDnskey(
      name: 'example.com.',
      flags: 256,
      protocol: dnssecProtocol,
      algorithm: dnssecAlgorithmEcdsaP256Sha256,
      publicKey: Uint8List.sublistView(point, 1),
      ttl: 3600,
    );
    // Presented high address first. Canonical order is the low address.
    rrset = [
      DnsA(
        name: 'www.example.com.',
        address: Uint8List.fromList(const [192, 0, 2, 2]),
        ttl: 60,
      ),
      DnsA(
        name: 'WWW.Example.COM.',
        address: Uint8List.fromList(const [192, 0, 2, 1]),
        ttl: 30,
      ),
    ];
    final unsigned = DnsRrsig(
      name: 'www.example.com.',
      typeCovered: dnsTypeA,
      algorithm: dnssecAlgorithmEcdsaP256Sha256,
      labels: 3,
      originalTtl: 3600,
      expiration: expiration,
      inception: inception,
      keyTag: dnssecKeyTag(dnskeyWireRdata(dnskey)),
      signer: 'Example.COM.',
      signature: Uint8List(dnssecEcdsaP256SignatureBytes),
      ttl: 3600,
    );
    final material = dnssecSignedMaterial(rrset: rrset, rrsig: unsigned);
    expect(material.isSuccess, isTrue, reason: '${material.errorOrNull}');
    final bytes = material.valueOrNull!;
    final low = _indexOf(bytes, const [192, 0, 2, 1]);
    final high = _indexOf(bytes, const [192, 0, 2, 2]);
    expect(low, greaterThanOrEqualTo(0));
    expect(high, greaterThan(low));
    final signature = PqEcdsaP256.sign(privateKey: secret, message: bytes);
    rrsig = DnsRrsig(
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
      ttl: unsigned.ttl,
    );
  });

  test('ECDSAP256SHA256 fixture verifies, including RRset order', () {
    final checked = verifyDnssecRrset(
      rrset: rrset,
      rrsig: rrsig,
      dnskey: dnskey,
      now: now,
    );
    expect(checked.isSuccess, isTrue, reason: '${checked.errorOrNull}');
  });

  test('a mutated signature fails closed', () {
    final bad = Uint8List.fromList(rrsig.signature)..[0] ^= 0x01;
    final checked = verifyDnssecRrset(
      rrset: rrset,
      rrsig: DnsRrsig(
        name: rrsig.name,
        typeCovered: rrsig.typeCovered,
        algorithm: rrsig.algorithm,
        labels: rrsig.labels,
        originalTtl: rrsig.originalTtl,
        expiration: rrsig.expiration,
        inception: rrsig.inception,
        keyTag: rrsig.keyTag,
        signer: rrsig.signer,
        signature: bad,
        ttl: rrsig.ttl,
      ),
      dnskey: dnskey,
      now: now,
    );
    expect(checked.isFailure, isTrue);
  });

  test('a mismatched owner name fails closed', () {
    final moved = [
      DnsA(name: 'other.example.com.', address: rrset[0].address, ttl: 60),
      DnsA(name: 'other.example.com.', address: rrset[1].address, ttl: 60),
    ];
    final checked = verifyDnssecRrset(
      rrset: moved,
      rrsig: DnsRrsig(
        name: rrsig.name,
        typeCovered: rrsig.typeCovered,
        algorithm: rrsig.algorithm,
        labels: 3,
        originalTtl: rrsig.originalTtl,
        expiration: rrsig.expiration,
        inception: rrsig.inception,
        keyTag: rrsig.keyTag,
        signer: rrsig.signer,
        signature: rrsig.signature,
        ttl: rrsig.ttl,
      ),
      dnskey: dnskey,
      now: now,
    );
    expect(checked.isFailure, isTrue);
  });

  test('inception and expiration fail closed on an injected clock', () {
    final before = verifyDnssecRrset(
      rrset: rrset,
      rrsig: rrsig,
      dnskey: dnskey,
      now: DateTime.utc(2024, 10, 31),
    );
    final atEnd = verifyDnssecRrset(
      rrset: rrset,
      rrsig: rrsig,
      dnskey: dnskey,
      now: DateTime.fromMillisecondsSinceEpoch(expiration * 1000, isUtc: true),
    );
    expect(before.isFailure, isTrue);
    expect(atEnd.isFailure, isTrue);
  });

  test('SHA-256 DS matches the DNSKEY and a mutated key does not', () {
    final rdata = dnskeyWireRdata(dnskey);
    final owner = dnsCanonicalName(dnskey.name).valueOrNull!;
    final digest = PqBytes.sha256(concatBytes([owner, rdata]));
    final ds = DnsDs(
      name: 'example.com.',
      keyTag: dnssecKeyTag(rdata),
      algorithm: dnssecAlgorithmEcdsaP256Sha256,
      digestType: dnssecDigestSha256,
      digest: digest,
    );
    expect(dnskeyMatchesDs(dnskey, ds), isTrue);
    final mutated = DnsDnskey(
      name: dnskey.name,
      flags: dnskey.flags,
      protocol: dnskey.protocol,
      algorithm: dnskey.algorithm,
      publicKey: Uint8List.fromList(dnskey.publicKey)..[0] ^= 0x01,
    );
    expect(dnskeyMatchesDs(mutated, ds), isFalse);
  });

  test('DNSKEY, DS, and RRSIG round-trip on the wire', () {
    final ds = DnsDs(
      name: 'example.com.',
      keyTag: rrsig.keyTag,
      algorithm: dnssecAlgorithmEcdsaP256Sha256,
      digestType: dnssecDigestSha256,
      digest: Uint8List(dnssecSha256DigestBytes),
    );
    final msg = DnsMessage(
      id: 7,
      flags: 0x8400,
      questions: [
        const DnsQuestion(name: 'example.com.', type: DnsType.dnskey),
      ],
      answers: [dnskey, ds, rrsig],
    );
    final encoded = encodeDnsMessage(msg);
    expect(encoded.isSuccess, isTrue, reason: '${encoded.errorOrNull}');
    final decoded = decodeDnsMessage(encoded.valueOrNull!);
    expect(decoded.isSuccess, isTrue, reason: '${decoded.errorOrNull}');
    final answers = decoded.valueOrNull!.answers;
    expect(answers[0], isA<DnsDnskey>());
    expect(answers[1], isA<DnsDs>());
    expect(answers[2], isA<DnsRrsig>());
    expect((answers[2] as DnsRrsig).signature, rrsig.signature);
    expect((answers[0] as DnsDnskey).publicKey, dnskey.publicKey);
  });

  test('AD is not validation', () async {
    final client = PqDnsClient(
      exchange: (q) async => encodeDnsMessage(
        DnsMessage(
          id: (q[0] << 8) | q[1],
          flags: 0x8420,
          questions: [
            const DnsQuestion(name: 'www.example.com.', type: DnsType.a),
          ],
          answers: rrset,
        ),
      ).valueOrNull!,
    );
    final looked = await client.lookup('www.example.com.', DnsType.a);
    expect(looked.isSuccess, isTrue);
    expect(looked.valueOrNull!.flags & 0x0020, 0x0020);
    final forged = verifyDnssecRrset(
      rrset: rrset,
      rrsig: DnsRrsig(
        name: rrsig.name,
        typeCovered: rrsig.typeCovered,
        algorithm: rrsig.algorithm,
        labels: rrsig.labels,
        originalTtl: rrsig.originalTtl,
        expiration: rrsig.expiration,
        inception: rrsig.inception,
        keyTag: rrsig.keyTag,
        signer: rrsig.signer,
        signature: Uint8List(dnssecEcdsaP256SignatureBytes),
        ttl: rrsig.ttl,
      ),
      dnskey: dnskey,
      now: now,
    );
    expect(forged.isFailure, isTrue);
  });

  test('canonical order is RDATA, not RDLENGTH', () {
    final rrset = [
      DnsTxt(name: 'example.com.', strings: ['\x7f']),
      DnsTxt(name: 'example.com.', strings: ['', 'A']),
    ];
    final unsigned = DnsRrsig(
      name: 'example.com.',
      typeCovered: dnsTypeTxt,
      algorithm: dnssecAlgorithmEcdsaP256Sha256,
      labels: 2,
      originalTtl: 3600,
      expiration: expiration,
      inception: inception,
      keyTag: 1,
      signer: 'example.com.',
      signature: Uint8List(dnssecEcdsaP256SignatureBytes),
    );
    final material = dnssecSignedMaterial(rrset: rrset, rrsig: unsigned);
    expect(material.isSuccess, isTrue, reason: '${material.errorOrNull}');
    final bytes = material.valueOrNull!;
    // rdlen 3, rdata 00 01 41 sorts before rdlen 2, rdata 01 7f.
    final longer = _indexOf(bytes, const [0x00, 0x03, 0x00, 0x01, 0x41]);
    final shorter = _indexOf(bytes, const [0x00, 0x02, 0x01, 0x7f]);
    expect(longer, greaterThanOrEqualTo(0));
    expect(shorter, greaterThan(longer));
  });

  test('signed material matches the RFC 4034 layout byte for byte', () {
    final material = dnssecSignedMaterial(
      rrset: [
        DnsA(
          name: 'A.Example.',
          address: Uint8List.fromList(const [192, 0, 2, 1]),
          ttl: 30,
        ),
      ],
      rrsig: DnsRrsig(
        name: 'A.Example.',
        typeCovered: dnsTypeA,
        algorithm: dnssecAlgorithmEcdsaP256Sha256,
        labels: 2,
        originalTtl: 3600,
        expiration: 100,
        inception: 10,
        keyTag: 42,
        signer: 'Example.',
        signature: Uint8List(dnssecEcdsaP256SignatureBytes),
        ttl: 60,
      ),
    );
    expect(material.isSuccess, isTrue, reason: '${material.errorOrNull}');
    expect(material.valueOrNull, <int>[
      0x00, 0x01, // type covered: A
      0x0d, // ECDSAP256SHA256
      0x02, // labels
      0x00, 0x00, 0x0e, 0x10, // original TTL 3600, not the RR TTL
      0x00, 0x00, 0x00, 0x64, // expiration
      0x00, 0x00, 0x00, 0x0a, // inception
      0x00, 0x2a, // key tag
      0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x00, // example.
      0x01, 0x61, 0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x00,
      0x00, 0x01, // type
      0x00, 0x01, // class IN
      0x00, 0x00, 0x0e, 0x10,
      0x00, 0x04,
      0xc0, 0x00, 0x02, 0x01,
    ]);
  });

  test('a DNSKEY without the zone bit fails closed', () {
    final key = DnsDnskey(
      name: dnskey.name,
      flags: 0,
      protocol: dnskey.protocol,
      algorithm: dnskey.algorithm,
      publicKey: dnskey.publicKey,
    );
    final signed = _sign(rrsig, key, rrset, secret);
    final checked = verifyDnssecRrset(
      rrset: rrset,
      rrsig: signed,
      dnskey: key,
      now: now,
    );
    expect(checked.isFailure, isTrue);
  });

  test('the SEP bit does not block a zone key', () {
    final key = DnsDnskey(
      name: dnskey.name,
      flags: dnssecZoneKeyFlag | 0x0001,
      protocol: dnskey.protocol,
      algorithm: dnskey.algorithm,
      publicKey: dnskey.publicKey,
    );
    final signed = _sign(rrsig, key, rrset, secret);
    final checked = verifyDnssecRrset(
      rrset: rrset,
      rrsig: signed,
      dnskey: key,
      now: now,
    );
    expect(checked.isSuccess, isTrue, reason: '${checked.errorOrNull}');
  });

  test('validity uses 32-bit serial arithmetic', () {
    const start = 0xFFFFFFF0;
    const end = 0x00000020;
    final unsigned = _withTimes(rrsig, inception: start, expiration: end);
    final material = dnssecSignedMaterial(rrset: rrset, rrsig: unsigned);
    expect(material.isSuccess, isTrue, reason: '${material.errorOrNull}');
    final signed = _withSignature(
      unsigned,
      PqEcdsaP256.sign(privateKey: secret, message: material.valueOrNull!),
    );
    DateTime at(int seconds) =>
        DateTime.fromMillisecondsSinceEpoch(seconds * 1000, isUtc: true);
    final beforeWrap = verifyDnssecRrset(
      rrset: rrset,
      rrsig: signed,
      dnskey: dnskey,
      now: at(0xFFFFFFF8),
    );
    final afterWrap = verifyDnssecRrset(
      rrset: rrset,
      rrsig: signed,
      dnskey: dnskey,
      now: at(0x10),
    );
    final pastEnd = verifyDnssecRrset(
      rrset: rrset,
      rrsig: signed,
      dnskey: dnskey,
      now: at(0x40),
    );
    expect(beforeWrap.isSuccess, isTrue, reason: '${beforeWrap.errorOrNull}');
    expect(afterWrap.isSuccess, isTrue, reason: '${afterWrap.errorOrNull}');
    expect(pastEnd.isFailure, isTrue);
  });

  test('a validity window of 2^31 seconds fails closed', () {
    final huge = _withTimes(rrsig, inception: 0, expiration: 0x80000000);
    final checked = verifyDnssecRrset(
      rrset: rrset,
      rrsig: huge,
      dnskey: dnskey,
      now: now,
    );
    expect(checked.isFailure, isTrue);
  });

  test('Ed448 algorithm 16 verifies and a flipped signature fails', () {
    final seed = Uint8List(dnssecEd448PublicKeyBytes)..[0] = 9;
    final key = DnsDnskey(
      name: 'example.com.',
      flags: dnssecZoneKeyFlag,
      protocol: dnssecProtocol,
      algorithm: dnssecAlgorithmEd448,
      publicKey: PqEd448.publicKeyFromSeed(seed),
      ttl: 3600,
    );
    final records = [
      DnsA(
        name: 'www.example.com.',
        address: Uint8List.fromList(const [192, 0, 2, 1]),
        ttl: 60,
      ),
    ];
    final unsigned = DnsRrsig(
      name: 'www.example.com.',
      typeCovered: dnsTypeA,
      algorithm: dnssecAlgorithmEd448,
      labels: 3,
      originalTtl: 60,
      expiration: expiration,
      inception: inception,
      keyTag: dnssecKeyTag(dnskeyWireRdata(key)),
      signer: 'example.com.',
      signature: Uint8List(dnssecEd448SignatureBytes),
      ttl: 60,
    );
    final material = dnssecSignedMaterial(rrset: records, rrsig: unsigned);
    expect(material.isSuccess, isTrue);
    final signature = PqEd448.sign(
      secretKey: seed,
      message: material.valueOrNull!,
    );
    final checked = verifyDnssecRrset(
      rrset: records,
      rrsig: _withSignature(unsigned, signature),
      dnskey: key,
      now: now,
    );
    expect(checked.isSuccess, isTrue);
    final flipped = Uint8List.fromList(signature)..[0] ^= 1;
    final bad = verifyDnssecRrset(
      rrset: records,
      rrsig: _withSignature(unsigned, flipped),
      dnskey: key,
      now: now,
    );
    expect(bad.isFailure, isTrue);
    expect(dnssecAlgorithmSupported(dnssecAlgorithmEd448), isTrue);
  });

  test('algorithms outside the suite do not verify', () {
    // RFC 8624: 1 RSAMD5, 3 DSA, 6 DSA-NSEC3-SHA1, and 12 ECC-GOST
    // must not be implemented. 17 is SM2SM3. pqforge has no SM2.
    for (final algorithm in const [1, 3, 6, 12, 17]) {
      expect(
        dnssecAlgorithmSupported(algorithm),
        isFalse,
        reason: '$algorithm',
      );
    }
  });

  group('RSA DNSKEY', () {
    final keys = <int, _RsaKey>{};
    const onVm = bool.fromEnvironment('dart.library.io');
    final sizes = onVm ? const [1024, 2048, 3072, 4096] : const [1024];

    setUpAll(() {
      keys[1024] = _rsa1024();
      if (!onVm) return;
      for (final bits in const [2048, 3072, 4096]) {
        final kp = PqRsa.generateKeyPair(modulusBits: bits);
        keys[bits] = (
          privateKey: kp.privateKey,
          modulus: kp.modulus,
          exponent: kp.exponent,
        );
      }
    });

    for (final bits in sizes) {
      for (final algorithm in const [
        dnssecAlgorithmRsaSha1,
        dnssecAlgorithmRsaSha1Nsec3Sha1,
        dnssecAlgorithmRsaSha256,
        dnssecAlgorithmRsaSha512,
      ]) {
        test(
          '$bits-bit algorithm $algorithm verifies and a flipped signature fails',
          () {
            final kp = keys[bits]!;
            final hash = switch (algorithm) {
              dnssecAlgorithmRsaSha512 => PqRsaHash.sha512,
              dnssecAlgorithmRsaSha256 => PqRsaHash.sha256,
              _ => PqRsaHash.sha1,
            };
            final key = DnsDnskey(
              name: 'example.com.',
              flags: dnssecZoneKeyFlag,
              protocol: dnssecProtocol,
              algorithm: algorithm,
              publicKey: _dnsRsaPublic(kp.modulus, kp.exponent),
              ttl: 3600,
            );
            final records = [
              DnsA(
                name: 'www.example.com.',
                address: Uint8List.fromList(const [192, 0, 2, 1]),
                ttl: 60,
              ),
            ];
            final unsigned = DnsRrsig(
              name: 'www.example.com.',
              typeCovered: dnsTypeA,
              algorithm: algorithm,
              labels: 3,
              originalTtl: 60,
              expiration: expiration,
              inception: inception,
              keyTag: dnssecKeyTag(dnskeyWireRdata(key)),
              signer: 'example.com.',
              signature: Uint8List(bits ~/ 8),
              ttl: 60,
            );
            final material = dnssecSignedMaterial(
              rrset: records,
              rrsig: unsigned,
            );
            expect(
              material.isSuccess,
              isTrue,
              reason: '${material.errorOrNull}',
            );
            final signature = PqRsa.signPkcs1(
              privateKey: kp.privateKey,
              message: material.valueOrNull!,
              hash: hash,
            );
            expect(signature, hasLength(bits ~/ 8));
            final checked = verifyDnssecRrset(
              rrset: records,
              rrsig: _withSignature(unsigned, signature),
              dnskey: key,
              now: now,
            );
            expect(checked.isSuccess, isTrue, reason: '${checked.errorOrNull}');
            final flipped = Uint8List.fromList(signature)..[0] ^= 1;
            expect(
              verifyDnssecRrset(
                rrset: records,
                rrsig: _withSignature(unsigned, flipped),
                dnskey: key,
                now: now,
              ).isFailure,
              isTrue,
            );
          },
        );
      }
    }

    test('the long RFC 3110 exponent form verifies a 1024-bit key', () {
      final kp = keys[1024]!;
      final key = DnsDnskey(
        name: 'example.com.',
        flags: dnssecZoneKeyFlag,
        protocol: dnssecProtocol,
        algorithm: dnssecAlgorithmRsaSha256,
        publicKey: _dnsRsaPublicLong(kp.modulus, kp.exponent),
        ttl: 3600,
      );
      expect(key.publicKey[0], 0);
      final records = [
        DnsA(
          name: 'www.example.com.',
          address: Uint8List.fromList(const [192, 0, 2, 1]),
          ttl: 60,
        ),
      ];
      final unsigned = DnsRrsig(
        name: 'www.example.com.',
        typeCovered: dnsTypeA,
        algorithm: dnssecAlgorithmRsaSha256,
        labels: 3,
        originalTtl: 60,
        expiration: expiration,
        inception: inception,
        keyTag: dnssecKeyTag(dnskeyWireRdata(key)),
        signer: 'example.com.',
        signature: Uint8List(128),
        ttl: 60,
      );
      final material = dnssecSignedMaterial(rrset: records, rrsig: unsigned);
      final signature = PqRsa.signPkcs1(
        privateKey: kp.privateKey,
        message: material.valueOrNull!,
        hash: PqRsaHash.sha256,
      );
      expect(
        verifyDnssecRrset(
          rrset: records,
          rrsig: _withSignature(unsigned, signature),
          dnskey: key,
          now: now,
        ).isSuccess,
        isTrue,
      );
    });

    test('a truncated RFC 3110 key does not verify', () {
      final kp = keys[1024]!;
      final key = DnsDnskey(
        name: 'example.com.',
        flags: dnssecZoneKeyFlag,
        protocol: dnssecProtocol,
        algorithm: dnssecAlgorithmRsaSha256,
        publicKey: Uint8List.fromList([3, 1, 0, 1]),
        ttl: 3600,
      );
      final records = [
        DnsA(
          name: 'www.example.com.',
          address: Uint8List.fromList(const [192, 0, 2, 1]),
          ttl: 60,
        ),
      ];
      final unsigned = DnsRrsig(
        name: 'www.example.com.',
        typeCovered: dnsTypeA,
        algorithm: dnssecAlgorithmRsaSha256,
        labels: 3,
        originalTtl: 60,
        expiration: expiration,
        inception: inception,
        keyTag: dnssecKeyTag(dnskeyWireRdata(key)),
        signer: 'example.com.',
        signature: Uint8List(128),
        ttl: 60,
      );
      expect(
        verifyDnssecRrset(
          rrset: records,
          rrsig: unsigned,
          dnskey: key,
          now: now,
        ).isFailure,
        isTrue,
      );
      expect(kp.modulus, hasLength(128));
    });

    test('RSA DS digests SHA-1, SHA-256, and SHA-384 match the DNSKEY', () {
      final kp = keys[1024]!;
      final key = DnsDnskey(
        name: 'example.com.',
        flags: dnssecZoneKeyFlag,
        protocol: dnssecProtocol,
        algorithm: dnssecAlgorithmRsaSha256,
        publicKey: _dnsRsaPublic(kp.modulus, kp.exponent),
        ttl: 3600,
      );
      final rdata = dnskeyWireRdata(key);
      final owner = dnsCanonicalName(key.name).valueOrNull!;
      final body = concatBytes([owner, rdata]);
      final digests = {
        dnssecDigestSha1: PqBytes.sha1(body),
        dnssecDigestSha256: PqBytes.sha256(body),
        dnssecDigestSha384: PqBytes.sha384(body),
      };
      for (final entry in digests.entries) {
        final ds = DnsDs(
          name: 'example.com.',
          keyTag: dnssecKeyTag(rdata),
          algorithm: dnssecAlgorithmRsaSha256,
          digestType: entry.key,
          digest: entry.value,
        );
        expect(dnskeyMatchesDs(key, ds), isTrue, reason: 'type ${entry.key}');
        final flipped = Uint8List.fromList(entry.value)..[0] ^= 1;
        expect(
          dnskeyMatchesDs(
            key,
            DnsDs(
              name: ds.name,
              keyTag: ds.keyTag,
              algorithm: ds.algorithm,
              digestType: ds.digestType,
              digest: flipped,
            ),
          ),
          isFalse,
        );
      }
      final set = DnsTrustAnchor.dsSet(
        zone: 'example.com.',
        ds: [
          DnsDs(
            name: 'example.com.',
            keyTag: 1,
            algorithm: dnssecAlgorithmRsaSha256,
            digestType: dnssecDigestSha256,
            digest: Uint8List(dnssecSha256DigestBytes),
          ),
          DnsDs(
            name: 'example.com.',
            keyTag: dnssecKeyTag(rdata),
            algorithm: dnssecAlgorithmRsaSha256,
            digestType: dnssecDigestSha256,
            digest: digests[dnssecDigestSha256]!,
          ),
        ],
      );
      expect(set.ds, isNull);
      expect(set.dsRecords.any((ds) => dnskeyMatchesDs(key, ds)), isTrue);
      final single = DnsTrustAnchor.ds(
        zone: 'example.com.',
        ds: set.dsRecords[1],
      );
      expect(single.ds, isNotNull);
    });
  }, timeout: const Timeout(Duration(minutes: 3)));
}

int _indexOf(Uint8List haystack, List<int> needle) {
  for (var i = 0; i + needle.length <= haystack.length; i++) {
    var match = true;
    for (var j = 0; j < needle.length; j++) {
      if (haystack[i + j] != needle[j]) {
        match = false;
        break;
      }
    }
    if (match) return i;
  }
  return -1;
}

DnsRrsig _sign(
  DnsRrsig from,
  DnsDnskey key,
  List<DnsRecord> rrset,
  Uint8List secret,
) {
  final unsigned = _withKeyTag(from, dnssecKeyTag(dnskeyWireRdata(key)));
  final material = dnssecSignedMaterial(rrset: rrset, rrsig: unsigned);
  if (material.isFailure) {
    throw StateError('${material.errorOrNull}');
  }
  return _withSignature(
    unsigned,
    PqEcdsaP256.sign(privateKey: secret, message: material.valueOrNull!),
  );
}

DnsRrsig _withKeyTag(DnsRrsig from, int keyTag) => DnsRrsig(
  name: from.name,
  typeCovered: from.typeCovered,
  algorithm: from.algorithm,
  labels: from.labels,
  originalTtl: from.originalTtl,
  expiration: from.expiration,
  inception: from.inception,
  keyTag: keyTag,
  signer: from.signer,
  signature: from.signature,
  ttl: from.ttl,
);

DnsRrsig _withTimes(
  DnsRrsig from, {
  required int inception,
  required int expiration,
}) => DnsRrsig(
  name: from.name,
  typeCovered: from.typeCovered,
  algorithm: from.algorithm,
  labels: from.labels,
  originalTtl: from.originalTtl,
  expiration: expiration,
  inception: inception,
  keyTag: from.keyTag,
  signer: from.signer,
  signature: from.signature,
  ttl: from.ttl,
);

DnsRrsig _withSignature(DnsRrsig from, Uint8List signature) => DnsRrsig(
  name: from.name,
  typeCovered: from.typeCovered,
  algorithm: from.algorithm,
  labels: from.labels,
  originalTtl: from.originalTtl,
  expiration: from.expiration,
  inception: from.inception,
  keyTag: from.keyTag,
  signer: from.signer,
  signature: signature,
  ttl: from.ttl,
);

/// RFC 3110. Exponent length, exponent, modulus.
Uint8List _dnsRsaPublic(Uint8List modulus, Uint8List exponent) {
  if (exponent.length < 256) {
    return Uint8List.fromList([exponent.length, ...exponent, ...modulus]);
  }
  return Uint8List.fromList([
    0,
    exponent.length >> 8,
    exponent.length & 0xff,
    ...exponent,
    ...modulus,
  ]);
}

/// RFC 3110 long form, including a short exponent.
Uint8List _dnsRsaPublicLong(Uint8List modulus, Uint8List exponent) {
  return Uint8List.fromList([
    0,
    exponent.length >> 8,
    exponent.length & 0xff,
    ...exponent,
    ...modulus,
  ]);
}

typedef _RsaKey = ({
  PqRsaPrivateKey privateKey,
  Uint8List modulus,
  Uint8List exponent,
});

/// 1024-bit PKCS#1 fixture. `generateKeyPair` refuses this size.
_RsaKey _rsa1024() {
  final modulus = _unhex(
    '87f1a099720c0314443fffc8143cd05895a6b8f3989c9d0e447f15b0d47d132b'
    'cde8917f0e08b6cde32168360bb47b6acf780d6edf399d79bee88e63482d6861'
    'd28afd30b346b8547faf61bb8777312152ca955f91bc860d8444e3c6467324d7'
    'e53c229cf431a92168893495354baaa97667cf362694d9513fb9aa43e1ea6c6b',
  );
  final exponent = _unhex('010001');
  return (
    modulus: modulus,
    exponent: exponent,
    privateKey: PqRsaPrivateKey(
      modulus: modulus,
      publicExponent: exponent,
      privateExponent: _unhex(
        '5b3b6f7a4b2d808b835a2800508497963ba88e0afcea6e047b3786890bb17cc2'
        '3307d74d1b5001ce9e9576e87e667b452d42f650e802348ad5f2204cc4cda474'
        'ad7cd6f319fb0700e75ccd2884c68ec15d23b78c84fd4d09b366da262d08916b'
        'd6044454fbff07193b962872a012c6374f09df83a8746dfeb0ccb8090e90e4e1',
      ),
      prime1: _unhex(
        'f74ccad20bcdeea87f759ce548f6602294b223eb14337c77bd45b8bbc346055c'
        'e3c0a8d357e36e1ea052ce7d82a15074bb52a6f9d910dd2757faeaa18d7c2293',
      ),
      prime2: _unhex(
        '8cb9f376210122728fba3fbc7899085c59769aafc090e2269723097c403f41d7'
        'be057ab0323257f8f3f6a0e6237bab75e6f37fdc6d39b941706164bdd298fdc9',
      ),
    ),
  );
}

Uint8List _unhex(String hex) {
  final out = Uint8List(hex.length ~/ 2);
  for (var i = 0; i < out.length; i++) {
    out[i] = int.parse(hex.substring(i * 2, i * 2 + 2), radix: 16);
  }
  return out;
}
