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
    final response = DnsMessage(
      id: 9,
      flags: 0x8420,
      questions: [const DnsQuestion(name: 'www.example.com.', type: DnsType.a)],
      answers: rrset,
    );
    final wire = encodeDnsMessage(response).valueOrNull!;
    final client = PqDnsClient(exchange: (_) async => wire);
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
