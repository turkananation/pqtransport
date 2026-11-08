import 'dart:io';
import 'dart:typed_data';

import 'package:pqforge/pqforge.dart';
import 'package:pqtransport/pqtransport.dart';
import 'package:swissarmyknife/swissarmyknife.dart';

/// In-memory DNSSEC. No sockets.
///
/// Signs one A record with Ed25519, then checks it two ways: one RRset
/// (`verifyDnssecRrset`) and a name (`authenticateDns`) from either a
/// DNSKEY anchor or a DS anchor. A flipped signature fails closed.
///
/// Live resolvers are `example/dns_live.dart`.
Future<void> main() async {
  final now = DateTime.utc(2026, 6, 1);
  final seed = Uint8List(32)..[0] = 7;
  final key = DnsDnskey(
    name: 'example.com.',
    flags: dnssecZoneKeyFlag,
    protocol: dnssecProtocol,
    algorithm: dnssecAlgorithmEd25519,
    publicKey: PqEd25519.publicKeyFromSeed(seed),
    ttl: 3600,
  );
  final address = DnsA(
    name: 'www.example.com.',
    address: Uint8List.fromList(const [192, 0, 2, 1]),
    ttl: 3600,
  );
  final addressSig = _sign([address], key, seed);
  final keySig = _sign([key], key, seed);

  final verified = verifyDnssecRrset(
    rrset: [address],
    rrsig: addressSig,
    dnskey: key,
    now: now,
  );
  if (verified.isFailure) {
    throw StateError('RRset verify failed: ${verified.errorOrNull}');
  }

  final lookup = _zone({
    ('example.com.', DnsType.dnskey): [key, keySig],
    ('www.example.com.', DnsType.a): [address, addressSig],
  });

  final fromKey = await authenticateDns(
    name: 'www.example.com.',
    type: DnsType.a,
    anchor: DnsTrustAnchor.dnskey(zone: 'example.com.', dnskey: key),
    lookup: lookup,
    now: now,
  );
  final fromDs = await authenticateDns(
    name: 'www.example.com.',
    type: DnsType.a,
    anchor: DnsTrustAnchor.ds(zone: 'example.com.', ds: _ds(key)),
    lookup: lookup,
    now: now,
  );
  final flipped = await authenticateDns(
    name: 'www.example.com.',
    type: DnsType.a,
    anchor: DnsTrustAnchor.dnskey(zone: 'example.com.', dnskey: key),
    lookup: _zone({
      ('example.com.', DnsType.dnskey): [key, keySig],
      ('www.example.com.', DnsType.a): [
        address,
        DnsRrsig(
          name: addressSig.name,
          typeCovered: addressSig.typeCovered,
          algorithm: addressSig.algorithm,
          labels: addressSig.labels,
          originalTtl: addressSig.originalTtl,
          expiration: addressSig.expiration,
          inception: addressSig.inception,
          keyTag: addressSig.keyTag,
          signer: addressSig.signer,
          signature: Uint8List.fromList(addressSig.signature)..[0] ^= 1,
        ),
      ],
    }),
    now: now,
  );

  _requireData(fromKey, 'dnskey anchor');
  _requireData(fromDs, 'ds anchor');
  if (flipped.isSuccess) {
    throw StateError('a flipped signature was accepted');
  }
  stdout.writeln('example.com Ed25519: secure from a DNSKEY and from a DS');
  stdout.writeln('flipped signature: ${flipped.errorOrNull}');
}

void _requireData(Result<DnsAuth, PqTransportError> result, String label) {
  if (result.isFailure) {
    throw StateError('$label: ${result.errorOrNull}');
  }
  final auth = result.valueOrNull!;
  if (auth is! DnsAuthData || auth.records.whereType<DnsA>().isEmpty) {
    throw StateError('$label did not return the A record');
  }
}

DnsLookup _zone(Map<(String, DnsType), List<DnsRecord>> rrsets) {
  return (name, type) async {
    final records = rrsets[(name, type)] ?? const <DnsRecord>[];
    return Result.success(DnsMessage(id: 1, flags: 0x8400, answers: records));
  };
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

DnsRrsig _sign(List<DnsRecord> rrset, DnsDnskey key, Uint8List seed) {
  final unsigned = DnsRrsig(
    name: rrset.first.name,
    typeCovered: dnsRecordType(rrset.first),
    algorithm: key.algorithm,
    labels: dnsLabelCount(rrset.first.name),
    originalTtl: 3600,
    expiration: 1893456000,
    inception: 1730419200,
    keyTag: dnssecKeyTag(dnskeyWireRdata(key)),
    signer: key.name,
    signature: Uint8List(dnssecEd25519SignatureBytes),
  );
  final material = dnssecSignedMaterial(rrset: rrset, rrsig: unsigned);
  if (material.isFailure) {
    throw StateError('${material.errorOrNull}');
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
    signature: PqEd25519.sign(secretKey: seed, message: material.valueOrNull!),
  );
}
