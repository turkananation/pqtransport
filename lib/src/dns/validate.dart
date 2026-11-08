import 'package:swissarmyknife/swissarmyknife.dart';

import '../core/errors.dart';
import '../core/lengths.dart';
import 'dnssec.dart';
import 'records.dart';

typedef DnsLookup =
    Future<Result<DnsMessage, PqTransportError>> Function(
      String name,
      DnsType type,
    );

/// A DS set or a DNSKEY the caller already trusts. This is not fetched.
final class DnsTrustAnchor {
  DnsTrustAnchor.ds({required String zone, required DnsDs ds})
    : this._(zone: zone, dsRecords: [ds], dnskey: null);

  /// More than one DS. The root publishes two KSKs.
  DnsTrustAnchor.dsSet({required String zone, required List<DnsDs> ds})
    : this._(zone: zone, dsRecords: ds, dnskey: null);

  DnsTrustAnchor.dnskey({required String zone, required DnsDnskey dnskey})
    : this._(zone: zone, dsRecords: const [], dnskey: dnskey);

  DnsTrustAnchor._({
    required this.zone,
    required this.dsRecords,
    required this.dnskey,
  });

  final String zone;
  final List<DnsDs> dsRecords;
  final DnsDnskey? dnskey;

  /// The only DS, or null when the anchor is a key or a set.
  DnsDs? get ds => dsRecords.length == 1 ? dsRecords.single : null;
}

sealed class DnsAuth {
  const DnsAuth();
}

/// Records whose RRSIG verified under [DnsTrustAnchor].
final class DnsAuthData extends DnsAuth {
  const DnsAuthData(this.records);
  final List<DnsRecord> records;
}

/// An NSEC proof. [nameError] is NXDOMAIN. Otherwise the name has no such type.
final class DnsAuthDenial extends DnsAuth {
  const DnsAuthDenial({required this.nameError});
  final bool nameError;
}

/// RFC 4035 validator for one name.
///
/// [lookup] is one query. Pass [PqDnsClient.lookup], not [PqDnsClient.resolve]:
/// CNAME hops are validated here. The trust chain walks from [anchor] down to
/// the signer. NSEC and NSEC3 prove denial. NSEC3 is hash algorithm 1 only
/// (SHA-1 from pqforge, RFC 5155). The iteration field allows 0 through
/// 65535. The AD bit is not consulted.
Future<Result<DnsAuth, PqTransportError>> authenticateDns({
  required String name,
  required DnsType type,
  required DnsTrustAnchor anchor,
  required DnsLookup lookup,
  required DateTime now,
}) {
  return _Validator(anchor, lookup, now).run(name, type, <String>{});
}

final class _Validator {
  _Validator(this.anchor, this.lookup, this.now);

  final DnsTrustAnchor anchor;
  final DnsLookup lookup;
  final DateTime now;
  final Map<String, List<DnsDnskey>> _keys = {};

  Future<Result<DnsAuth, PqTransportError>> run(
    String name,
    DnsType type,
    Set<String> seen,
  ) async {
    final id = dnsNameKey(name);
    if (id == null || !seen.add('$id ${dnsTypeValue(type)}')) {
      return Result.failure(PqTransportError.unsupported('cname loop'));
    }
    if (seen.length > dnsCnameLimit) {
      return Result.failure(PqTransportError.unsupported('cname limit'));
    }
    final got = await lookup(name, type);
    if (got.isFailure) return Result.failure(got.errorOrNull!);
    final msg = got.valueOrNull!;
    final rcode = msg.flags & dnsRcodeMask;
    if (rcode == dnsRcodeNxDomain) {
      return _denial(msg, name, dnsTypeValue(type), nameError: true);
    }
    if (rcode != 0) {
      return Result.failure(PqTransportError.unexpectedMessage('dns rcode'));
    }
    if (type != DnsType.cname) {
      final cname = _of(msg.answers, name, dnsTypeCname);
      if (cname.isNotEmpty) {
        final signed = await _verify(cname, msg.answers);
        if (signed.isFailure) return Result.failure(signed.errorOrNull!);
        return run((cname.first as DnsCname).canonical, type, seen);
      }
    }
    final rrset = _of(msg.answers, name, dnsTypeValue(type));
    if (rrset.isEmpty) {
      return _denial(msg, name, dnsTypeValue(type), nameError: false);
    }
    final sig = await _verify(rrset, msg.answers);
    if (sig.isFailure) return Result.failure(sig.errorOrNull!);
    if (sig.valueOrNull!.labels < dnsLabelCount(name)) {
      if (msg.authority.whereType<DnsNsec>().isEmpty &&
          msg.authority.whereType<DnsNsec3>().isNotEmpty) {
        final proof = await _nsec3Wildcard(msg, sig.valueOrNull!.signer, name);
        if (proof.isFailure) return Result.failure(proof.errorOrNull!);
      } else {
        final nsecs = await _nsecs(msg, sig.valueOrNull!.signer);
        if (nsecs.isFailure) return Result.failure(nsecs.errorOrNull!);
        if (!nsecs.valueOrNull!.any(
          (n) => dnsNsecCovers(n.name, n.next, name),
        )) {
          return Result.failure(
            PqTransportError.unexpectedMessage('wildcard nsec'),
          );
        }
      }
    }
    return Result.success(DnsAuthData(rrset));
  }

  Future<Result<DnsRrsig, PqTransportError>> _verify(
    List<DnsRecord> rrset,
    List<DnsRecord> section,
  ) async {
    final sigs = _sigs(section, rrset.first.name, dnsRecordType(rrset.first));
    if (sigs.isEmpty) {
      return Result.failure(
        PqTransportError.unexpectedMessage('rrsig missing'),
      );
    }
    final keys = await _zoneKeys(sigs.first.signer);
    if (keys.isFailure) return Result.failure(keys.errorOrNull!);
    final matched = _matched(rrset, sigs, keys.valueOrNull!);
    if (matched == null) {
      return Result.failure(PqTransportError.unexpectedMessage('rrsig'));
    }
    return Result.success(matched);
  }

  DnsRrsig? _matched(
    List<DnsRecord> rrset,
    List<DnsRrsig> sigs,
    List<DnsDnskey> keys,
  ) {
    for (final sig in sigs) {
      for (final key in keys) {
        if (verifyDnssecRrset(
          rrset: rrset,
          rrsig: sig,
          dnskey: key,
          now: now,
        ).isSuccess) {
          return sig;
        }
      }
    }
    return null;
  }

  Future<Result<DnsAuth, PqTransportError>> _denial(
    DnsMessage msg,
    String qname,
    int qtype, {
    required bool nameError,
  }) async {
    if (msg.authority.whereType<DnsNsec>().isEmpty) {
      if (msg.authority.whereType<DnsNsec3>().isNotEmpty) {
        return _nsec3Denial(msg, qname, qtype, nameError: nameError);
      }
      return Result.failure(PqTransportError.unexpectedMessage('nsec missing'));
    }
    final signer = _sigs(
      msg.authority,
      msg.authority.whereType<DnsNsec>().first.name,
      dnsTypeNsec,
    );
    if (signer.isEmpty) {
      return Result.failure(PqTransportError.unexpectedMessage('nsec sig'));
    }
    final nsecs = await _nsecs(msg, signer.first.signer);
    if (nsecs.isFailure) return Result.failure(nsecs.errorOrNull!);
    if (nameError) {
      final proof = dnsNsecProvesNameError(
        qname: qname,
        zone: signer.first.signer,
        nsecs: nsecs.valueOrNull!,
      );
      if (proof.isFailure) return Result.failure(proof.errorOrNull!);
      return const Result.success(DnsAuthDenial(nameError: true));
    }
    if (!nsecs.valueOrNull!.any((n) => dnsNsecProvesNoData(n, qname, qtype))) {
      return Result.failure(PqTransportError.unexpectedMessage('nsec nodata'));
    }
    return const Result.success(DnsAuthDenial(nameError: false));
  }

  Future<Result<List<DnsNsec>, PqTransportError>> _nsecs(
    DnsMessage msg,
    String signer,
  ) async {
    final keys = await _zoneKeys(signer);
    if (keys.isFailure) return Result.failure(keys.errorOrNull!);
    final out = <DnsNsec>[];
    for (final nsec in msg.authority.whereType<DnsNsec>()) {
      final sigs = _sigs(msg.authority, nsec.name, dnsTypeNsec);
      final ok = _matched([nsec], sigs, keys.valueOrNull!);
      if (ok == null) {
        return Result.failure(PqTransportError.unexpectedMessage('nsec sig'));
      }
      out.add(nsec);
    }
    if (out.isEmpty) {
      return Result.failure(PqTransportError.unexpectedMessage('nsec missing'));
    }
    return Result.success(out);
  }

  Future<Result<DnsAuth, PqTransportError>> _nsec3Denial(
    DnsMessage msg,
    String qname,
    int qtype, {
    required bool nameError,
  }) async {
    final first = msg.authority.whereType<DnsNsec3>().first;
    final sigs = _sigs(msg.authority, first.name, dnsTypeNsec3);
    if (sigs.isEmpty) {
      return Result.failure(PqTransportError.unexpectedMessage('nsec3 sig'));
    }
    final rows = await _nsec3s(msg, sigs.first.signer);
    if (rows.isFailure) return Result.failure(rows.errorOrNull!);
    final proof = nameError
        ? dnsNsec3ProvesNameError(
            qname: qname,
            zone: sigs.first.signer,
            nsecs: rows.valueOrNull!,
          )
        : dnsNsec3ProvesNoData(
            qname: qname,
            zone: sigs.first.signer,
            qtype: qtype,
            nsecs: rows.valueOrNull!,
          );
    if (proof.isFailure) return Result.failure(proof.errorOrNull!);
    return Result.success(DnsAuthDenial(nameError: nameError));
  }

  Future<Result<void, PqTransportError>> _nsec3Wildcard(
    DnsMessage msg,
    String signer,
    String qname,
  ) async {
    final rows = await _nsec3s(msg, signer);
    if (rows.isFailure) return Result.failure(rows.errorOrNull!);
    return dnsNsec3ProvesWildcard(
      qname: qname,
      zone: signer,
      nsecs: rows.valueOrNull!,
    );
  }

  Future<Result<List<DnsNsec3>, PqTransportError>> _nsec3s(
    DnsMessage msg,
    String signer,
  ) async {
    final keys = await _zoneKeys(signer);
    if (keys.isFailure) return Result.failure(keys.errorOrNull!);
    final out = <DnsNsec3>[];
    for (final nsec in msg.authority.whereType<DnsNsec3>()) {
      final sigs = _sigs(msg.authority, nsec.name, dnsTypeNsec3);
      final ok = _matched([nsec], sigs, keys.valueOrNull!);
      if (ok == null) {
        return Result.failure(PqTransportError.unexpectedMessage('nsec3 sig'));
      }
      out.add(nsec);
    }
    if (out.isEmpty) {
      return Result.failure(
        PqTransportError.unexpectedMessage('nsec3 missing'),
      );
    }
    return Result.success(out);
  }

  Future<Result<List<DnsDnskey>, PqTransportError>> _zoneKeys(
    String zone,
  ) async {
    final cached = _keys[dnsNameKey(zone)];
    if (cached != null) return Result.success(cached);
    if (!dnsNamesEqual(zone, anchor.zone) && !_below(zone, anchor.zone)) {
      return Result.failure(PqTransportError.unexpectedMessage('trust zone'));
    }
    final path = _path(anchor.zone, zone);
    if (path == null) {
      return Result.failure(PqTransportError.unexpectedMessage('trust zone'));
    }
    List<DnsDnskey>? parent;
    for (final hop in path) {
      final keys = await _keysAt(hop, parent);
      if (keys.isFailure) return keys;
      parent = keys.valueOrNull;
      _keys[dnsNameKey(hop)!] = parent!;
    }
    return Result.success(parent!);
  }

  Future<Result<List<DnsDnskey>, PqTransportError>> _keysAt(
    String zone,
    List<DnsDnskey>? parent,
  ) async {
    if (parent != null) {
      final dsMsg = await lookup(zone, DnsType.ds);
      if (dsMsg.isFailure) return Result.failure(dsMsg.errorOrNull!);
      final dsSet = _of(dsMsg.valueOrNull!.answers, zone, dnsTypeDs);
      final dsOk = _matched(
        dsSet,
        _sigs(dsMsg.valueOrNull!.answers, zone, dnsTypeDs),
        parent,
      );
      if (dsOk == null) {
        return Result.failure(PqTransportError.unexpectedMessage('ds'));
      }
      final anchors = dsSet.whereType<DnsDs>().toList();
      return _selfSigned(zone, anchors, null);
    }
    if (anchor.dsRecords.isNotEmpty) {
      return _selfSigned(zone, anchor.dsRecords, null);
    }
    return _selfSigned(zone, const [], anchor.dnskey);
  }

  Future<Result<List<DnsDnskey>, PqTransportError>> _selfSigned(
    String zone,
    List<DnsDs> ds,
    DnsDnskey? pinned,
  ) async {
    final msg = await lookup(zone, DnsType.dnskey);
    if (msg.isFailure) return Result.failure(msg.errorOrNull!);
    final keys = _of(msg.valueOrNull!.answers, zone, dnsTypeDnskey);
    final trusted = <DnsDnskey>[
      for (final rr in keys)
        if (rr is DnsDnskey &&
            (pinned != null
                ? _sameKey(rr, pinned)
                : ds.any((item) => dnskeyMatchesDs(rr, item))))
          rr,
    ];
    if (trusted.isEmpty) {
      return Result.failure(PqTransportError.unexpectedMessage('dnskey'));
    }
    if (_matched(
          keys,
          _sigs(msg.valueOrNull!.answers, zone, dnsTypeDnskey),
          trusted,
        ) ==
        null) {
      return Result.failure(PqTransportError.unexpectedMessage('dnskey'));
    }
    return Result.success([
      for (final rr in keys)
        if (rr is DnsDnskey) rr,
    ]);
  }

  List<DnsRecord> _of(List<DnsRecord> records, String owner, int type) => [
    for (final rr in records)
      if (rr is! DnsRrsig &&
          rr is! DnsOpt &&
          dnsNamesEqual(rr.name, owner) &&
          dnsRecordType(rr) == type)
        rr,
  ];

  List<DnsRrsig> _sigs(List<DnsRecord> records, String owner, int type) => [
    for (final rr in records)
      if (rr is DnsRrsig &&
          dnsNamesEqual(rr.name, owner) &&
          rr.typeCovered == type)
        rr,
  ];
}

bool _sameKey(DnsDnskey a, DnsDnskey b) =>
    dnsNamesEqual(a.name, b.name) &&
    a.algorithm == b.algorithm &&
    a.protocol == b.protocol &&
    a.publicKey.length == b.publicKey.length &&
    _bytesEq(a.publicKey, b.publicKey);

bool _bytesEq(List<int> a, List<int> b) {
  if (a.length != b.length) return false;
  for (var i = 0; i < a.length; i++) {
    if (a[i] != b[i]) return false;
  }
  return true;
}

bool _below(String name, String zone) {
  var current = name;
  while (true) {
    final parent = dnsParent(current);
    if (parent == null) return false;
    if (dnsNamesEqual(parent, zone) || dnsNamesEqual(current, zone)) {
      return dnsNamesEqual(current, zone) ? false : true;
    }
    if (dnsNamesEqual(parent, zone)) return true;
    current = parent;
  }
}

List<String>? _path(String anchor, String zone) {
  if (dnsNamesEqual(anchor, zone)) return [zone];
  final hops = <String>[zone];
  var current = zone;
  while (true) {
    final parent = dnsParent(current);
    if (parent == null) return null;
    hops.add(parent);
    if (dnsNamesEqual(parent, anchor)) {
      return hops.reversed.toList();
    }
    current = parent;
  }
}
