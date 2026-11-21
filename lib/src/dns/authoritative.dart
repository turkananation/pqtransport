import '../core/lengths.dart';
import 'dnssec.dart';
import 'records.dart';

/// One in-memory zone. This is not [DnsIterativeResolver], and the AD
/// bit is not set. AA is set only on an answer, a NODATA, or an
/// NXDOMAIN from this zone. A delegation clears AA.
final class DnsAuthoritativeZone {
  DnsAuthoritativeZone({
    required String origin,
    required this.soa,
    required this.nameservers,
    this.records = const [],
  }) : origin = _absolute(origin);

  final String origin;
  final DnsSoa soa;
  final List<DnsNs> nameservers;
  final List<DnsRecord> records;

  DnsMessage answer(DnsMessage query) {
    if (!query.isQuery || query.questions.length != 1) {
      return DnsMessage(id: query.id, flags: dnsFlagQr | dnsRcodeFormErr);
    }
    final q = query.questions.single;
    if (q.klass != dnsClassIn) {
      return DnsMessage(
        id: query.id,
        flags: dnsFlagQr | dnsRcodeRefused,
        questions: [q],
      );
    }
    if (!_inZone(q.name)) {
      return DnsMessage(
        id: query.id,
        flags: dnsFlagQr | dnsRcodeRefused,
        questions: [q],
      );
    }
    final name = _absolute(q.name);
    final cut = _delegation(name);
    if (cut != null) {
      final glue = <DnsRecord>[];
      for (final ns in cut) {
        glue.addAll(_glue(ns.nameserver));
      }
      return DnsMessage(
        id: query.id,
        flags: dnsFlagQr,
        questions: [q],
        authority: cut,
        additional: glue,
      );
    }
    final atName = _at(name);
    if (atName.isEmpty && !dnsNamesEqual(name, origin)) {
      return _negative(query.id, q, nx: true);
    }
    if (q.type == DnsType.ns && dnsNamesEqual(name, origin)) {
      return _aa(query.id, q, nameservers);
    }
    if (q.type == DnsType.soa && dnsNamesEqual(name, origin)) {
      return _aa(query.id, q, [soa]);
    }
    final typed = [
      for (final rr in atName)
        if (rr.type == q.type) rr,
    ];
    if (typed.isNotEmpty) return _aa(query.id, q, typed);
    final cname = [
      for (final rr in atName)
        if (rr.type == DnsType.cname) rr,
    ];
    if (cname.isNotEmpty && q.type != DnsType.cname) {
      return _aa(query.id, q, cname);
    }
    return _negative(query.id, q, nx: false);
  }

  DnsMessage _aa(int id, DnsQuestion q, List<DnsRecord> answers) {
    return DnsMessage(
      id: id,
      flags: dnsFlagQr | dnsFlagAa,
      questions: [q],
      answers: answers,
    );
  }

  DnsMessage _negative(int id, DnsQuestion q, {required bool nx}) {
    return DnsMessage(
      id: id,
      flags: dnsFlagQr | dnsFlagAa | (nx ? dnsRcodeNxDomain : 0),
      questions: [q],
      authority: [soa],
    );
  }

  bool _inZone(String name) {
    final key = dnsNameKey(_absolute(name));
    final apex = dnsNameKey(origin);
    if (key == null || apex == null) return false;
    if (key == apex) return true;
    return key.endsWith(apex);
  }

  List<DnsRecord> _at(String name) => [
    for (final rr in records)
      if (dnsNamesEqual(rr.name, name)) rr,
  ];

  List<DnsNs>? _delegation(String name) {
    final key = dnsNameKey(name);
    final apex = dnsNameKey(origin);
    if (key == null || apex == null || key == apex) return null;
    String? best;
    for (final ns in records.whereType<DnsNs>()) {
      final owner = dnsNameKey(_absolute(ns.name));
      if (owner == null || owner == apex) continue;
      if (key == owner || !key.endsWith(owner)) continue;
      if (best == null || owner.length > best.length) best = owner;
    }
    if (best == null) return null;
    return [
      for (final ns in records.whereType<DnsNs>())
        if (dnsNameKey(_absolute(ns.name)) == best) ns,
    ];
  }

  List<DnsRecord> _glue(String host) {
    if (!_inZone(host)) return const [];
    return [
      for (final rr in _at(_absolute(host)))
        if (rr.type == DnsType.a || rr.type == DnsType.aaaa) rr,
    ];
  }
}

String _absolute(String name) => name.endsWith('.') ? name : '$name.';
