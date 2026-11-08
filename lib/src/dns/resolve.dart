import 'dart:math';
import 'dart:typed_data';

import 'package:swissarmyknife/swissarmyknife.dart';

import '../core/errors.dart';
import '../core/lengths.dart';
import 'dnssec.dart';
import 'pq_dns_client.dart';
import 'records.dart';
import 'validate.dart';

/// RFC 4033. Secure has a chain to [DnsTrustAnchor]. Insecure was proved
/// unsigned. Bogus failed validation and is not cached.
enum DnsSecurity { secure, insecure, bogus }

/// One iterative lookup. [records] is empty when [nameError] is set or the
/// type is absent.
final class DnsResolution {
  const DnsResolution({
    required this.security,
    required this.records,
    this.nameError = false,
  });

  final DnsSecurity security;
  final List<DnsRecord> records;
  final bool nameError;
}

/// A root server the caller can already reach. [addresses] may be empty
/// when [nameserver] is enough for [DnsSend].
final class DnsHint {
  const DnsHint(this.nameserver, this.addresses);

  final String nameserver;
  final List<Uint8List> addresses;
}

/// Sends one query to [nameserver]. The message already has the CD bit, the
/// DO bit, and a DNS cookie. Truncation is the sender's TCP retry.
typedef DnsSend =
    Future<Result<DnsMessage, PqTransportError>> Function(
      DnsMessage query,
      String nameserver,
      List<Uint8List> addresses,
    );

/// RFC 1034 iterative resolver with DNSSEC (RFC 4035, RFC 5155) and qname
/// minimization (RFC 9156).
///
/// [anchor.zone] is the root. Answers and denial proofs are stored in
/// [Cache]. NSEC3 extra iterations default to 0 (RFC 9276). The hash
/// function still accepts the full 16-bit field when [maxNsec3Iterations]
/// is raised. The AD bit is ignored.
final class DnsIterativeResolver {
  DnsIterativeResolver({
    required this.hints,
    required this.anchor,
    required this.send,
    DateTime Function()? clock,
    this.maxQueries = 32,
    this.maxNsec3Iterations = 0,
    Random? random,
  }) : _clock = clock ?? DateTime.now,
       _random = random ?? Random(),
       answers = Cache<DnsCacheKey, DnsResolution>(clock: clock),
       _spans = Cache<String, _Span>(clock: clock),
       _serverCookies = Cache<String, Uint8List>(maxSize: 32, clock: clock);

  final List<DnsHint> hints;
  final DnsTrustAnchor anchor;
  final DnsSend send;
  final int maxQueries;
  final int maxNsec3Iterations;
  final DateTime Function() _clock;
  final Random _random;

  /// Positive and negative answers. TTL comes from the records or the SOA.
  final Cache<DnsCacheKey, DnsResolution> answers;

  final Cache<String, _Span> _spans;
  final Cache<String, Uint8List> _serverCookies;

  final Uint8List _clientCookie = Uint8List(8);
  var _cookieReady = false;
  var _queries = 0;
  _Zone? _root;

  Future<Result<DnsResolution, PqTransportError>> lookup(
    String name,
    DnsType type,
  ) {
    _queries = 0;
    return _resolve(name, type, <String>{});
  }

  Future<Result<DnsResolution, PqTransportError>> _resolve(
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
    final cached = _cached(name, type);
    if (cached != null) return Result.success(cached);
    final root = await _rootZone();
    if (root.isFailure) return Result.failure(root.errorOrNull!);
    final zone = root.valueOrNull!;
    if (zone.security == DnsSecurity.bogus) {
      return const Result.success(
        DnsResolution(security: DnsSecurity.bogus, records: []),
      );
    }
    return _walk(zone, name, type, seen);
  }

  Future<Result<DnsResolution, PqTransportError>> _walk(
    _Zone start,
    String qname,
    DnsType type,
    Set<String> seen,
  ) async {
    var zone = start;
    final seenZones = <String>{};
    while (true) {
      final zoneKey = dnsNameKey(zone.name);
      if (zoneKey == null || !seenZones.add(zoneKey)) {
        return Result.failure(PqTransportError.unsupported('cname loop'));
      }
      final next = _deeper(zone.name, qname);
      final last = dnsNamesEqual(next, qname);
      final asked = await _ask(zone, next, last ? type : DnsType.ns);
      if (asked.isFailure) return Result.failure(asked.errorOrNull!);
      final msg = asked.valueOrNull!;
      final dname = _dnameFor(msg, qname);
      if (dname != null) {
        if (!_chain(zone, [dname], msg.answers, _clock())) {
          return const Result.success(
            DnsResolution(security: DnsSecurity.bogus, records: []),
          );
        }
        final synthesized = dnsDnameSubstitute(qname, dname.name, dname.target);
        if (synthesized == null) {
          return Result.failure(PqTransportError.unexpectedMessage('dname'));
        }
        final followed = await _resolve(synthesized, type, seen);
        if (followed.isFailure) return followed;
        return Result.success(_combine(zone, followed.valueOrNull!));
      }
      final referral = _referral(msg, qname, zone.name);
      if (referral != null) {
        final cut = await _delegate(zone, referral, msg);
        if (cut.isFailure) return Result.failure(cut.errorOrNull!);
        final step = cut.valueOrNull!;
        if (step.resolution != null) return Result.success(step.resolution!);
        zone = step.zone!;
        continue;
      }
      if (!last) {
        if (msg.rcode == dnsRcodeNxDomain) {
          final full = await _ask(zone, qname, type);
          if (full.isFailure) return Result.failure(full.errorOrNull!);
          return _finish(zone, qname, type, full.valueOrNull!);
        }
        zone = _Zone(next, zone.servers, zone.security, zone.keys);
        continue;
      }
      final cname = _cnameFor(msg, qname);
      if (cname != null && type != DnsType.cname) {
        if (!_chain(zone, [cname], msg.answers, _clock())) {
          return const Result.success(
            DnsResolution(security: DnsSecurity.bogus, records: []),
          );
        }
        final followed = await _resolve(cname.canonical, type, seen);
        if (followed.isFailure) return followed;
        return Result.success(_combine(zone, followed.valueOrNull!));
      }
      return _finish(zone, qname, type, msg);
    }
  }

  Result<DnsResolution, PqTransportError> _finish(
    _Zone zone,
    String name,
    DnsType type,
    DnsMessage msg,
  ) {
    if (msg.rcode != 0 && msg.rcode != dnsRcodeNxDomain) {
      return Result.failure(PqTransportError.unexpectedMessage('dns rcode'));
    }
    final rrset = _rrset(msg.answers, name, dnsTypeValue(type));
    final nameError = msg.rcode == dnsRcodeNxDomain;
    if (rrset.isEmpty) {
      if (zone.security == DnsSecurity.insecure) {
        final resolution = DnsResolution(
          security: DnsSecurity.insecure,
          records: const [],
          nameError: nameError,
        );
        _remember(name, type, resolution, _negativeTtl(msg));
        return Result.success(resolution);
      }
      final keys = zone.keys ?? const <DnsDnskey>[];
      final now = _clock();
      final nsecs = _signedRecords<DnsNsec>(msg.authority, keys, now);
      final nsec3s = _signedRecords<DnsNsec3>(msg.authority, keys, now);
      final proved = nameError
          ? dnsNsecProvesNameError(
                  qname: name,
                  zone: zone.name,
                  nsecs: nsecs,
                ).isSuccess ||
                dnsNsec3ProvesNameError(
                  qname: name,
                  zone: zone.name,
                  nsecs: nsec3s,
                  maxIterations: maxNsec3Iterations,
                ).isSuccess
          : nsecs.any(
                  (n) => dnsNsecProvesNoData(n, name, dnsTypeValue(type)),
                ) ||
                dnsNsec3ProvesNoData(
                  qname: name,
                  zone: zone.name,
                  qtype: dnsTypeValue(type),
                  nsecs: nsec3s,
                  maxIterations: maxNsec3Iterations,
                ).isSuccess;
      if (!proved) {
        return const Result.success(
          DnsResolution(security: DnsSecurity.bogus, records: []),
        );
      }
      _rememberSpan(zone.name, nsecs, nsec3s, _negativeTtl(msg));
      final resolution = DnsResolution(
        security: DnsSecurity.secure,
        records: const [],
        nameError: nameError,
      );
      _remember(name, type, resolution, _negativeTtl(msg));
      return Result.success(resolution);
    }
    if (zone.security == DnsSecurity.insecure) {
      final resolution = DnsResolution(
        security: DnsSecurity.insecure,
        records: rrset,
      );
      _remember(name, type, resolution, _setTtl(rrset));
      return Result.success(resolution);
    }
    if (!_verified(rrset, msg.answers, zone.keys ?? const [], _clock())) {
      return const Result.success(
        DnsResolution(security: DnsSecurity.bogus, records: []),
      );
    }
    final resolution = DnsResolution(
      security: DnsSecurity.secure,
      records: rrset,
    );
    _remember(name, type, resolution, _setTtl(rrset));
    return Result.success(resolution);
  }

  Future<Result<_Step, PqTransportError>> _delegate(
    _Zone parent,
    String child,
    DnsMessage referral,
  ) async {
    final servers = <_Server>[];
    final nsRecords = <DnsRecord>[];
    for (final rr in referral.authority) {
      if (rr is! DnsNs || !dnsNamesEqual(rr.name, child)) continue;
      nsRecords.add(rr);
      servers.add(_Server(rr.nameserver, _glue(referral, rr.nameserver)));
    }
    if (servers.isEmpty) {
      return Result.failure(
        PqTransportError.unexpectedMessage('lame referral'),
      );
    }
    for (var i = 0; i < servers.length; i++) {
      if (servers[i].addresses.isNotEmpty) continue;
      if (_below(servers[i].name, child) ||
          dnsNamesEqual(servers[i].name, child)) {
        continue;
      }
      final resolved = await _resolve(servers[i].name, DnsType.a, <String>{});
      if (resolved.isFailure) continue;
      final got = resolved.valueOrNull!;
      if (got.security == DnsSecurity.bogus) continue;
      final addresses = [
        for (final rr in got.records)
          if (rr is DnsA) rr.address else if (rr is DnsAaaa) rr.address,
      ];
      if (addresses.isEmpty) continue;
      servers[i] = _Server(servers[i].name, addresses);
    }
    if (parent.security == DnsSecurity.secure &&
        !_verified(
          nsRecords,
          referral.authority,
          parent.keys ?? const [],
          _clock(),
        )) {
      return const Result.success(_Step.done(_bogus));
    }
    if (parent.security == DnsSecurity.insecure) {
      return Result.success(
        _Step.zone(_Zone(child, servers, DnsSecurity.insecure, null)),
      );
    }
    final dsMsg = await _ask(parent, child, DnsType.ds);
    if (dsMsg.isFailure) return Result.failure(dsMsg.errorOrNull!);
    final dsRecords = _rrset(dsMsg.valueOrNull!.answers, child, dnsTypeDs);
    final keys = parent.keys ?? const <DnsDnskey>[];
    final now = _clock();
    if (dsRecords.isNotEmpty) {
      if (!_verified(dsRecords, dsMsg.valueOrNull!.answers, keys, now)) {
        return const Result.success(_Step.done(_bogus));
      }
      final supported = dsRecords.whereType<DnsDs>().where(_dsSupported);
      if (supported.isEmpty) {
        return Result.success(
          _Step.zone(_Zone(child, servers, DnsSecurity.insecure, null)),
        );
      }
      final asking = _Zone(child, servers, DnsSecurity.insecure, null);
      final keyMsg = await _ask(asking, child, DnsType.dnskey);
      if (keyMsg.isFailure) return Result.failure(keyMsg.errorOrNull!);
      final keyRecords = _rrset(
        keyMsg.valueOrNull!.answers,
        child,
        dnsTypeDnskey,
      );
      final trusted = <DnsDnskey>[
        for (final rr in keyRecords)
          if (rr is DnsDnskey &&
              _usable(rr) &&
              supported.any((ds) => dnskeyMatchesDs(rr, ds)))
            rr,
      ];
      if (trusted.isEmpty ||
          !_verified(keyRecords, keyMsg.valueOrNull!.answers, trusted, now)) {
        return const Result.success(_Step.done(_bogus));
      }
      return Result.success(
        _Step.zone(_Zone(child, servers, DnsSecurity.secure, trusted)),
      );
    }
    final nsecs = _signedRecords<DnsNsec>(
      dsMsg.valueOrNull!.authority,
      keys,
      now,
    );
    final nsec3s = _signedRecords<DnsNsec3>(
      dsMsg.valueOrNull!.authority,
      keys,
      now,
    );
    final absent =
        nsecs.any((n) => dnsNsecProvesNoData(n, child, dnsTypeDs)) ||
        dnsNsec3ProvesNoData(
          qname: child,
          zone: parent.name,
          qtype: dnsTypeDs,
          nsecs: nsec3s,
          maxIterations: maxNsec3Iterations,
        ).isSuccess;
    if (!absent) return const Result.success(_Step.done(_bogus));
    _rememberSpan(parent.name, nsecs, nsec3s, _negativeTtl(dsMsg.valueOrNull!));
    return Result.success(
      _Step.zone(_Zone(child, servers, DnsSecurity.insecure, null)),
    );
  }

  Future<Result<_Zone, PqTransportError>> _rootZone() async {
    final cached = _root;
    if (cached != null) return Result.success(cached);
    if (hints.isEmpty || !dnsNamesEqual(anchor.zone, '.')) {
      return Result.failure(PqTransportError.unexpectedMessage('trust zone'));
    }
    final servers = [
      for (final hint in hints) _Server(hint.nameserver, hint.addresses),
    ];
    final priming = _Zone('.', servers, DnsSecurity.insecure, null);
    final msg = await _ask(priming, '.', DnsType.dnskey);
    if (msg.isFailure) return Result.failure(msg.errorOrNull!);
    final records = _rrset(msg.valueOrNull!.answers, '.', dnsTypeDnskey);
    final trusted = <DnsDnskey>[
      for (final rr in records)
        if (rr is DnsDnskey && _usable(rr) && _matchesAnchor(rr)) rr,
    ];
    if (trusted.isEmpty ||
        !_verified(records, msg.valueOrNull!.answers, trusted, _clock())) {
      return const Result.success(_Zone('.', [], DnsSecurity.bogus, null));
    }
    final zone = _Zone('.', servers, DnsSecurity.secure, trusted);
    _root = zone;
    return Result.success(zone);
  }

  Future<Result<DnsMessage, PqTransportError>> _ask(
    _Zone zone,
    String qname,
    DnsType qtype,
  ) async {
    PqTransportError? last;
    for (final server in zone.servers) {
      final msg = await _send(server, qname, qtype);
      if (msg.isFailure) {
        last = msg.errorOrNull;
        continue;
      }
      if (_lame(msg.valueOrNull!, qname, zone.name)) {
        last = PqTransportError.unexpectedMessage('lame referral');
        continue;
      }
      return msg;
    }
    return Result.failure(
      last ?? PqTransportError.unexpectedMessage('lame referral'),
    );
  }

  Future<Result<DnsMessage, PqTransportError>> _send(
    _Server server,
    String qname,
    DnsType qtype,
  ) async {
    if (!_cookieReady) {
      for (var i = 0; i < 8; i++) {
        _clientCookie[i] = _random.nextInt(256);
      }
      _cookieReady = true;
    }
    final known = _serverCookies.get(dnsNameKey(server.name) ?? server.name);
    final first = await _once(server, qname, qtype, known);
    if (first.isFailure) return first;
    if (first.valueOrNull!.rcode != dnsRcodeBadCookie) return first;
    final serverCookie = dnsServerCookie(first.valueOrNull!, _clientCookie);
    if (serverCookie == null) {
      return Result.failure(PqTransportError.unexpectedMessage('dns cookie'));
    }
    final joined = Uint8List(8 + serverCookie.length)
      ..setRange(0, 8, _clientCookie)
      ..setRange(8, 8 + serverCookie.length, serverCookie);
    _serverCookies.put(dnsNameKey(server.name) ?? server.name, joined);
    return _once(server, qname, qtype, joined);
  }

  Future<Result<DnsMessage, PqTransportError>> _once(
    _Server server,
    String qname,
    DnsType qtype,
    Uint8List? cookie,
  ) async {
    if (_queries >= maxQueries) {
      return Result.failure(PqTransportError.unsupported('dns query budget'));
    }
    _queries++;
    final id = _random.nextInt(0x10000);
    final material = cookie ?? _clientCookie;
    final query = DnsMessage(
      id: id,
      flags: dnsFlagCd,
      questions: [DnsQuestion(name: qname, type: qtype)],
      additional: [
        DnsOpt(flags: ednsFlagDo, options: {ednsOptionCookie: material}),
      ],
    );
    final response = await send(query, server.name, server.addresses);
    if (response.isFailure) return response;
    final msg = response.valueOrNull!;
    if (msg.id != id) {
      return Result.failure(PqTransportError.unexpectedMessage('dns id'));
    }
    if (msg.questions.isNotEmpty) {
      final q = msg.questions.first;
      if (q.type != qtype || !dnsNamesEqual(q.name, qname)) {
        return Result.failure(
          PqTransportError.unexpectedMessage('dns question'),
        );
      }
    }
    if ((msg.flags & dnsFlagTc) != 0) {
      return Result.failure(PqTransportError.unsupported('truncated dns'));
    }
    return Result.success(msg);
  }

  DnsResolution? _cached(String name, DnsType type) {
    final key = dnsNameKey(name);
    if (key == null) return null;
    final hit = answers.get(DnsCacheKey(key, type));
    if (hit != null) return hit;
    for (final id in _spans.keys.toList()) {
      final span = _spans.get(id);
      if (span == null) continue;
      if (!dnsNamesEqual(name, span.zone) && !_below(name, span.zone)) continue;
      if (span.nsecs.isNotEmpty &&
          dnsNsecProvesNameError(
            qname: name,
            zone: span.zone,
            nsecs: span.nsecs,
          ).isSuccess) {
        return const DnsResolution(
          security: DnsSecurity.secure,
          records: [],
          nameError: true,
        );
      }
      if (span.nsecs.any(
        (n) => dnsNsecProvesNoData(n, name, dnsTypeValue(type)),
      )) {
        return const DnsResolution(
          security: DnsSecurity.secure,
          records: [],
          nameError: false,
        );
      }
      if (span.nsec3s.isNotEmpty &&
          dnsNsec3ProvesNameError(
            qname: name,
            zone: span.zone,
            nsecs: span.nsec3s,
            maxIterations: maxNsec3Iterations,
          ).isSuccess) {
        return const DnsResolution(
          security: DnsSecurity.secure,
          records: [],
          nameError: true,
        );
      }
      if (dnsNsec3ProvesNoData(
        qname: name,
        zone: span.zone,
        qtype: dnsTypeValue(type),
        nsecs: span.nsec3s,
        maxIterations: maxNsec3Iterations,
      ).isSuccess) {
        return const DnsResolution(
          security: DnsSecurity.secure,
          records: [],
          nameError: false,
        );
      }
    }
    return null;
  }

  void _remember(
    String name,
    DnsType type,
    DnsResolution resolution,
    Duration ttl,
  ) {
    if (resolution.security == DnsSecurity.bogus) return;
    final key = dnsNameKey(name);
    if (key == null) return;
    answers.put(DnsCacheKey(key, type), resolution, ttl: ttl);
  }

  void _rememberSpan(
    String zone,
    List<DnsNsec> nsecs,
    List<DnsNsec3> nsec3s,
    Duration ttl,
  ) {
    if (nsecs.isEmpty && nsec3s.isEmpty) return;
    final zoneKey = dnsNameKey(zone);
    if (zoneKey == null) return;
    final owners = [
      for (final rr in nsecs) dnsNameKey(rr.name),
      for (final rr in nsec3s) dnsNameKey(rr.name),
    ].join(' ');
    _spans.put('$zoneKey $owners', _Span(zone, nsecs, nsec3s), ttl: ttl);
  }

  bool _chain(
    _Zone zone,
    List<DnsRecord> rrset,
    List<DnsRecord> section,
    DateTime now,
  ) {
    if (zone.security == DnsSecurity.insecure) return true;
    return _verified(rrset, section, zone.keys ?? const [], now);
  }

  bool _matchesAnchor(DnsDnskey key) {
    final pinned = anchor.dnskey;
    if (pinned != null) {
      return dnsNamesEqual(key.name, pinned.name) &&
          key.algorithm == pinned.algorithm &&
          key.protocol == pinned.protocol &&
          key.publicKey.length == pinned.publicKey.length &&
          _same(key.publicKey, pinned.publicKey);
    }
    final ds = anchor.ds;
    if (ds == null) return false;
    return dnskeyMatchesDs(key, ds);
  }
}

const DnsResolution _bogus = DnsResolution(
  security: DnsSecurity.bogus,
  records: [],
);

final class _Server {
  const _Server(this.name, this.addresses);
  final String name;
  final List<Uint8List> addresses;
}

final class _Zone {
  const _Zone(this.name, this.servers, this.security, this.keys);
  final String name;
  final List<_Server> servers;
  final DnsSecurity security;
  final List<DnsDnskey>? keys;
}

final class _Span {
  const _Span(this.zone, this.nsecs, this.nsec3s);
  final String zone;
  final List<DnsNsec> nsecs;
  final List<DnsNsec3> nsec3s;
}

final class _Step {
  const _Step.zone(this.zone) : resolution = null;
  const _Step.done(this.resolution) : zone = null;
  final _Zone? zone;
  final DnsResolution? resolution;
}

DnsResolution _combine(_Zone zone, DnsResolution followed) {
  if (followed.security == DnsSecurity.bogus) return followed;
  final insecure =
      zone.security == DnsSecurity.insecure ||
      followed.security == DnsSecurity.insecure;
  return DnsResolution(
    security: insecure ? DnsSecurity.insecure : DnsSecurity.secure,
    records: followed.records,
    nameError: followed.nameError,
  );
}

bool _lame(DnsMessage msg, String qname, String zone) {
  if (msg.rcode == dnsRcodeServFail || msg.rcode == dnsRcodeRefused) {
    return true;
  }
  if (_referral(msg, qname, zone) != null) return false;
  return (msg.flags & dnsFlagAa) == 0;
}

String? _referral(DnsMessage msg, String qname, String zone) {
  String? best;
  for (final rr in msg.authority) {
    if (rr is! DnsNs) continue;
    if (!_below(rr.name, zone)) continue;
    if (!_below(qname, rr.name) && !dnsNamesEqual(qname, rr.name)) continue;
    if (best == null || _below(rr.name, best)) best = rr.name;
  }
  return best;
}

String _deeper(String zone, String qname) {
  if (dnsNamesEqual(zone, qname)) return qname;
  final labels = <String>[];
  var name = qname;
  while (!dnsNamesEqual(name, zone)) {
    final parent = dnsParent(name);
    if (parent == null) return qname;
    final trimmed = name.endsWith('.')
        ? name.substring(0, name.length - 1)
        : name;
    final dot = trimmed.indexOf('.');
    labels.add(dot < 0 ? trimmed : trimmed.substring(0, dot));
    name = parent;
  }
  if (labels.isEmpty) return qname;
  final next = labels.last;
  if (dnsNamesEqual(zone, '.')) return '$next.';
  final apex = zone.endsWith('.') ? zone : '$zone.';
  return '$next.$apex';
}

bool _below(String name, String zone) {
  var current = name;
  while (true) {
    final parent = dnsParent(current);
    if (parent == null) return false;
    if (dnsNamesEqual(parent, zone)) return true;
    current = parent;
  }
}

DnsDname? _dnameFor(DnsMessage msg, String qname) {
  for (final rr in [...msg.answers, ...msg.authority]) {
    if (rr is DnsDname && _below(qname, rr.name)) return rr;
  }
  return null;
}

DnsCname? _cnameFor(DnsMessage msg, String qname) {
  for (final rr in msg.answers) {
    if (rr is DnsCname && dnsNamesEqual(rr.name, qname)) return rr;
  }
  return null;
}

List<Uint8List> _glue(DnsMessage msg, String nameserver) => [
  for (final rr in msg.additional)
    if (rr is DnsA && dnsNamesEqual(rr.name, nameserver)) rr.address,
  for (final rr in msg.additional)
    if (rr is DnsAaaa && dnsNamesEqual(rr.name, nameserver)) rr.address,
];

List<DnsRecord> _rrset(List<DnsRecord> records, String owner, int type) => [
  for (final rr in records)
    if (rr is! DnsRrsig &&
        rr is! DnsOpt &&
        dnsNamesEqual(rr.name, owner) &&
        dnsRecordType(rr) == type)
      rr,
];

bool _usable(DnsDnskey key) =>
    (key.flags & dnssecZoneKeyFlag) != 0 &&
    (key.flags & dnssecRevokedKeyFlag) == 0 &&
    key.protocol == dnssecProtocol &&
    dnssecAlgorithmSupported(key.algorithm);

bool _dsSupported(DnsDs ds) =>
    dnssecAlgorithmSupported(ds.algorithm) &&
    (ds.digestType == dnssecDigestSha1 ||
        ds.digestType == dnssecDigestSha256 ||
        ds.digestType == dnssecDigestSha384);

bool _verified(
  List<DnsRecord> rrset,
  List<DnsRecord> section,
  List<DnsDnskey> keys,
  DateTime now,
) {
  if (rrset.isEmpty || keys.isEmpty) return false;
  final owner = rrset.first.name;
  final type = dnsRecordType(rrset.first);
  for (final rr in section) {
    if (rr is! DnsRrsig ||
        rr.typeCovered != type ||
        !dnsNamesEqual(rr.name, owner)) {
      continue;
    }
    for (final key in keys) {
      if (verifyDnssecRrset(
        rrset: rrset,
        rrsig: rr,
        dnskey: key,
        now: now,
      ).isSuccess) {
        return true;
      }
    }
  }
  return false;
}

List<T> _signedRecords<T extends DnsRecord>(
  List<DnsRecord> section,
  List<DnsDnskey> keys,
  DateTime now,
) => [
  for (final rr in section)
    if (rr is T && _verified([rr], section, keys, now)) rr,
];

Duration _setTtl(List<DnsRecord> records) {
  var seconds = records.first.ttl;
  for (final rr in records) {
    if (rr.ttl < seconds) seconds = rr.ttl;
  }
  return Duration(seconds: seconds < 0 ? 0 : seconds);
}

Duration _negativeTtl(DnsMessage msg) {
  for (final rr in msg.authority) {
    if (rr is! DnsSoa) continue;
    final seconds = rr.minimum < rr.ttl ? rr.minimum : rr.ttl;
    return Duration(seconds: seconds < 0 ? 0 : seconds);
  }
  return msg.minTtl();
}

bool _same(List<int> a, List<int> b) {
  if (a.length != b.length) return false;
  for (var i = 0; i < a.length; i++) {
    if (a[i] != b[i]) return false;
  }
  return true;
}
