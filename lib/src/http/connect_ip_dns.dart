import 'dart:convert';
import 'dart:typed_data';

import 'package:swissarmyknife/swissarmyknife.dart';

import '../core/bytes.dart';
import '../core/errors.dart';
import '../quic/packet.dart';
import 'capsule.dart';

/// draft-ietf-masque-connect-ip-dns-07. Provisional capsule types.
/// They are not stable IANA values. Not a masque-go flight.
const int capsuleDnsAssign = 0x1ACE79EC;
const int capsulePref64 = 0x274C0FBC;

const int _svcbNoDefaultAlpn = 2;
const int _svcbIpv4Hint = 4;
const int _svcbIpv6Hint = 6;

final class DnsAssignNameserver {
  const DnsAssignNameserver({
    required this.priority,
    this.ipv4 = const [],
    this.ipv6 = const [],
    this.authenticationDomain = '',
    this.serviceParameters = const [],
  });

  /// SVCB ServiceMode. Zero is refused.
  final int priority;
  final List<Uint8List> ipv4;
  final List<Uint8List> ipv6;
  final String authenticationDomain;

  /// RFC 9460 §2.2 wire. `ipv4hint` and `ipv6hint` are refused.
  final List<int> serviceParameters;
}

final class DnsAssignConfiguration {
  const DnsAssignConfiguration({
    required this.nameservers,
    this.internalDomains = const [],
    this.searchDomains = const [],
  });

  final List<DnsAssignNameserver> nameservers;
  final List<String> internalDomains;
  final List<String> searchDomains;
}

final class Nat64Prefix {
  const Nat64Prefix({required this.prefixLength, required this.prefix});

  /// RFC 6052 §2.2. 32, 40, 48, 56, 64, or 96.
  final int prefixLength;

  /// 96 bits. Unused low bits are zero.
  final Uint8List prefix;
}

Result<Uint8List, PqTransportError> encodeDnsAssign(
  List<DnsAssignConfiguration> configurations,
) {
  final body = BytesBuilder(copy: false);
  for (final config in configurations) {
    final one = _encodeConfiguration(config);
    if (one.isFailure) return Result.failure(one.errorOrNull!);
    body.add(one.valueOrNull!);
  }
  return Result.success(body.takeBytes());
}

Result<List<DnsAssignConfiguration>, PqTransportError> decodeDnsAssign(
  Uint8List value,
) {
  if (value.isEmpty) return const Result.success([]);
  final out = <DnsAssignConfiguration>[];
  var offset = 0;
  while (offset < value.length) {
    final one = _decodeConfiguration(value, offset);
    if (one == null) {
      return Result.failure(PqTransportError.decodeFailure('DNS_ASSIGN'));
    }
    out.add(one.config);
    offset += one.consumed;
  }
  return Result.success(out);
}

HttpCapsule dnsAssignCapsule(List<DnsAssignConfiguration> configurations) {
  final value = encodeDnsAssign(configurations);
  if (value.isFailure) {
    throw StateError('DNS_ASSIGN');
  }
  return HttpCapsule(type: capsuleDnsAssign, value: value.valueOrNull!);
}

Result<Uint8List, PqTransportError> encodePref64(List<Nat64Prefix> prefixes) {
  final body = BytesBuilder(copy: false);
  for (final prefix in prefixes) {
    if (!_pref64Length(prefix.prefixLength) || prefix.prefix.length != 12) {
      return Result.failure(PqTransportError.decodeFailure('PREF64'));
    }
    body.addByte(prefix.prefixLength);
    body.add(prefix.prefix);
  }
  return Result.success(body.takeBytes());
}

Result<List<Nat64Prefix>, PqTransportError> decodePref64(Uint8List value) {
  if (value.isEmpty) return const Result.success([]);
  if (value.length % 13 != 0) {
    return Result.failure(PqTransportError.decodeFailure('PREF64'));
  }
  final out = <Nat64Prefix>[];
  for (var i = 0; i < value.length; i += 13) {
    final length = value[i];
    if (!_pref64Length(length)) {
      return Result.failure(PqTransportError.decodeFailure('PREF64'));
    }
    out.add(
      Nat64Prefix(
        prefixLength: length,
        prefix: Uint8List.sublistView(value, i + 1, i + 13),
      ),
    );
  }
  return Result.success(out);
}

HttpCapsule pref64Capsule(List<Nat64Prefix> prefixes) {
  final value = encodePref64(prefixes);
  if (value.isFailure) throw StateError('PREF64');
  return HttpCapsule(type: capsulePref64, value: value.valueOrNull!);
}

bool _pref64Length(int length) =>
    length == 32 ||
    length == 40 ||
    length == 48 ||
    length == 56 ||
    length == 64 ||
    length == 96;

Result<Uint8List, PqTransportError> _encodeConfiguration(
  DnsAssignConfiguration config,
) {
  if (config.nameservers.isEmpty) {
    return Result.failure(PqTransportError.decodeFailure('DNS_ASSIGN'));
  }
  final body = BytesBuilder(copy: false);
  writeQuicVarint(body, config.nameservers.length);
  for (final ns in config.nameservers) {
    final one = _encodeNameserver(ns);
    if (one.isFailure) return Result.failure(one.errorOrNull!);
    body.add(one.valueOrNull!);
  }
  final internal = _encodeDomains(config.internalDomains);
  if (internal.isFailure) return Result.failure(internal.errorOrNull!);
  body.add(internal.valueOrNull!);
  final search = _encodeDomains(config.searchDomains);
  if (search.isFailure) return Result.failure(search.errorOrNull!);
  body.add(search.valueOrNull!);
  return Result.success(body.takeBytes());
}

Result<Uint8List, PqTransportError> _encodeNameserver(DnsAssignNameserver ns) {
  if (ns.priority == 0 || ns.priority > 0xffff) {
    return Result.failure(PqTransportError.decodeFailure('DNS_ASSIGN'));
  }
  for (final address in ns.ipv4) {
    if (address.length != 4) {
      return Result.failure(PqTransportError.decodeFailure('DNS_ASSIGN'));
    }
  }
  for (final address in ns.ipv6) {
    if (address.length != 16) {
      return Result.failure(PqTransportError.decodeFailure('DNS_ASSIGN'));
    }
  }
  final params = Uint8List.fromList(ns.serviceParameters);
  if (_badSvcb(params)) {
    return Result.failure(PqTransportError.decodeFailure('DNS_ASSIGN'));
  }
  final noDefault = _hasSvcbKey(params, _svcbNoDefaultAlpn);
  if (!noDefault && ns.ipv4.isEmpty && ns.ipv6.isEmpty) {
    return Result.failure(PqTransportError.decodeFailure('DNS_ASSIGN'));
  }
  final body = BytesBuilder(copy: false);
  writeUint16(body, ns.priority);
  writeQuicVarint(body, ns.ipv4.length);
  for (final address in ns.ipv4) {
    body.add(address);
  }
  writeQuicVarint(body, ns.ipv6.length);
  for (final address in ns.ipv6) {
    body.add(address);
  }
  final domain = _encodeDomain(ns.authenticationDomain);
  if (domain.isFailure) return Result.failure(domain.errorOrNull!);
  body.add(domain.valueOrNull!);
  writeQuicVarint(body, params.length);
  body.add(params);
  return Result.success(body.takeBytes());
}

Result<Uint8List, PqTransportError> _encodeDomains(List<String> domains) {
  final body = BytesBuilder(copy: false);
  writeQuicVarint(body, domains.length);
  for (final domain in domains) {
    final one = _encodeDomain(domain);
    if (one.isFailure) return Result.failure(one.errorOrNull!);
    body.add(one.valueOrNull!);
  }
  return Result.success(body.takeBytes());
}

Result<Uint8List, PqTransportError> _encodeDomain(String domain) {
  final bytes = utf8.encode(domain);
  if (bytes.length > 255) {
    return Result.failure(PqTransportError.decodeFailure('DNS_ASSIGN'));
  }
  final body = BytesBuilder(copy: false);
  writeQuicVarint(body, bytes.length);
  body.add(bytes);
  return Result.success(body.takeBytes());
}

({DnsAssignConfiguration config, int consumed})? _decodeConfiguration(
  Uint8List value,
  int offset,
) {
  final reader = ByteReader(Uint8List.sublistView(value, offset));
  final count = readVarint(reader);
  if (count <= 0) return null;
  final start = offset;
  offset += reader.offset;
  final nameservers = <DnsAssignNameserver>[];
  for (var i = 0; i < count; i++) {
    final one = _decodeNameserver(value, offset);
    if (one == null) return null;
    nameservers.add(one.ns);
    offset += one.consumed;
  }
  final internal = _decodeDomains(value, offset);
  if (internal == null) return null;
  offset += internal.consumed;
  final search = _decodeDomains(value, offset);
  if (search == null) return null;
  offset += search.consumed;
  return (
    config: DnsAssignConfiguration(
      nameservers: nameservers,
      internalDomains: internal.domains,
      searchDomains: search.domains,
    ),
    consumed: offset - start,
  );
}

({DnsAssignNameserver ns, int consumed})? _decodeNameserver(
  Uint8List value,
  int offset,
) {
  if (offset + 2 > value.length) return null;
  final priority = readUint16(value, offset);
  if (priority == 0) return null;
  var at = offset + 2;
  final reader = ByteReader(Uint8List.sublistView(value, at));
  final v4Count = readVarint(reader);
  if (v4Count < 0) return null;
  at += reader.offset;
  if (at + (v4Count * 4) > value.length) return null;
  final ipv4 = <Uint8List>[];
  for (var i = 0; i < v4Count; i++) {
    ipv4.add(Uint8List.sublistView(value, at, at + 4));
    at += 4;
  }
  final v6reader = ByteReader(Uint8List.sublistView(value, at));
  final v6Count = readVarint(v6reader);
  if (v6Count < 0) return null;
  at += v6reader.offset;
  if (at + (v6Count * 16) > value.length) return null;
  final ipv6 = <Uint8List>[];
  for (var i = 0; i < v6Count; i++) {
    ipv6.add(Uint8List.sublistView(value, at, at + 16));
    at += 16;
  }
  final domain = _decodeDomain(value, at);
  if (domain == null) return null;
  at += domain.consumed;
  final paramsReader = ByteReader(Uint8List.sublistView(value, at));
  final paramsLen = readVarint(paramsReader);
  if (paramsLen < 0) return null;
  at += paramsReader.offset;
  if (at + paramsLen > value.length) return null;
  final params = Uint8List.sublistView(value, at, at + paramsLen);
  if (_badSvcb(params)) return null;
  if (!_hasSvcbKey(params, _svcbNoDefaultAlpn) &&
      ipv4.isEmpty &&
      ipv6.isEmpty) {
    return null;
  }
  at += paramsLen;
  return (
    ns: DnsAssignNameserver(
      priority: priority,
      ipv4: ipv4,
      ipv6: ipv6,
      authenticationDomain: domain.text,
      serviceParameters: params,
    ),
    consumed: at - offset,
  );
}

({List<String> domains, int consumed})? _decodeDomains(
  Uint8List value,
  int offset,
) {
  final reader = ByteReader(Uint8List.sublistView(value, offset));
  final count = readVarint(reader);
  if (count < 0) return null;
  var at = offset + reader.offset;
  final domains = <String>[];
  for (var i = 0; i < count; i++) {
    final one = _decodeDomain(value, at);
    if (one == null) return null;
    domains.add(one.text);
    at += one.consumed;
  }
  return (domains: domains, consumed: at - offset);
}

({String text, int consumed})? _decodeDomain(Uint8List value, int offset) {
  final reader = ByteReader(Uint8List.sublistView(value, offset));
  final len = readVarint(reader);
  if (len < 0) return null;
  final at = offset + reader.offset;
  if (at + len > value.length) return null;
  try {
    final text = utf8.decode(Uint8List.sublistView(value, at, at + len));
    return (text: text, consumed: reader.offset + len);
  } on FormatException {
    return null;
  }
}

bool _badSvcb(Uint8List params) {
  var i = 0;
  var sawHint = false;
  while (i + 4 <= params.length) {
    final key = readUint16(params, i);
    final len = readUint16(params, i + 2);
    i += 4;
    if (i + len > params.length) return true;
    if (key == _svcbIpv4Hint || key == _svcbIpv6Hint) sawHint = true;
    i += len;
  }
  return sawHint || i != params.length;
}

bool _hasSvcbKey(Uint8List params, int want) {
  var i = 0;
  while (i + 4 <= params.length) {
    final key = readUint16(params, i);
    final len = readUint16(params, i + 2);
    if (key == want) return true;
    i += 4 + len;
  }
  return false;
}
