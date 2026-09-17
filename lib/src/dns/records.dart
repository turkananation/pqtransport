import 'dart:convert';
import 'dart:typed_data';

import '../core/lengths.dart';

enum DnsType { a, aaaa, cname, mx, txt, srv, caa, https, svcb, opt, ptr, ns }

int dnsTypeValue(DnsType t) => switch (t) {
  DnsType.a => dnsTypeA,
  DnsType.aaaa => dnsTypeAaaa,
  DnsType.cname => dnsTypeCname,
  DnsType.mx => dnsTypeMx,
  DnsType.txt => dnsTypeTxt,
  DnsType.srv => dnsTypeSrv,
  DnsType.caa => dnsTypeCaa,
  DnsType.https => dnsTypeHttps,
  DnsType.svcb => dnsTypeSvcb,
  DnsType.opt => dnsTypeOpt,
  DnsType.ptr => dnsTypePtr,
  DnsType.ns => dnsTypeNs,
};

DnsType? dnsTypeFromValue(int v) => switch (v) {
  dnsTypeA => DnsType.a,
  dnsTypeAaaa => DnsType.aaaa,
  dnsTypeCname => DnsType.cname,
  dnsTypeMx => DnsType.mx,
  dnsTypeTxt => DnsType.txt,
  dnsTypeSrv => DnsType.srv,
  dnsTypeCaa => DnsType.caa,
  dnsTypeHttps => DnsType.https,
  dnsTypeSvcb => DnsType.svcb,
  dnsTypeOpt => DnsType.opt,
  dnsTypePtr => DnsType.ptr,
  dnsTypeNs => DnsType.ns,
  _ => null,
};

final class DnsQuestion {
  const DnsQuestion({
    required this.name,
    required this.type,
    this.klass = dnsClassIn,
  });

  final String name;
  final DnsType type;
  final int klass;
}

sealed class DnsRecord {
  const DnsRecord({
    required this.name,
    required this.type,
    required this.ttl,
    this.klass = dnsClassIn,
  });

  final String name;
  final DnsType type;
  final int ttl;
  final int klass;
}

final class DnsA extends DnsRecord {
  DnsA({required super.name, required this.address, super.ttl = 300})
    : super(type: DnsType.a);
  final Uint8List address; // 4
}

final class DnsAaaa extends DnsRecord {
  DnsAaaa({required super.name, required this.address, super.ttl = 300})
    : super(type: DnsType.aaaa);
  final Uint8List address; // 16
}

final class DnsCname extends DnsRecord {
  DnsCname({required super.name, required this.canonical, super.ttl = 300})
    : super(type: DnsType.cname);
  final String canonical;
}

final class DnsMx extends DnsRecord {
  DnsMx({
    required super.name,
    required this.preference,
    required this.exchange,
    super.ttl = 300,
  }) : super(type: DnsType.mx);
  final int preference;
  final String exchange;
}

final class DnsTxt extends DnsRecord {
  DnsTxt({required super.name, required this.strings, super.ttl = 300})
    : super(type: DnsType.txt);
  final List<String> strings;
}

final class DnsSrv extends DnsRecord {
  DnsSrv({
    required super.name,
    required this.priority,
    required this.weight,
    required this.port,
    required this.target,
    super.ttl = 300,
  }) : super(type: DnsType.srv);
  final int priority;
  final int weight;
  final int port;
  final String target;
}

final class DnsCaa extends DnsRecord {
  DnsCaa({
    required super.name,
    required this.flags,
    required this.tag,
    required this.value,
    super.ttl = 300,
  }) : super(type: DnsType.caa);
  final int flags;
  final String tag;
  final String value;
}

final class DnsSvcb extends DnsRecord {
  DnsSvcb({
    required super.name,
    required this.priority,
    required this.target,
    this.params = const {},
    super.ttl = 300,
    super.type = DnsType.svcb,
  });
  final int priority;
  final String target;
  final Map<int, Uint8List> params;
}

final class DnsHttps extends DnsSvcb {
  DnsHttps({
    required super.name,
    required super.priority,
    required super.target,
    super.params,
    super.ttl,
  }) : super(type: DnsType.https);
}

final class DnsOpt extends DnsRecord {
  DnsOpt({
    this.udpPayload = edns0UdpPayloadDefault,
    this.extendedRcode = 0,
    this.version = 0,
    this.flags = 0,
    this.options = const {},
  }) : super(name: '.', type: DnsType.opt, ttl: 0, klass: udpPayload);
  final int udpPayload;
  final int extendedRcode;
  final int version;
  final int flags;
  final Map<int, Uint8List> options;
}

final class DnsPtr extends DnsRecord {
  DnsPtr({required super.name, required this.pointer, super.ttl = 300})
    : super(type: DnsType.ptr);
  final String pointer;
}

final class DnsNs extends DnsRecord {
  DnsNs({required super.name, required this.nameserver, super.ttl = 300})
    : super(type: DnsType.ns);
  final String nameserver;
}

final class DnsMessage {
  const DnsMessage({
    required this.id,
    this.flags = 0,
    this.questions = const [],
    this.answers = const [],
    this.authority = const [],
    this.additional = const [],
  });

  final int id;
  final int flags;
  final List<DnsQuestion> questions;
  final List<DnsRecord> answers;
  final List<DnsRecord> authority;
  final List<DnsRecord> additional;

  bool get isQuery => (flags & 0x8000) == 0;
  bool get isResponse => !isQuery;

  Duration minTtl() {
    final ttls = [
      ...answers,
      ...authority,
    ].map((r) => r.ttl).where((t) => t > 0);
    if (ttls.isEmpty) return const Duration(seconds: 60);
    return Duration(seconds: ttls.reduce((a, b) => a < b ? a : b));
  }
}

String utf8string(Uint8List bytes) => utf8.decode(bytes);
