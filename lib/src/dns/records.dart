import 'dart:convert';
import 'dart:typed_data';

import '../core/lengths.dart';

enum DnsType {
  a,
  aaaa,
  cname,
  dname,
  mx,
  txt,
  srv,
  caa,
  https,
  svcb,
  opt,
  ptr,
  ns,
  dnskey,
  ds,
  rrsig,
  soa,
  nsec,
  nsec3,
  nsec3param,
  opaque,
}

int dnsTypeValue(DnsType t) => switch (t) {
  DnsType.a => dnsTypeA,
  DnsType.aaaa => dnsTypeAaaa,
  DnsType.cname => dnsTypeCname,
  DnsType.dname => dnsTypeDname,
  DnsType.mx => dnsTypeMx,
  DnsType.txt => dnsTypeTxt,
  DnsType.srv => dnsTypeSrv,
  DnsType.caa => dnsTypeCaa,
  DnsType.https => dnsTypeHttps,
  DnsType.svcb => dnsTypeSvcb,
  DnsType.opt => dnsTypeOpt,
  DnsType.ptr => dnsTypePtr,
  DnsType.ns => dnsTypeNs,
  DnsType.dnskey => dnsTypeDnskey,
  DnsType.ds => dnsTypeDs,
  DnsType.rrsig => dnsTypeRrsig,
  DnsType.soa => dnsTypeSoa,
  DnsType.nsec => dnsTypeNsec,
  DnsType.nsec3 => dnsTypeNsec3,
  DnsType.nsec3param => dnsTypeNsec3param,
  DnsType.opaque => 0,
};

DnsType? dnsTypeFromValue(int v) => switch (v) {
  dnsTypeA => DnsType.a,
  dnsTypeAaaa => DnsType.aaaa,
  dnsTypeCname => DnsType.cname,
  dnsTypeDname => DnsType.dname,
  dnsTypeMx => DnsType.mx,
  dnsTypeTxt => DnsType.txt,
  dnsTypeSrv => DnsType.srv,
  dnsTypeCaa => DnsType.caa,
  dnsTypeHttps => DnsType.https,
  dnsTypeSvcb => DnsType.svcb,
  dnsTypeOpt => DnsType.opt,
  dnsTypePtr => DnsType.ptr,
  dnsTypeNs => DnsType.ns,
  dnsTypeDnskey => DnsType.dnskey,
  dnsTypeDs => DnsType.ds,
  dnsTypeRrsig => DnsType.rrsig,
  dnsTypeSoa => DnsType.soa,
  dnsTypeNsec => DnsType.nsec,
  dnsTypeNsec3 => DnsType.nsec3,
  dnsTypeNsec3param => DnsType.nsec3param,
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

final class DnsDname extends DnsRecord {
  DnsDname({required super.name, required this.target, super.ttl = 300})
    : super(type: DnsType.dname);
  final String target;
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

/// RFC 4034 DNSKEY. [publicKey] is the algorithm-specific key, not a SPKI.
final class DnsDnskey extends DnsRecord {
  DnsDnskey({
    required super.name,
    required this.flags,
    required this.protocol,
    required this.algorithm,
    required this.publicKey,
    super.ttl = 300,
  }) : super(type: DnsType.dnskey);

  final int flags;
  final int protocol;
  final int algorithm;
  final Uint8List publicKey;
}

/// RFC 4034 DS. Digest bytes are not checked until [dnskeyMatchesDs].
final class DnsDs extends DnsRecord {
  DnsDs({
    required super.name,
    required this.keyTag,
    required this.algorithm,
    required this.digestType,
    required this.digest,
    super.ttl = 300,
  }) : super(type: DnsType.ds);

  final int keyTag;
  final int algorithm;
  final int digestType;
  final Uint8List digest;
}

/// RFC 4034 RRSIG. [signature] is not verified by the codec.
final class DnsRrsig extends DnsRecord {
  DnsRrsig({
    required super.name,
    required this.typeCovered,
    required this.algorithm,
    required this.labels,
    required this.originalTtl,
    required this.expiration,
    required this.inception,
    required this.keyTag,
    required this.signer,
    required this.signature,
    super.ttl = 300,
  }) : super(type: DnsType.rrsig);

  final int typeCovered;
  final int algorithm;
  final int labels;
  final int originalTtl;
  final int expiration;
  final int inception;
  final int keyTag;
  final String signer;
  final Uint8List signature;
}

/// RFC 1035 SOA.
final class DnsSoa extends DnsRecord {
  DnsSoa({
    required super.name,
    required this.mname,
    required this.rname,
    required this.serial,
    required this.refresh,
    required this.retry,
    required this.expire,
    required this.minimum,
    super.ttl = 300,
  }) : super(type: DnsType.soa);

  final String mname;
  final String rname;
  final int serial;
  final int refresh;
  final int retry;
  final int expire;
  final int minimum;
}

/// RFC 4034 NSEC. [types] is the wire type bitmap.
final class DnsNsec extends DnsRecord {
  DnsNsec({
    required super.name,
    required this.next,
    required this.types,
    super.ttl = 300,
  }) : super(type: DnsType.nsec);

  final String next;
  final Uint8List types;
}

/// RFC 5155 NSEC3. The hash is raw owner bytes, not a presentation name.
final class DnsNsec3 extends DnsRecord {
  DnsNsec3({
    required super.name,
    required this.hashAlgorithm,
    required this.flags,
    required this.iterations,
    required this.salt,
    required this.next,
    required this.types,
    super.ttl = 300,
  }) : super(type: DnsType.nsec3);

  final int hashAlgorithm;
  final int flags;
  final int iterations;
  final Uint8List salt;
  final Uint8List next;
  final Uint8List types;
}

/// RFC 5155 NSEC3PARAM.
final class DnsNsec3param extends DnsRecord {
  DnsNsec3param({
    required super.name,
    required this.hashAlgorithm,
    required this.flags,
    required this.iterations,
    required this.salt,
    super.ttl = 300,
  }) : super(type: DnsType.nsec3param);

  final int hashAlgorithm;
  final int flags;
  final int iterations;
  final Uint8List salt;
}

/// RFC 3597. An RR this codec does not interpret. [rdata] is the raw body.
final class DnsOpaque extends DnsRecord {
  DnsOpaque({
    required super.name,
    required this.typeCode,
    required this.rdata,
    super.ttl = 0,
    super.klass = dnsClassIn,
  }) : super(type: DnsType.opaque);

  final int typeCode;
  final Uint8List rdata;
}

/// Wire type of [rr]. Opaque records keep the code from the message.
int dnsRecordType(DnsRecord rr) =>
    rr is DnsOpaque ? rr.typeCode : dnsTypeValue(rr.type);

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

  /// Low 12 bits. RFC 6891 folds the OPT extended rcode above the header rcode.
  int get rcode {
    final base = flags & dnsRcodeMask;
    for (final rr in additional) {
      if (rr is DnsOpt) return (rr.extendedRcode << 4) | base;
    }
    return base;
  }

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
