import 'dart:convert';
import 'dart:typed_data';

import 'package:pqforge/pqforge.dart';
import 'package:swissarmyknife/swissarmyknife.dart';

import '../core/bytes.dart';
import '../core/errors.dart';
import '../core/lengths.dart';
import 'records.dart';

/// Lowercase US-ASCII wire name, uncompressed. Empty name is the root.
Result<Uint8List, PqTransportError> dnsCanonicalName(String name) {
  final trimmed = name.endsWith('.')
      ? name.substring(0, name.length - 1)
      : name;
  if (trimmed.isEmpty) return Result.success(Uint8List(1));
  final b = BytesBuilder(copy: false);
  for (final label in trimmed.split('.')) {
    if (label.isEmpty) {
      return Result.failure(PqTransportError.decodeFailure('empty dns label'));
    }
    final raw = _lowerAscii(utf8.encode(label));
    if (raw.length > dnsLabelMaxBytes) {
      return Result.failure(PqTransportError.decodeFailure('label too long'));
    }
    b.addByte(raw.length);
    b.add(raw);
  }
  b.addByte(0);
  final wire = b.takeBytes();
  if (wire.length > dnsNameMaxBytes) {
    return Result.failure(PqTransportError.decodeFailure('name too long'));
  }
  return Result.success(wire);
}

/// Labels in [name], not counting the root.
int dnsLabelCount(String name) {
  final trimmed = name.endsWith('.')
      ? name.substring(0, name.length - 1)
      : name;
  if (trimmed.isEmpty) return 0;
  var n = 0;
  for (final label in trimmed.split('.')) {
    if (label.isNotEmpty) n++;
  }
  return n;
}

Uint8List _lowerAscii(List<int> raw) {
  final out = Uint8List(raw.length);
  for (var i = 0; i < raw.length; i++) {
    final b = raw[i];
    out[i] = b >= 0x41 && b <= 0x5a ? b + 0x20 : b;
  }
  return out;
}

/// DNSKEY RDATA (RFC 4034 §2.1).
Uint8List dnskeyWireRdata(DnsDnskey key) {
  final b = BytesBuilder(copy: false);
  writeUint16(b, key.flags);
  b.addByte(key.protocol);
  b.addByte(key.algorithm);
  b.add(key.publicKey);
  return b.takeBytes();
}

/// RFC 4034 Appendix B.
int dnssecKeyTag(Uint8List rdata) {
  var ac = 0;
  for (var i = 0; i < rdata.length; i++) {
    ac += (i & 1) == 1 ? rdata[i] : rdata[i] << 8;
  }
  ac += (ac >> 16) & 0xffff;
  return ac & 0xffff;
}

/// SHA-256 (type 2) or SHA-384 (type 4) over the canonical owner and DNSKEY
/// RDATA. Other digests and other algorithms return false. This does not
/// fetch the parent.
bool dnskeyMatchesDs(DnsDnskey key, DnsDs ds) {
  if (!dnssecAlgorithmSupported(key.algorithm)) return false;
  if (ds.algorithm != key.algorithm) return false;
  if (!_sameName(key.name, ds.name)) return false;
  final rdata = dnskeyWireRdata(key);
  if (ds.keyTag != dnssecKeyTag(rdata)) return false;
  final owner = dnsCanonicalName(key.name);
  if (owner.isFailure) return false;
  final digest = _dsDigest(
    ds.digestType,
    concatBytes([owner.valueOrNull!, rdata]),
  );
  if (digest == null || digest.length != ds.digest.length) return false;
  return PqBytes.constantTimeEquals(digest, ds.digest);
}

/// True for the algorithms pqforge verifies: 8, 13, 14, and 15.
bool dnssecAlgorithmSupported(int algorithm) => switch (algorithm) {
  dnssecAlgorithmRsaSha256 ||
  dnssecAlgorithmEcdsaP256Sha256 ||
  dnssecAlgorithmEcdsaP384Sha384 ||
  dnssecAlgorithmEd25519 => true,
  _ => false,
};

/// Map key for a DNS name. Null when [name] is not a legal DNS name.
String? dnsNameKey(String name) {
  final wire = dnsCanonicalName(name);
  if (wire.isFailure) return null;
  return String.fromCharCodes(wire.valueOrNull!);
}

bool dnsNamesEqual(String a, String b) {
  final left = dnsNameKey(a);
  final right = dnsNameKey(b);
  if (left == null || right == null) return false;
  return left == right;
}

/// Parent of [name], or null at the root. `www.example.com.` → `example.com.`
String? dnsParent(String name) {
  final trimmed = name.endsWith('.')
      ? name.substring(0, name.length - 1)
      : name;
  if (trimmed.isEmpty) return null;
  final dot = trimmed.indexOf('.');
  if (dot < 0) return '.';
  return '${trimmed.substring(dot + 1)}.';
}

/// Owner name used in the signed bytes. RFC 4035 §5.3.2.
///
/// When [labels] is less than the label count of [expanded], the leftmost
/// labels are replaced with `*`.
Result<String, PqTransportError> dnsSignedOwner(String expanded, int labels) {
  final count = dnsLabelCount(expanded);
  if (labels > count) {
    return Result.failure(
      PqTransportError.unsupported('rrsig labels exceed the owner'),
    );
  }
  if (labels == count) return Result.success(expanded);
  if (labels == 0) return const Result.success('*.');
  final trimmed = expanded.endsWith('.')
      ? expanded.substring(0, expanded.length - 1)
      : expanded;
  final parts = trimmed.split('.');
  final tail = parts.sublist(parts.length - labels).join('.');
  return Result.success('*.$tail.');
}

/// RFC 4034 §3.1.8.1 and §6. The signature field is not included.
///
/// A smaller [DnsRrsig.labels] is a wildcard: the signed owner is `*` plus
/// the rightmost labels. Two RRs are ordered by canonical RDATA
/// (RFC 4034 §6.3), not by RDLENGTH and not by presentation order.
Result<Uint8List, PqTransportError> dnssecSignedMaterial({
  required List<DnsRecord> rrset,
  required DnsRrsig rrsig,
}) {
  if (rrset.isEmpty) {
    return Result.failure(PqTransportError.unsupported('empty rrset'));
  }
  if (!dnssecAlgorithmSupported(rrsig.algorithm)) {
    return Result.failure(
      PqTransportError.unsupported(
        'dnssec algorithm ${rrsig.algorithm} is not supported',
      ),
    );
  }
  final ownerName = rrset.first.name;
  final signedName = dnsSignedOwner(ownerName, rrsig.labels);
  if (signedName.isFailure) return Result.failure(signedName.errorOrNull!);
  final owner = dnsCanonicalName(signedName.valueOrNull!);
  if (owner.isFailure) return Result.failure(owner.errorOrNull!);
  final signer = dnsCanonicalName(rrsig.signer);
  if (signer.isFailure) return Result.failure(signer.errorOrNull!);
  final covered = <({Uint8List rdata, Uint8List wire})>[];
  for (final rr in rrset) {
    if (rr is DnsRrsig || rr is DnsOpt) {
      return Result.failure(
        PqTransportError.unsupported('rrsig does not cover itself'),
      );
    }
    if (!_sameName(rr.name, ownerName)) {
      return Result.failure(
        PqTransportError.unsupported('rrset owner mismatch'),
      );
    }
    if (dnsRecordType(rr) != rrsig.typeCovered) {
      return Result.failure(
        PqTransportError.unsupported('rrset type mismatch'),
      );
    }
    if (rr.klass != dnsClassIn) {
      return Result.failure(PqTransportError.unsupported('rrset class'));
    }
    final rdata = _canonicalRdata(rr);
    if (rdata.isFailure) return Result.failure(rdata.errorOrNull!);
    final body = rdata.valueOrNull!;
    final rrWire = BytesBuilder(copy: false);
    rrWire.add(owner.valueOrNull!);
    writeUint16(rrWire, rrsig.typeCovered);
    writeUint16(rrWire, dnsClassIn);
    writeUint32(rrWire, rrsig.originalTtl);
    writeUint16(rrWire, body.length);
    rrWire.add(body);
    covered.add((rdata: body, wire: rrWire.takeBytes()));
  }
  covered.sort((a, b) => _compareBytes(a.rdata, b.rdata));
  final prefix = BytesBuilder(copy: false);
  writeUint16(prefix, rrsig.typeCovered);
  prefix.addByte(rrsig.algorithm);
  prefix.addByte(rrsig.labels);
  writeUint32(prefix, rrsig.originalTtl);
  writeUint32(prefix, rrsig.expiration);
  writeUint32(prefix, rrsig.inception);
  writeUint16(prefix, rrsig.keyTag);
  prefix.add(signer.valueOrNull!);
  for (final rr in covered) {
    prefix.add(rr.wire);
  }
  return Result.success(prefix.takeBytes());
}

/// Verifies [rrset] under [rrsig] and [dnskey].
///
/// Algorithms 8, 13, 14, and 15. The signature check is the matching
/// pqforge verify. [now] is the caller's clock. Validity is 32-bit serial
/// arithmetic on `[inception, expiration)`. The zone bit is required.
/// A smaller label count is verified as a wildcard. The AD bit is not read.
Result<void, PqTransportError> verifyDnssecRrset({
  required List<DnsRecord> rrset,
  required DnsRrsig rrsig,
  required DnsDnskey dnskey,
  required DateTime now,
}) {
  if (!dnssecAlgorithmSupported(dnskey.algorithm) ||
      dnskey.protocol != dnssecProtocol ||
      dnskey.algorithm != rrsig.algorithm) {
    return Result.failure(
      PqTransportError.unsupported('dnskey algorithm is not supported'),
    );
  }
  if ((dnskey.flags & dnssecZoneKeyFlag) == 0) {
    return Result.failure(
      PqTransportError.unsupported('dnskey zone bit is clear'),
    );
  }
  if (!_sameName(dnskey.name, rrsig.signer)) {
    return Result.failure(
      PqTransportError.unsupported('dnskey owner is not the signer'),
    );
  }
  final rdata = dnskeyWireRdata(dnskey);
  if (dnssecKeyTag(rdata) != rrsig.keyTag) {
    return Result.failure(PqTransportError.unsupported('dnskey tag'));
  }
  final seconds = now.toUtc().millisecondsSinceEpoch ~/ 1000;
  if (!_rrsigInWindow(seconds, rrsig.inception, rrsig.expiration)) {
    return Result.failure(
      PqTransportError.unsupported('rrsig outside validity'),
    );
  }
  final material = dnssecSignedMaterial(rrset: rrset, rrsig: rrsig);
  if (material.isFailure) return Result.failure(material.errorOrNull!);
  final ok = _verifySignature(dnskey, material.valueOrNull!, rrsig.signature);
  if (!ok) {
    return Result.failure(PqTransportError.unsupported('rrsig verify failed'));
  }
  return const Result.success(null);
}

bool _sameName(String a, String b) => dnsNamesEqual(a, b);

Uint8List? _dsDigest(int digestType, Uint8List data) => switch (digestType) {
  dnssecDigestSha256 => PqBytes.sha256(data),
  dnssecDigestSha384 => PqBytes.sha384(data),
  _ => null,
};

/// pqforge verifies the signature. Lengths are the RFC lengths for the algorithm.
bool _verifySignature(DnsDnskey key, Uint8List message, Uint8List signature) {
  switch (key.algorithm) {
    case dnssecAlgorithmEcdsaP256Sha256:
      if (key.publicKey.length != dnssecEcdsaP256PublicKeyBytes ||
          signature.length != dnssecEcdsaP256SignatureBytes) {
        return false;
      }
      final point = Uint8List(dnssecEcdsaP256PublicKeyBytes + 1)
        ..[0] = 0x04
        ..setRange(1, dnssecEcdsaP256PublicKeyBytes + 1, key.publicKey);
      return PqEcdsaP256.verify(
        publicKey: point,
        message: message,
        signature: signature,
      );
    case dnssecAlgorithmEcdsaP384Sha384:
      if (key.publicKey.length != dnssecEcdsaP384PublicKeyBytes ||
          signature.length != dnssecEcdsaP384SignatureBytes) {
        return false;
      }
      final point = Uint8List(dnssecEcdsaP384PublicKeyBytes + 1)
        ..[0] = 0x04
        ..setRange(1, dnssecEcdsaP384PublicKeyBytes + 1, key.publicKey);
      return PqEcdsaP384.verify(
        publicKey: point,
        message: message,
        signature: signature,
      );
    case dnssecAlgorithmEd25519:
      if (key.publicKey.length != dnssecEd25519PublicKeyBytes ||
          signature.length != dnssecEd25519SignatureBytes) {
        return false;
      }
      return PqEd25519.verify(
        publicKey: key.publicKey,
        message: message,
        signature: signature,
      );
    case dnssecAlgorithmRsaSha256:
      final rsa = _rsaPublic(key.publicKey);
      if (rsa == null) return false;
      return PqRsa.verifyPkcs1(
        modulus: rsa.$1,
        exponent: rsa.$2,
        message: message,
        signature: signature,
        hash: PqRsaHash.sha256,
      );
    default:
      return false;
  }
}

/// RFC 3110. Returns modulus, exponent.
(Uint8List, Uint8List)? _rsaPublic(Uint8List key) {
  if (key.isEmpty) return null;
  final int expLen;
  final int start;
  if (key[0] == 0) {
    if (key.length < 3) return null;
    expLen = (key[1] << 8) | key[2];
    start = 3;
  } else {
    expLen = key[0];
    start = 1;
  }
  if (expLen <= 0 || start + expLen >= key.length) return null;
  return (
    Uint8List.sublistView(key, start + expLen),
    Uint8List.sublistView(key, start, start + expLen),
  );
}

/// RFC 4034 §4.1.2. [typeCode] is set in [bitmap].
bool dnsBitmapContains(Uint8List bitmap, int typeCode) {
  final window = typeCode >> 8;
  final bit = typeCode & 0xff;
  var i = 0;
  while (i + 2 <= bitmap.length) {
    final block = bitmap[i];
    final len = bitmap[i + 1];
    if (len < 1 || len > dnsNsecWindowBytes || i + 2 + len > bitmap.length) {
      return false;
    }
    if (block == window) {
      final byte = bit >> 3;
      if (byte >= len) return false;
      return (bitmap[i + 2 + byte] & (0x80 >> (bit & 7))) != 0;
    }
    i += 2 + len;
  }
  return false;
}

/// Canonical type bitmap. Windows are ascending. Unused trailing bytes are cut.
Uint8List dnsTypeBitmap(List<int> types) {
  final windows = <int, List<int>>{};
  for (final type in types) {
    final bytes = windows.putIfAbsent(
      type >> 8,
      () => List<int>.filled(dnsNsecWindowBytes, 0),
    );
    final bit = type & 0xff;
    bytes[bit >> 3] |= 0x80 >> (bit & 7);
  }
  final out = BytesBuilder(copy: false);
  final keys = windows.keys.toList()..sort();
  for (final window in keys) {
    final bytes = windows[window]!;
    var len = bytes.length;
    while (len > 0 && bytes[len - 1] == 0) {
      len--;
    }
    if (len == 0) continue;
    out.addByte(window);
    out.addByte(len);
    out.add(bytes.sublist(0, len));
  }
  return out.takeBytes();
}

/// RFC 4034 §6.1 and RFC 4035 §5.4. [name] is strictly between [owner] and [next].
///
/// A [next] that sorts at or before [owner] wraps, which is the last name in
/// the zone.
bool dnsNsecCovers(String owner, String next, String name) {
  final o = dnsCanonicalName(owner);
  final n = dnsCanonicalName(next);
  final q = dnsCanonicalName(name);
  if (o.isFailure || n.isFailure || q.isFailure) return false;
  if (dnsNamesEqual(owner, name) || dnsNamesEqual(next, name)) return false;
  final ownerNext = _compareBytes(o.valueOrNull!, n.valueOrNull!);
  final ownerName = _compareBytes(o.valueOrNull!, q.valueOrNull!);
  final nameNext = _compareBytes(q.valueOrNull!, n.valueOrNull!);
  if (ownerNext < 0) return ownerName < 0 && nameNext < 0;
  return ownerName < 0 || nameNext < 0;
}

/// RFC 4035 §5.4. NODATA at [qname] for [qtype]. A referral is not NODATA.
bool dnsNsecProvesNoData(DnsNsec nsec, String qname, int qtype) {
  if (!dnsNamesEqual(nsec.name, qname)) return false;
  if (dnsBitmapContains(nsec.types, qtype)) return false;
  if (qtype != dnsTypeDs && dnsBitmapContains(nsec.types, dnsTypeCname)) {
    return false;
  }
  if (qtype != dnsTypeDs &&
      dnsBitmapContains(nsec.types, dnsTypeNs) &&
      !dnsBitmapContains(nsec.types, dnsTypeSoa)) {
    return false;
  }
  return true;
}

/// RFC 4035 §5.4. [zone] is the authenticated apex. The wildcard at the
/// closest encloser must also be covered.
Result<void, PqTransportError> dnsNsecProvesNameError({
  required String qname,
  required String zone,
  required List<DnsNsec> nsecs,
}) {
  if (dnsNamesEqual(qname, zone) || !_under(qname, zone)) {
    return Result.failure(PqTransportError.unexpectedMessage('nsec zone'));
  }
  if (nsecs.any((n) => dnsNamesEqual(n.name, qname))) {
    return Result.failure(PqTransportError.unexpectedMessage('nsec exists'));
  }
  if (!nsecs.any((n) => dnsNsecCovers(n.name, n.next, qname))) {
    return Result.failure(PqTransportError.unexpectedMessage('nsec cover'));
  }
  final encloser = _closestEncloser(qname, zone, nsecs);
  if (encloser == null) {
    return Result.failure(PqTransportError.unexpectedMessage('nsec encloser'));
  }
  final wildcard = dnsNamesEqual(encloser, '.') ? '*.' : '*.$encloser';
  if (!nsecs.any((n) => dnsNsecCovers(n.name, n.next, wildcard))) {
    return Result.failure(PqTransportError.unexpectedMessage('nsec wildcard'));
  }
  return const Result.success(null);
}

bool _under(String name, String zone) {
  var current = name;
  while (true) {
    final parent = dnsParent(current);
    if (parent == null) return false;
    if (dnsNamesEqual(parent, zone)) return true;
    current = parent;
  }
}

String? _closestEncloser(String qname, String zone, List<DnsNsec> nsecs) {
  var name = dnsParent(qname);
  while (name != null) {
    final current = name;
    if (dnsNamesEqual(current, zone) ||
        nsecs.any((n) => dnsNamesEqual(n.name, current))) {
      return current;
    }
    if (dnsNamesEqual(name, '.')) return null;
    name = dnsParent(name);
  }
  return null;
}

/// RFC 4034 §3.1.5 and RFC 1982. Half-open `[inception, expiration)`.
///
/// A span of 0, or of 2^31 seconds or more, is not a defined signature
/// lifetime and fails closed.
bool _rrsigInWindow(int now, int inception, int expiration) {
  final n = now & 0xffffffff;
  final i = inception & 0xffffffff;
  final e = expiration & 0xffffffff;
  final span = (e - i) & 0xffffffff;
  if (span == 0 || span >= 0x80000000) return false;
  final fromStart = (n - i) & 0xffffffff;
  return fromStart < span;
}

int _compareBytes(Uint8List a, Uint8List b) {
  final n = a.length < b.length ? a.length : b.length;
  for (var i = 0; i < n; i++) {
    final d = a[i] - b[i];
    if (d != 0) return d;
  }
  return a.length - b.length;
}

Result<Uint8List, PqTransportError> _canonicalRdata(DnsRecord rr) {
  final b = BytesBuilder(copy: false);
  switch (rr) {
    case DnsA(:final address):
      if (address.length != 4) {
        return Result.failure(PqTransportError.decodeFailure('A rdata'));
      }
      b.add(address);
    case DnsAaaa(:final address):
      if (address.length != 16) {
        return Result.failure(PqTransportError.decodeFailure('AAAA rdata'));
      }
      b.add(address);
    case DnsCname(:final canonical):
      final named = _addName(b, canonical);
      if (named.isFailure) return Result.failure(named.errorOrNull!);
    case DnsPtr(:final pointer):
      final named = _addName(b, pointer);
      if (named.isFailure) return Result.failure(named.errorOrNull!);
    case DnsNs(:final nameserver):
      final named = _addName(b, nameserver);
      if (named.isFailure) return Result.failure(named.errorOrNull!);
    case DnsMx(:final preference, :final exchange):
      writeUint16(b, preference);
      final named = _addName(b, exchange);
      if (named.isFailure) return Result.failure(named.errorOrNull!);
    case DnsTxt(:final strings):
      for (final s in strings) {
        final raw = utf8.encode(s);
        if (raw.length > 255) {
          return Result.failure(PqTransportError.decodeFailure('txt too long'));
        }
        b.addByte(raw.length);
        b.add(raw);
      }
    case DnsSrv(:final priority, :final weight, :final port, :final target):
      writeUint16(b, priority);
      writeUint16(b, weight);
      writeUint16(b, port);
      final named = _addName(b, target);
      if (named.isFailure) return Result.failure(named.errorOrNull!);
    case DnsCaa(:final flags, :final tag, :final value):
      b.addByte(flags);
      final tb = utf8.encode(tag);
      if (tb.length > 255) {
        return Result.failure(PqTransportError.decodeFailure('caa'));
      }
      b.addByte(tb.length);
      b.add(tb);
      b.add(utf8.encode(value));
    case DnsHttps() || DnsSvcb():
      final s = rr as DnsSvcb;
      writeUint16(b, s.priority);
      final named = _addName(b, s.target);
      if (named.isFailure) return Result.failure(named.errorOrNull!);
      final keys = s.params.keys.toList()..sort();
      for (final k in keys) {
        writeUint16(b, k);
        final v = s.params[k]!;
        writeUint16(b, v.length);
        b.add(v);
      }
    case DnsOpt():
      return Result.failure(PqTransportError.unsupported('opt is not signed'));
    case DnsDnskey():
      b.add(dnskeyWireRdata(rr));
    case DnsDs(
      :final keyTag,
      :final algorithm,
      :final digestType,
      :final digest,
    ):
      writeUint16(b, keyTag);
      b.addByte(algorithm);
      b.addByte(digestType);
      b.add(digest);
    case DnsRrsig():
      return Result.failure(
        PqTransportError.unsupported('rrsig does not cover itself'),
      );
    case DnsSoa(
      :final mname,
      :final rname,
      :final serial,
      :final refresh,
      :final retry,
      :final expire,
      :final minimum,
    ):
      final m = _addName(b, mname);
      if (m.isFailure) return Result.failure(m.errorOrNull!);
      final r = _addName(b, rname);
      if (r.isFailure) return Result.failure(r.errorOrNull!);
      writeUint32(b, serial);
      writeUint32(b, refresh);
      writeUint32(b, retry);
      writeUint32(b, expire);
      writeUint32(b, minimum);
    case DnsNsec(:final next, :final types):
      final n = _addName(b, next);
      if (n.isFailure) return Result.failure(n.errorOrNull!);
      b.add(types);
    case DnsNsec3(
      :final hashAlgorithm,
      :final flags,
      :final iterations,
      :final salt,
      :final next,
      :final types,
    ):
      b.addByte(hashAlgorithm);
      b.addByte(flags);
      writeUint16(b, iterations);
      b.addByte(salt.length);
      b.add(salt);
      b.addByte(next.length);
      b.add(next);
      b.add(types);
    case DnsNsec3param(
      :final hashAlgorithm,
      :final flags,
      :final iterations,
      :final salt,
    ):
      b.addByte(hashAlgorithm);
      b.addByte(flags);
      writeUint16(b, iterations);
      b.addByte(salt.length);
      b.add(salt);
    case DnsOpaque(:final rdata):
      b.add(rdata);
  }
  return Result.success(b.takeBytes());
}

Result<void, PqTransportError> _addName(BytesBuilder b, String name) {
  final n = dnsCanonicalName(name);
  if (n.isFailure) return Result.failure(n.errorOrNull!);
  b.add(n.valueOrNull!);
  return const Result.success(null);
}
