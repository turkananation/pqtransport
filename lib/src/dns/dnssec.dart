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

/// SHA-256 DS (digest type 2) over the canonical owner and DNSKEY RDATA.
///
/// Other digest types and other algorithms return false. This does not fetch
/// the parent.
bool dnskeyMatchesDs(DnsDnskey key, DnsDs ds) {
  if (key.algorithm != dnssecAlgorithmEcdsaP256Sha256) return false;
  if (ds.algorithm != key.algorithm) return false;
  if (ds.digestType != dnssecDigestSha256) return false;
  if (ds.digest.length != dnssecSha256DigestBytes) return false;
  if (!_sameName(key.name, ds.name)) return false;
  final rdata = dnskeyWireRdata(key);
  if (ds.keyTag != dnssecKeyTag(rdata)) return false;
  final owner = dnsCanonicalName(key.name);
  if (owner.isFailure) return false;
  final digest = PqBytes.sha256(concatBytes([owner.valueOrNull!, rdata]));
  return PqBytes.constantTimeEquals(digest, ds.digest);
}

/// RFC 4034 §3.1.8.1 and §6. The signature field is not included.
///
/// Wildcards are not this slice: [DnsRrsig.labels] must equal the owner
/// label count. Two RRs are ordered by canonical RDATA (RFC 4034 §6.3),
/// not by RDLENGTH and not by presentation order.
Result<Uint8List, PqTransportError> dnssecSignedMaterial({
  required List<DnsRecord> rrset,
  required DnsRrsig rrsig,
}) {
  if (rrset.isEmpty) {
    return Result.failure(PqTransportError.unsupported('empty rrset'));
  }
  if (rrsig.algorithm != dnssecAlgorithmEcdsaP256Sha256) {
    return Result.failure(
      PqTransportError.unsupported(
        'dnssec algorithm ${rrsig.algorithm} is not ECDSAP256SHA256',
      ),
    );
  }
  final ownerName = rrset.first.name;
  if (dnsLabelCount(ownerName) != rrsig.labels) {
    return Result.failure(
      PqTransportError.unsupported('rrsig labels do not match the owner'),
    );
  }
  final owner = dnsCanonicalName(ownerName);
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
    if (dnsTypeValue(rr.type) != rrsig.typeCovered) {
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
/// ECDSAP256SHA256 (algorithm 13) only. The signature check is
/// [PqEcdsaP256.verify]. [now] is the caller's clock. Validity is 32-bit
/// serial arithmetic on `[inception, expiration)`. The zone bit is required.
/// The DNS header AD bit is not read.
Result<void, PqTransportError> verifyDnssecRrset({
  required List<DnsRecord> rrset,
  required DnsRrsig rrsig,
  required DnsDnskey dnskey,
  required DateTime now,
}) {
  if (dnskey.algorithm != dnssecAlgorithmEcdsaP256Sha256 ||
      dnskey.protocol != dnssecProtocol) {
    return Result.failure(
      PqTransportError.unsupported('dnskey is not ECDSAP256SHA256'),
    );
  }
  if ((dnskey.flags & dnssecZoneKeyFlag) == 0) {
    return Result.failure(
      PqTransportError.unsupported('dnskey zone bit is clear'),
    );
  }
  if (dnskey.publicKey.length != dnssecEcdsaP256PublicKeyBytes) {
    return Result.failure(PqTransportError.unsupported('dnskey p256 length'));
  }
  if (rrsig.signature.length != dnssecEcdsaP256SignatureBytes) {
    return Result.failure(PqTransportError.unsupported('rrsig p256 length'));
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
  final point = Uint8List(dnssecEcdsaP256PublicKeyBytes + 1)
    ..[0] = 0x04
    ..setRange(1, dnssecEcdsaP256PublicKeyBytes + 1, dnskey.publicKey);
  final ok = PqEcdsaP256.verify(
    publicKey: point,
    message: material.valueOrNull!,
    signature: rrsig.signature,
  );
  if (!ok) {
    return Result.failure(PqTransportError.unsupported('rrsig verify failed'));
  }
  return const Result.success(null);
}

bool _sameName(String a, String b) {
  final left = dnsCanonicalName(a);
  final right = dnsCanonicalName(b);
  if (left.isFailure || right.isFailure) return false;
  return PqBytes.constantTimeEquals(left.valueOrNull!, right.valueOrNull!);
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
  }
  return Result.success(b.takeBytes());
}

Result<void, PqTransportError> _addName(BytesBuilder b, String name) {
  final n = dnsCanonicalName(name);
  if (n.isFailure) return Result.failure(n.errorOrNull!);
  b.add(n.valueOrNull!);
  return const Result.success(null);
}
