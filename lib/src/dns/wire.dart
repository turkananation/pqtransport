import 'dart:convert';
import 'dart:typed_data';

import 'package:swissarmyknife/swissarmyknife.dart';

import '../core/bytes.dart';
import '../core/errors.dart';
import '../core/lengths.dart';
import 'records.dart';

Result<Uint8List, PqTransportError> encodeDnsMessage(DnsMessage msg) {
  final b = BytesBuilder(copy: false);
  writeUint16(b, msg.id);
  writeUint16(b, msg.flags);
  writeUint16(b, msg.questions.length);
  writeUint16(b, msg.answers.length);
  writeUint16(b, msg.authority.length);
  writeUint16(b, msg.additional.length);
  for (final q in msg.questions) {
    final n = _writeName(b, q.name);
    if (n.isFailure) return Result.failure(n.errorOrNull!);
    writeUint16(b, dnsTypeValue(q.type));
    writeUint16(b, q.klass);
  }
  for (final rr in [...msg.answers, ...msg.authority, ...msg.additional]) {
    final e = _writeRr(b, rr);
    if (e.isFailure) return Result.failure(e.errorOrNull!);
  }
  final wire = b.takeBytes();
  if (wire.length > dnsMessageMaxBytes) {
    return Result.failure(
      PqTransportError.decodeFailure('dns message too large'),
    );
  }
  return Result.success(wire);
}

/// Decode a DNS message. RFC 1035 §4.1.4 compression pointers in rdata
/// (CNAME / NS / PTR / MX / SRV / HTTPS / SVCB names) are offsets from the
/// **start of [wire]**, not from the start of that rdata slice. RDLENGTH
/// still bounds the record so a truncated name cannot consume the next RR.
Result<DnsMessage, PqTransportError> decodeDnsMessage(Uint8List wire) {
  if (wire.length < dnsHeaderBytes) {
    return Result.failure(PqTransportError.decodeFailure('short dns header'));
  }
  final r = _DnsReader(wire);
  final id = r.u16();
  final flags = r.u16();
  final qd = r.u16();
  final an = r.u16();
  final ns = r.u16();
  final ar = r.u16();
  if (r.failed != null) return Result.failure(r.failed!);
  final questions = <DnsQuestion>[];
  for (var i = 0; i < qd; i++) {
    final name = r.readName();
    if (name == null) return Result.failure(r.failed!);
    final typeV = r.u16();
    final klass = r.u16();
    final type = dnsTypeFromValue(typeV);
    if (type == null) {
      return Result.failure(
        PqTransportError.decodeFailure('unknown qtype $typeV'),
      );
    }
    questions.add(DnsQuestion(name: name, type: type, klass: klass));
  }
  final answers = <DnsRecord>[];
  final authority = <DnsRecord>[];
  final additional = <DnsRecord>[];
  for (var i = 0; i < an; i++) {
    final rr = r.readRr();
    if (rr == null) return Result.failure(r.failed!);
    answers.add(rr);
  }
  for (var i = 0; i < ns; i++) {
    final rr = r.readRr();
    if (rr == null) return Result.failure(r.failed!);
    authority.add(rr);
  }
  for (var i = 0; i < ar; i++) {
    final rr = r.readRr();
    if (rr == null) return Result.failure(r.failed!);
    additional.add(rr);
  }
  if (r.failed != null) return Result.failure(r.failed!);
  return Result.success(
    DnsMessage(
      id: id,
      flags: flags,
      questions: questions,
      answers: answers,
      authority: authority,
      additional: additional,
    ),
  );
}

Result<void, PqTransportError> _writeName(BytesBuilder b, String name) {
  if (name == '.' || name.isEmpty) {
    b.addByte(0);
    return const Result.success(null);
  }
  final labels = name.split('.').where((l) => l.isNotEmpty);
  for (final label in labels) {
    final bytes = utf8.encode(label);
    if (bytes.length > dnsLabelMaxBytes) {
      return Result.failure(PqTransportError.decodeFailure('label too long'));
    }
    b.addByte(bytes.length);
    b.add(bytes);
  }
  b.addByte(0);
  return const Result.success(null);
}

Result<void, PqTransportError> _writeRr(BytesBuilder b, DnsRecord rr) {
  final n = _writeName(b, rr.name);
  if (n.isFailure) return n;
  writeUint16(b, dnsTypeValue(rr.type));
  if (rr is DnsOpt) {
    writeUint16(b, rr.udpPayload);
    b.addByte(rr.extendedRcode);
    b.addByte(rr.version);
    writeUint16(b, rr.flags);
  } else {
    writeUint16(b, rr.klass);
    writeUint32(b, rr.ttl);
  }
  final rdata = BytesBuilder(copy: false);
  final body = _writeRdata(rdata, rr);
  if (body.isFailure) return body;
  final bytes = rdata.takeBytes();
  writeUint16(b, bytes.length);
  b.add(bytes);
  return const Result.success(null);
}

Result<void, PqTransportError> _writeRdata(BytesBuilder b, DnsRecord rr) {
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
      return _writeName(b, canonical);
    case DnsPtr(:final pointer):
      return _writeName(b, pointer);
    case DnsNs(:final nameserver):
      return _writeName(b, nameserver);
    case DnsMx(:final preference, :final exchange):
      writeUint16(b, preference);
      return _writeName(b, exchange);
    case DnsTxt(:final strings):
      for (final s in strings) {
        final bytes = utf8.encode(s);
        if (bytes.length > 255) {
          return Result.failure(PqTransportError.decodeFailure('txt too long'));
        }
        b.addByte(bytes.length);
        b.add(bytes);
      }
    case DnsSrv(:final priority, :final weight, :final port, :final target):
      writeUint16(b, priority);
      writeUint16(b, weight);
      writeUint16(b, port);
      return _writeName(b, target);
    case DnsCaa(:final flags, :final tag, :final value):
      b.addByte(flags);
      final tb = utf8.encode(tag);
      b.addByte(tb.length);
      b.add(tb);
      b.add(utf8.encode(value));
    case DnsHttps() || DnsSvcb():
      final s = rr as DnsSvcb;
      writeUint16(b, s.priority);
      final tn = _writeName(b, s.target);
      if (tn.isFailure) return tn;
      final keys = s.params.keys.toList()..sort();
      for (final k in keys) {
        writeUint16(b, k);
        final v = s.params[k]!;
        writeUint16(b, v.length);
        b.add(v);
      }
    case DnsOpt(:final options):
      final keys = options.keys.toList()..sort();
      for (final k in keys) {
        writeUint16(b, k);
        final v = options[k]!;
        writeUint16(b, v.length);
        b.add(v);
      }
  }
  return const Result.success(null);
}

final class _DnsReader {
  _DnsReader(this.wire);

  final Uint8List wire;
  int offset = 0;
  PqTransportError? failed;

  int get remaining => wire.length - offset;

  int u8() {
    if (remaining < 1) {
      failed ??= PqTransportError.decodeFailure('truncated u8');
      return 0;
    }
    return wire[offset++];
  }

  int u16() {
    if (remaining < 2) {
      failed ??= PqTransportError.decodeFailure('truncated u16');
      return 0;
    }
    final v = readUint16(wire, offset);
    offset += 2;
    return v;
  }

  int u32() {
    if (remaining < 4) {
      failed ??= PqTransportError.decodeFailure('truncated u32');
      return 0;
    }
    final v = readUint32(wire, offset);
    offset += 4;
    return v;
  }

  Uint8List take(int n) {
    if (remaining < n) {
      failed ??= PqTransportError.decodeFailure('truncated rdata');
      return Uint8List(0);
    }
    final out = slice(wire, offset, offset + n);
    offset += n;
    return out;
  }

  String? readName({int depth = 0, int? end}) {
    if (depth > dnsPointerDepthMax) {
      failed = PqTransportError.decodeFailure('pointer depth');
      return null;
    }
    final labels = <String>[];
    var hops = 0;
    var jumped = false;
    var returnTo = offset;
    final seen = <int>{};
    while (true) {
      final pos = jumped ? returnTo : offset;
      final localLimit = jumped ? wire.length : (end ?? wire.length);
      if (pos >= localLimit) {
        failed = PqTransportError.decodeFailure(
          jumped ? 'name oob' : 'truncated name',
        );
        return null;
      }
      if (!seen.add(pos)) {
        failed = PqTransportError.decodeFailure('pointer loop');
        return null;
      }
      final len = wire[pos];
      if ((len & dnsPointerMask) == dnsPointerMask) {
        hops++;
        if (hops > dnsPointerDepthMax) {
          failed = PqTransportError.decodeFailure('pointer loop');
          return null;
        }
        if (pos + 1 >= localLimit) {
          failed = PqTransportError.decodeFailure('truncated pointer');
          return null;
        }
        final ptr = ((len & 0x3f) << 8) | wire[pos + 1];
        if (!jumped) {
          offset += 2;
          jumped = true;
        }
        returnTo = ptr;
        continue;
      }
      if (!jumped) {
        offset++;
      } else {
        returnTo++;
      }
      if (len == 0) break;
      if (len > dnsLabelMaxBytes) {
        failed = PqTransportError.decodeFailure('label too long');
        return null;
      }
      final start = jumped ? returnTo : offset;
      if (start + len > localLimit) {
        failed = PqTransportError.decodeFailure('truncated label');
        return null;
      }
      labels.add(utf8.decode(wire.sublist(start, start + len)));
      if (jumped) {
        returnTo += len;
      } else {
        offset += len;
      }
    }
    if (labels.isEmpty) return '.';
    return '${labels.join('.')}.';
  }

  DnsRecord? readRr() {
    final name = readName();
    if (name == null) return null;
    final typeV = u16();
    final klass = u16();
    final ttl = u32();
    final rdlen = u16();
    if (failed != null) return null;
    if (remaining < rdlen) {
      failed = PqTransportError.decodeFailure('truncated rdata');
      return null;
    }
    final rdataStart = offset;
    final rdataEnd = rdataStart + rdlen;
    final type = dnsTypeFromValue(typeV);
    if (type == null) {
      failed = PqTransportError.decodeFailure('unknown rr type $typeV');
      offset = rdataEnd;
      return null;
    }
    final rec = _parseRdata(name, type, klass, ttl, rdataStart, rdataEnd);
    offset = rdataEnd;
    return rec;
  }

  bool _rdataNeed(int n, int rdataEnd) {
    if (offset + n > rdataEnd) {
      failed ??= PqTransportError.decodeFailure('truncated rdata');
      return false;
    }
    return true;
  }

  DnsRecord? _parseRdata(
    String name,
    DnsType type,
    int klass,
    int ttl,
    int rdataStart,
    int rdataEnd,
  ) {
    final rdata = slice(wire, rdataStart, rdataEnd);
    offset = rdataStart;
    switch (type) {
      case DnsType.a:
        if (rdata.length != 4) {
          failed = PqTransportError.decodeFailure('A length');
          return null;
        }
        return DnsA(name: name, address: rdata, ttl: ttl);
      case DnsType.aaaa:
        if (rdata.length != 16) {
          failed = PqTransportError.decodeFailure('AAAA length');
          return null;
        }
        return DnsAaaa(name: name, address: rdata, ttl: ttl);
      case DnsType.cname:
        final n = readName(end: rdataEnd);
        if (n == null) return null;
        return DnsCname(name: name, canonical: n, ttl: ttl);
      case DnsType.ptr:
        final n = readName(end: rdataEnd);
        if (n == null) return null;
        return DnsPtr(name: name, pointer: n, ttl: ttl);
      case DnsType.ns:
        final n = readName(end: rdataEnd);
        if (n == null) return null;
        return DnsNs(name: name, nameserver: n, ttl: ttl);
      case DnsType.mx:
        if (!_rdataNeed(2, rdataEnd)) return null;
        final pref = u16();
        final ex = readName(end: rdataEnd);
        if (ex == null) return null;
        return DnsMx(name: name, preference: pref, exchange: ex, ttl: ttl);
      case DnsType.txt:
        final inner = _DnsReader(rdata);
        final strings = <String>[];
        while (inner.remaining > 0) {
          final n = inner.u8();
          strings.add(utf8.decode(inner.take(n)));
        }
        if (inner.failed != null) {
          failed = inner.failed;
          return null;
        }
        return DnsTxt(name: name, strings: strings, ttl: ttl);
      case DnsType.srv:
        if (!_rdataNeed(6, rdataEnd)) return null;
        final pri = u16();
        final w = u16();
        final port = u16();
        final tgt = readName(end: rdataEnd);
        if (tgt == null) return null;
        return DnsSrv(
          name: name,
          priority: pri,
          weight: w,
          port: port,
          target: tgt,
          ttl: ttl,
        );
      case DnsType.caa:
        if (rdata.length < 2) {
          failed = PqTransportError.decodeFailure('caa');
          return null;
        }
        final flags = rdata[0];
        final tagLen = rdata[1];
        if (2 + tagLen > rdata.length) {
          failed = PqTransportError.decodeFailure('caa');
          return null;
        }
        final tag = utf8.decode(rdata.sublist(2, 2 + tagLen));
        final value = utf8.decode(rdata.sublist(2 + tagLen));
        return DnsCaa(
          name: name,
          flags: flags,
          tag: tag,
          value: value,
          ttl: ttl,
        );
      case DnsType.svcb:
      case DnsType.https:
        if (!_rdataNeed(2, rdataEnd)) return null;
        final pri = u16();
        final tgt = readName(end: rdataEnd);
        if (tgt == null) return null;
        final params = <int, Uint8List>{};
        while (offset + 4 <= rdataEnd) {
          final k = u16();
          final l = u16();
          if (!_rdataNeed(l, rdataEnd)) return null;
          params[k] = take(l);
        }
        if (type == DnsType.https) {
          return DnsHttps(
            name: name,
            priority: pri,
            target: tgt,
            params: params,
            ttl: ttl,
          );
        }
        return DnsSvcb(
          name: name,
          priority: pri,
          target: tgt,
          params: params,
          ttl: ttl,
        );
      case DnsType.opt:
        final inner = _DnsReader(rdata);
        final options = <int, Uint8List>{};
        while (inner.remaining > 0) {
          final k = inner.u16();
          final l = inner.u16();
          options[k] = inner.take(l);
        }
        if (inner.failed != null) {
          failed = inner.failed;
          return null;
        }
        return DnsOpt(
          udpPayload: klass,
          extendedRcode: (ttl >> 24) & 0xff,
          version: (ttl >> 16) & 0xff,
          flags: ttl & 0xffff,
          options: options,
        );
    }
  }
}
