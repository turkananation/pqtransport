import 'dart:convert';
import 'dart:typed_data';

import 'package:swissarmyknife/swissarmyknife.dart';

import '../core/bytes.dart';
import '../core/errors.dart';
import '../core/lengths.dart';

/// RFC 7541 header field. Names are lowercase on the HTTP/2 path.
final class HpackHeader {
  const HpackHeader(this.name, this.value);

  final String name;
  final String value;

  @override
  bool operator ==(Object other) =>
      other is HpackHeader && other.name == name && other.value == value;

  @override
  int get hashCode => Object.hash(name, value);

  @override
  String toString() => '$name: $value';
}

/// RFC 7541 Appendix A static table (1-based indices on the wire).
const List<HpackHeader> hpackStaticTable = [
  HpackHeader(':authority', ''),
  HpackHeader(':method', 'GET'),
  HpackHeader(':method', 'POST'),
  HpackHeader(':path', '/'),
  HpackHeader(':path', '/index.html'),
  HpackHeader(':scheme', 'http'),
  HpackHeader(':scheme', 'https'),
  HpackHeader(':status', '200'),
  HpackHeader(':status', '204'),
  HpackHeader(':status', '206'),
  HpackHeader(':status', '304'),
  HpackHeader(':status', '400'),
  HpackHeader(':status', '404'),
  HpackHeader(':status', '500'),
  HpackHeader('accept-charset', ''),
  HpackHeader('accept-encoding', 'gzip, deflate'),
  HpackHeader('accept-language', ''),
  HpackHeader('accept-ranges', ''),
  HpackHeader('accept', ''),
  HpackHeader('access-control-allow-origin', ''),
  HpackHeader('age', ''),
  HpackHeader('allow', ''),
  HpackHeader('authorization', ''),
  HpackHeader('cache-control', ''),
  HpackHeader('content-disposition', ''),
  HpackHeader('content-encoding', ''),
  HpackHeader('content-language', ''),
  HpackHeader('content-length', ''),
  HpackHeader('content-location', ''),
  HpackHeader('content-range', ''),
  HpackHeader('content-type', ''),
  HpackHeader('cookie', ''),
  HpackHeader('date', ''),
  HpackHeader('etag', ''),
  HpackHeader('expect', ''),
  HpackHeader('expires', ''),
  HpackHeader('from', ''),
  HpackHeader('host', ''),
  HpackHeader('if-match', ''),
  HpackHeader('if-modified-since', ''),
  HpackHeader('if-none-match', ''),
  HpackHeader('if-range', ''),
  HpackHeader('if-unmodified-since', ''),
  HpackHeader('last-modified', ''),
  HpackHeader('link', ''),
  HpackHeader('location', ''),
  HpackHeader('max-forwards', ''),
  HpackHeader('proxy-authenticate', ''),
  HpackHeader('proxy-authorization', ''),
  HpackHeader('range', ''),
  HpackHeader('referer', ''),
  HpackHeader('refresh', ''),
  HpackHeader('retry-after', ''),
  HpackHeader('server', ''),
  HpackHeader('set-cookie', ''),
  HpackHeader('strict-transport-security', ''),
  HpackHeader('transfer-encoding', ''),
  HpackHeader('user-agent', ''),
  HpackHeader('vary', ''),
  HpackHeader('via', ''),
  HpackHeader('www-authenticate', ''),
];

/// RFC 7541 encoder/decoder with a static table plus one dynamic table.
final class HpackCodec {
  HpackCodec({int tableSize = http2DefaultHeaderTableSize})
    : _maxTableSize = tableSize;

  int _maxTableSize;
  final List<HpackHeader> _dynamic = [];
  int _dynamicSize = 0;
  int? _pendingTableSize;

  int get tableSize => _maxTableSize;

  /// RFC 7541 §4.2. Encoder emits a size update on the next header block.
  void setMaxTableSize(int size) {
    if (size < 0) return;
    _pendingTableSize = size;
    _applyTableSize(size);
  }

  Uint8List encode(List<HpackHeader> headers, {bool huffman = true}) {
    final b = BytesBuilder(copy: false);
    final pending = _pendingTableSize;
    if (pending != null) {
      _writeInt(b, pending, 5, hpackTableSizeUpdate);
      _pendingTableSize = null;
    }
    for (final h in headers) {
      final (nv, nameIndex) = _find(h);
      if (nv != null) {
        _writeInt(b, nv, 7, hpackIndexedMask);
        continue;
      }
      if (nameIndex != null) {
        _writeInt(b, nameIndex, 6, hpackLiteralIncremental);
      } else {
        _writeInt(b, 0, 6, hpackLiteralIncremental);
        _writeString(b, h.name, huffman: huffman);
      }
      _writeString(b, h.value, huffman: huffman);
      _insert(h);
    }
    return b.takeBytes();
  }

  Result<List<HpackHeader>, PqTransportError> decode(Uint8List block) {
    if (block.length > httpMaxHeaderBytes) {
      return Result.failure(PqTransportError.decodeFailure('hpack huge'));
    }
    final out = <HpackHeader>[];
    var i = 0;
    while (i < block.length) {
      final b0 = block[i];
      if ((b0 & hpackIndexedMask) != 0) {
        final n = _readInt(block, i, 7);
        if (n.isFailure) return Result.failure(n.errorOrNull!);
        final (index, next) = n.valueOrNull!;
        i = next;
        if (index == 0) {
          return Result.failure(
            PqTransportError.decodeFailure('hpack index 0'),
          );
        }
        final h = _at(index);
        if (h == null) {
          return Result.failure(
            PqTransportError.decodeFailure('hpack missing $index'),
          );
        }
        out.add(h);
      } else if ((b0 & hpackLiteralIncrementalMask) ==
          hpackLiteralIncremental) {
        final parsed = _readLiteral(block, i, 6, incremental: true);
        if (parsed.isFailure) return Result.failure(parsed.errorOrNull!);
        final (h, next) = parsed.valueOrNull!;
        i = next;
        out.add(h);
      } else if ((b0 & hpackTableSizeUpdateMask) == hpackTableSizeUpdate) {
        final n = _readInt(block, i, 5);
        if (n.isFailure) return Result.failure(n.errorOrNull!);
        final (size, next) = n.valueOrNull!;
        i = next;
        if (size > _maxTableSize) {
          return Result.failure(
            PqTransportError.decodeFailure('hpack table size'),
          );
        }
        _applyTableSize(size);
      } else {
        final parsed = _readLiteral(block, i, 4, incremental: false);
        if (parsed.isFailure) return Result.failure(parsed.errorOrNull!);
        final (h, next) = parsed.valueOrNull!;
        i = next;
        out.add(h);
      }
    }
    return Result.success(out);
  }

  Result<(HpackHeader, int), PqTransportError> _readLiteral(
    Uint8List block,
    int offset,
    int prefixBits, {
    required bool incremental,
  }) {
    final n = _readInt(block, offset, prefixBits);
    if (n.isFailure) return Result.failure(n.errorOrNull!);
    var (nameIndex, i) = n.valueOrNull!;
    late final String name;
    if (nameIndex == 0) {
      final s = _readString(block, i);
      if (s.isFailure) return Result.failure(s.errorOrNull!);
      name = s.valueOrNull!.$1;
      i = s.valueOrNull!.$2;
    } else {
      final h = _at(nameIndex);
      if (h == null) {
        return Result.failure(
          PqTransportError.decodeFailure('hpack name $nameIndex'),
        );
      }
      name = h.name;
    }
    final v = _readString(block, i);
    if (v.isFailure) return Result.failure(v.errorOrNull!);
    final header = HpackHeader(name, v.valueOrNull!.$1);
    if (incremental) _insert(header);
    return Result.success((header, v.valueOrNull!.$2));
  }

  (int? nameValue, int? nameIndex) _find(HpackHeader h) {
    int? nameIndex;
    for (var i = 0; i < hpackStaticTable.length; i++) {
      final e = hpackStaticTable[i];
      if (e.name != h.name) continue;
      nameIndex ??= i + 1;
      if (e.value == h.value) return (i + 1, nameIndex);
    }
    for (var i = 0; i < _dynamic.length; i++) {
      final e = _dynamic[i];
      if (e.name != h.name) continue;
      final idx = hpackStaticTableLength + 1 + i;
      nameIndex ??= idx;
      if (e.value == h.value) return (idx, nameIndex);
    }
    return (null, nameIndex);
  }

  HpackHeader? _at(int index) {
    if (index <= 0) return null;
    if (index <= hpackStaticTableLength) {
      return hpackStaticTable[index - 1];
    }
    final di = index - hpackStaticTableLength - 1;
    if (di < 0 || di >= _dynamic.length) return null;
    return _dynamic[di];
  }

  void _insert(HpackHeader h) {
    final size = h.name.length + h.value.length + hpackEntryOverheadBytes;
    if (size > _maxTableSize) {
      _dynamic.clear();
      _dynamicSize = 0;
      return;
    }
    while (_dynamicSize + size > _maxTableSize && _dynamic.isNotEmpty) {
      final evicted = _dynamic.removeLast();
      _dynamicSize -=
          evicted.name.length + evicted.value.length + hpackEntryOverheadBytes;
    }
    _dynamic.insert(0, h);
    _dynamicSize += size;
  }

  void _applyTableSize(int size) {
    _maxTableSize = size;
    while (_dynamicSize > _maxTableSize && _dynamic.isNotEmpty) {
      final evicted = _dynamic.removeLast();
      _dynamicSize -=
          evicted.name.length + evicted.value.length + hpackEntryOverheadBytes;
    }
  }

  static void _writeInt(BytesBuilder b, int value, int prefixBits, int high) {
    final max = (1 << prefixBits) - 1;
    if (value < max) {
      b.addByte(high | value);
      return;
    }
    b.addByte(high | max);
    var v = value - max;
    while (v >= hpackIntContinuation) {
      b.addByte((v & 0x7f) | hpackIntContinuation);
      v >>= 7;
    }
    b.addByte(v);
  }

  static Result<(int, int), PqTransportError> _readInt(
    Uint8List buf,
    int offset,
    int prefixBits,
  ) {
    if (offset >= buf.length) {
      return Result.failure(PqTransportError.decodeFailure('hpack int'));
    }
    final max = (1 << prefixBits) - 1;
    final first = buf[offset] & max;
    var i = offset + 1;
    if (first < max) return Result.success((first, i));
    var value = first;
    var shift = 0;
    while (true) {
      if (i >= buf.length) {
        return Result.failure(PqTransportError.decodeFailure('hpack int'));
      }
      if (shift > hpackMaxIntegerShift) {
        return Result.failure(
          PqTransportError.decodeFailure('hpack int overflow'),
        );
      }
      final b = buf[i++];
      value += (b & 0x7f) << shift;
      if ((b & hpackIntContinuation) == 0) break;
      shift += 7;
    }
    return Result.success((value, i));
  }

  static void _writeString(BytesBuilder b, String s, {required bool huffman}) {
    final raw = utf8.encode(s);
    if (huffman) {
      final enc = hpackHuffmanEncode(raw);
      _writeInt(b, enc.length, 7, hpackHuffmanBit);
      b.add(enc);
      return;
    }
    _writeInt(b, raw.length, 7, 0);
    b.add(raw);
  }

  static Result<(String, int), PqTransportError> _readString(
    Uint8List buf,
    int offset,
  ) {
    if (offset >= buf.length) {
      return Result.failure(PqTransportError.decodeFailure('hpack str'));
    }
    final huffman = (buf[offset] & hpackHuffmanBit) != 0;
    final n = _readInt(buf, offset, 7);
    if (n.isFailure) return Result.failure(n.errorOrNull!);
    final (len, i) = n.valueOrNull!;
    if (len < 0 || i + len > buf.length) {
      return Result.failure(PqTransportError.decodeFailure('hpack str len'));
    }
    final sliceBytes = slice(buf, i, i + len);
    try {
      if (huffman) {
        final dec = hpackHuffmanDecode(sliceBytes);
        if (dec.isFailure) return Result.failure(dec.errorOrNull!);
        return Result.success((utf8.decode(dec.valueOrNull!), i + len));
      }
      return Result.success((utf8.decode(sliceBytes), i + len));
    } on FormatException {
      return Result.failure(PqTransportError.decodeFailure('hpack utf8'));
    }
  }
}

Uint8List hpackHuffmanEncode(List<int> bytes) {
  var acc = 0;
  var nbits = 0;
  final out = BytesBuilder(copy: false);
  for (final b in bytes) {
    var code = _huffCode[b];
    var len = _huffBits[b];
    while (len > 0) {
      final space = 8 - nbits;
      final take = len < space ? len : space;
      final shift = len - take;
      acc = (acc << take) | ((code >> shift) & ((1 << take) - 1));
      nbits += take;
      len -= take;
      code &= (1 << len) - 1;
      if (nbits == 8) {
        out.addByte(acc);
        acc = 0;
        nbits = 0;
      }
    }
  }
  if (nbits > 0) {
    final pad = 8 - nbits;
    acc = (acc << pad) | ((1 << pad) - 1);
    out.addByte(acc);
  }
  return out.takeBytes();
}

Result<Uint8List, PqTransportError> hpackHuffmanDecode(Uint8List wire) {
  var acc = 0;
  var nbits = 0;
  final out = BytesBuilder(copy: false);
  for (final b in wire) {
    for (var bit = 7; bit >= 0; bit--) {
      acc = (acc << 1) | ((b >> bit) & 1);
      nbits++;
      final sym = _huffLookup(acc, nbits);
      if (sym == null) {
        if (nbits > hpackHuffmanMaxCodeBits) {
          return Result.failure(PqTransportError.decodeFailure('huffman'));
        }
        continue;
      }
      if (sym == 256) {
        return Result.failure(PqTransportError.decodeFailure('huffman eos'));
      }
      out.addByte(sym);
      acc = 0;
      nbits = 0;
    }
  }
  if (nbits > 7) {
    return Result.failure(PqTransportError.decodeFailure('huffman pad'));
  }
  if (nbits > 0) {
    final pad = (1 << nbits) - 1;
    if (acc != pad) {
      return Result.failure(PqTransportError.decodeFailure('huffman pad'));
    }
  }
  return Result.success(out.takeBytes());
}

List<Map<int, int>>? _huffByLen;

int? _huffLookup(int acc, int nbits) {
  final table = _huffByLen ??= _buildHuffByLen();
  if (nbits <= 0 || nbits >= table.length) return null;
  return table[nbits][acc];
}

List<Map<int, int>> _buildHuffByLen() {
  final tables = List<Map<int, int>>.generate(
    hpackHuffmanMaxCodeBits + 1,
    (_) => <int, int>{},
  );
  for (var s = 0; s < _huffCode.length; s++) {
    tables[_huffBits[s]][_huffCode[s]] = s;
  }
  return tables;
}

// RFC 7541 Appendix B. Index 256 is EOS (30 ones).
const List<int> _huffCode = [
  0x1ff8,
  0x7fffd8,
  0xfffffe2,
  0xfffffe3,
  0xfffffe4,
  0xfffffe5,
  0xfffffe6,
  0xfffffe7,
  0xfffffe8,
  0xffffea,
  0x3ffffffc,
  0xfffffe9,
  0xfffffea,
  0x3ffffffd,
  0xfffffeb,
  0xfffffec,
  0xfffffed,
  0xfffffee,
  0xfffffef,
  0xffffff0,
  0xffffff1,
  0xffffff2,
  0x3ffffffe,
  0xffffff3,
  0xffffff4,
  0xffffff5,
  0xffffff6,
  0xffffff7,
  0xffffff8,
  0xffffff9,
  0xffffffa,
  0xffffffb,
  0x14,
  0x3f8,
  0x3f9,
  0xffa,
  0x1ff9,
  0x15,
  0xf8,
  0x7fa,
  0x3fa,
  0x3fb,
  0xf9,
  0x7fb,
  0xfa,
  0x16,
  0x17,
  0x18,
  0x0,
  0x1,
  0x2,
  0x19,
  0x1a,
  0x1b,
  0x1c,
  0x1d,
  0x1e,
  0x1f,
  0x5c,
  0xfb,
  0x7ffc,
  0x20,
  0xffb,
  0x3fc,
  0x1ffa,
  0x21,
  0x5d,
  0x5e,
  0x5f,
  0x60,
  0x61,
  0x62,
  0x63,
  0x64,
  0x65,
  0x66,
  0x67,
  0x68,
  0x69,
  0x6a,
  0x6b,
  0x6c,
  0x6d,
  0x6e,
  0x6f,
  0x70,
  0x71,
  0x72,
  0xfc,
  0x73,
  0xfd,
  0x1ffb,
  0x7fff0,
  0x1ffc,
  0x3ffc,
  0x22,
  0x7ffd,
  0x3,
  0x23,
  0x4,
  0x24,
  0x5,
  0x25,
  0x26,
  0x27,
  0x6,
  0x74,
  0x75,
  0x28,
  0x29,
  0x2a,
  0x7,
  0x2b,
  0x76,
  0x2c,
  0x8,
  0x9,
  0x2d,
  0x77,
  0x78,
  0x79,
  0x7a,
  0x7b,
  0x7ffe,
  0x7fc,
  0x3ffd,
  0x1ffd,
  0xffffffc,
  0xfffe6,
  0x3fffd2,
  0xfffe7,
  0xfffe8,
  0x3fffd3,
  0x3fffd4,
  0x3fffd5,
  0x7fffd9,
  0x3fffd6,
  0x7fffda,
  0x7fffdb,
  0x7fffdc,
  0x7fffdd,
  0x7fffde,
  0xffffeb,
  0x7fffdf,
  0xffffec,
  0xffffed,
  0x3fffd7,
  0x7fffe0,
  0xffffee,
  0x7fffe1,
  0x7fffe2,
  0x7fffe3,
  0x7fffe4,
  0x1fffdc,
  0x3fffd8,
  0x7fffe5,
  0x3fffd9,
  0x7fffe6,
  0x7fffe7,
  0xffffef,
  0x3fffda,
  0x1fffdd,
  0xfffe9,
  0x3fffdb,
  0x3fffdc,
  0x7fffe8,
  0x7fffe9,
  0x1fffde,
  0x7fffea,
  0x3fffdd,
  0x3fffde,
  0xfffff0,
  0x1fffdf,
  0x3fffdf,
  0x7fffeb,
  0x7fffec,
  0x1fffe0,
  0x1fffe1,
  0x3fffe0,
  0x1fffe2,
  0x7fffed,
  0x3fffe1,
  0x7fffee,
  0x7fffef,
  0xfffea,
  0x3fffe2,
  0x3fffe3,
  0x3fffe4,
  0x7ffff0,
  0x3fffe5,
  0x3fffe6,
  0x7ffff1,
  0x3ffffe0,
  0x3ffffe1,
  0xfffeb,
  0x7fff1,
  0x3fffe7,
  0x7ffff2,
  0x3fffe8,
  0x1ffffec,
  0x3ffffe2,
  0x3ffffe3,
  0x3ffffe4,
  0x7ffffde,
  0x7ffffdf,
  0x3ffffe5,
  0xfffff1,
  0x1ffffed,
  0x7fff2,
  0x1fffe3,
  0x3ffffe6,
  0x7ffffe0,
  0x7ffffe1,
  0x3ffffe7,
  0x7ffffe2,
  0xfffff2,
  0x1fffe4,
  0x1fffe5,
  0x3ffffe8,
  0x3ffffe9,
  0xffffffd,
  0x7ffffe3,
  0x7ffffe4,
  0x7ffffe5,
  0xfffec,
  0xfffff3,
  0xfffed,
  0x1fffe6,
  0x3fffe9,
  0x1fffe7,
  0x1fffe8,
  0x7ffff3,
  0x3fffea,
  0x3fffeb,
  0x1ffffee,
  0x1ffffef,
  0xfffff4,
  0xfffff5,
  0x3ffffea,
  0x7ffff4,
  0x3ffffeb,
  0x7ffffe6,
  0x3ffffec,
  0x3ffffed,
  0x7ffffe7,
  0x7ffffe8,
  0x7ffffe9,
  0x7ffffea,
  0x7ffffeb,
  0xffffffe,
  0x7ffffec,
  0x7ffffed,
  0x7ffffee,
  0x7ffffef,
  0x7fffff0,
  0x3ffffee,
  0x3fffffff,
];

const List<int> _huffBits = [
  13,
  23,
  28,
  28,
  28,
  28,
  28,
  28,
  28,
  24,
  30,
  28,
  28,
  30,
  28,
  28,
  28,
  28,
  28,
  28,
  28,
  28,
  30,
  28,
  28,
  28,
  28,
  28,
  28,
  28,
  28,
  28,
  6,
  10,
  10,
  12,
  13,
  6,
  8,
  11,
  10,
  10,
  8,
  11,
  8,
  6,
  6,
  6,
  5,
  5,
  5,
  6,
  6,
  6,
  6,
  6,
  6,
  6,
  7,
  8,
  15,
  6,
  12,
  10,
  13,
  6,
  7,
  7,
  7,
  7,
  7,
  7,
  7,
  7,
  7,
  7,
  7,
  7,
  7,
  7,
  7,
  7,
  7,
  7,
  7,
  7,
  7,
  7,
  8,
  7,
  8,
  13,
  19,
  13,
  14,
  6,
  15,
  5,
  6,
  5,
  6,
  5,
  6,
  6,
  6,
  5,
  7,
  7,
  6,
  6,
  6,
  5,
  6,
  7,
  6,
  5,
  5,
  6,
  7,
  7,
  7,
  7,
  7,
  15,
  11,
  14,
  13,
  28,
  20,
  22,
  20,
  20,
  22,
  22,
  22,
  23,
  22,
  23,
  23,
  23,
  23,
  23,
  24,
  23,
  24,
  24,
  22,
  23,
  24,
  23,
  23,
  23,
  23,
  21,
  22,
  23,
  22,
  23,
  23,
  24,
  22,
  21,
  20,
  22,
  22,
  23,
  23,
  21,
  23,
  22,
  22,
  24,
  21,
  22,
  23,
  23,
  21,
  21,
  22,
  21,
  23,
  22,
  23,
  23,
  20,
  22,
  22,
  22,
  23,
  22,
  22,
  23,
  26,
  26,
  20,
  19,
  22,
  23,
  22,
  25,
  26,
  26,
  26,
  27,
  27,
  26,
  24,
  25,
  19,
  21,
  26,
  27,
  27,
  26,
  27,
  24,
  21,
  21,
  26,
  26,
  28,
  27,
  27,
  27,
  20,
  24,
  20,
  21,
  22,
  21,
  21,
  23,
  22,
  22,
  25,
  25,
  24,
  24,
  26,
  23,
  26,
  27,
  26,
  26,
  27,
  27,
  27,
  27,
  27,
  28,
  27,
  27,
  27,
  27,
  27,
  26,
  30,
];
