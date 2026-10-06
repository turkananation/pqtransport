import 'dart:convert';
import 'dart:typed_data';

import 'package:swissarmyknife/swissarmyknife.dart';

import '../core/bytes.dart';
import '../core/errors.dart';
import '../core/lengths.dart';
import 'hpack.dart';

/// RFC 9204 Appendix A static table (0-based indices on the wire).
const List<HpackHeader> qpackStaticTable = [
  HpackHeader(':authority', ''),
  HpackHeader(':path', '/'),
  HpackHeader('age', '0'),
  HpackHeader('content-disposition', ''),
  HpackHeader('content-length', '0'),
  HpackHeader('cookie', ''),
  HpackHeader('date', ''),
  HpackHeader('etag', ''),
  HpackHeader('if-modified-since', ''),
  HpackHeader('if-none-match', ''),
  HpackHeader('last-modified', ''),
  HpackHeader('link', ''),
  HpackHeader('location', ''),
  HpackHeader('referer', ''),
  HpackHeader('set-cookie', ''),
  HpackHeader(':method', 'CONNECT'),
  HpackHeader(':method', 'DELETE'),
  HpackHeader(':method', 'GET'),
  HpackHeader(':method', 'HEAD'),
  HpackHeader(':method', 'OPTIONS'),
  HpackHeader(':method', 'POST'),
  HpackHeader(':method', 'PUT'),
  HpackHeader(':scheme', 'http'),
  HpackHeader(':scheme', 'https'),
  HpackHeader(':status', '103'),
  HpackHeader(':status', '200'),
  HpackHeader(':status', '304'),
  HpackHeader(':status', '404'),
  HpackHeader(':status', '503'),
  HpackHeader('accept', '*/*'),
  HpackHeader('accept', 'application/dns-message'),
  HpackHeader('accept-encoding', 'gzip, deflate, br'),
  HpackHeader('accept-ranges', 'bytes'),
  HpackHeader('access-control-allow-headers', 'cache-control'),
  HpackHeader('access-control-allow-headers', 'content-type'),
  HpackHeader('access-control-allow-origin', '*'),
  HpackHeader('cache-control', 'max-age=0'),
  HpackHeader('cache-control', 'max-age=2592000'),
  HpackHeader('cache-control', 'max-age=604800'),
  HpackHeader('cache-control', 'no-cache'),
  HpackHeader('cache-control', 'no-store'),
  HpackHeader('cache-control', 'public, max-age=31536000'),
  HpackHeader('content-encoding', 'br'),
  HpackHeader('content-encoding', 'gzip'),
  HpackHeader('content-type', 'application/dns-message'),
  HpackHeader('content-type', 'application/javascript'),
  HpackHeader('content-type', 'application/json'),
  HpackHeader('content-type', 'application/x-www-form-urlencoded'),
  HpackHeader('content-type', 'image/gif'),
  HpackHeader('content-type', 'image/jpeg'),
  HpackHeader('content-type', 'image/png'),
  HpackHeader('content-type', 'text/css'),
  HpackHeader('content-type', 'text/html; charset=utf-8'),
  HpackHeader('content-type', 'text/plain'),
  HpackHeader('content-type', 'text/plain;charset=utf-8'),
  HpackHeader('range', 'bytes=0-'),
  HpackHeader('strict-transport-security', 'max-age=31536000'),
  HpackHeader(
    'strict-transport-security',
    'max-age=31536000; includesubdomains',
  ),
  HpackHeader(
    'strict-transport-security',
    'max-age=31536000; includesubdomains; preload',
  ),
  HpackHeader('vary', 'accept-encoding'),
  HpackHeader('vary', 'origin'),
  HpackHeader('x-content-type-options', 'nosniff'),
  HpackHeader('x-xss-protection', '1; mode=block'),
  HpackHeader(':status', '100'),
  HpackHeader(':status', '204'),
  HpackHeader(':status', '206'),
  HpackHeader(':status', '302'),
  HpackHeader(':status', '400'),
  HpackHeader(':status', '403'),
  HpackHeader(':status', '421'),
  HpackHeader(':status', '425'),
  HpackHeader(':status', '500'),
  HpackHeader('accept-language', ''),
  HpackHeader('access-control-allow-credentials', 'FALSE'),
  HpackHeader('access-control-allow-credentials', 'TRUE'),
  HpackHeader('access-control-allow-headers', '*'),
  HpackHeader('access-control-allow-methods', 'get'),
  HpackHeader('access-control-allow-methods', 'get, post, options'),
  HpackHeader('access-control-allow-methods', 'options'),
  HpackHeader('access-control-expose-headers', 'content-length'),
  HpackHeader('access-control-request-headers', 'content-type'),
  HpackHeader('access-control-request-method', 'get'),
  HpackHeader('access-control-request-method', 'post'),
  HpackHeader('alt-svc', 'clear'),
  HpackHeader('authorization', ''),
  HpackHeader(
    'content-security-policy',
    "script-src 'none'; object-src 'none'; base-uri 'none'",
  ),
  HpackHeader('early-data', '1'),
  HpackHeader('expect-ct', ''),
  HpackHeader('forwarded', ''),
  HpackHeader('if-range', ''),
  HpackHeader('origin', ''),
  HpackHeader('purpose', 'prefetch'),
  HpackHeader('server', ''),
  HpackHeader('timing-allow-origin', '*'),
  HpackHeader('upgrade-insecure-requests', '1'),
  HpackHeader('user-agent', ''),
  HpackHeader('x-forwarded-for', ''),
  HpackHeader('x-frame-options', 'deny'),
  HpackHeader('x-frame-options', 'sameorigin'),
];

int _entrySize(HpackHeader h) =>
    utf8.encode(h.name).length +
    utf8.encode(h.value).length +
    hpackEntryOverheadBytes;

final class _DynTable {
  final List<HpackHeader> entries = [];
  var capacity = 0;
  var size = 0;
  var inserts = 0;
  var knownReceived = 0;

  void setCapacity(int cap) {
    capacity = cap;
    _evict();
  }

  void insert(HpackHeader h) {
    final sz = _entrySize(h);
    if (sz > capacity) {
      entries.clear();
      size = 0;
      return;
    }
    entries.add(h);
    size += sz;
    inserts++;
    _evict();
  }

  HpackHeader? atAbsolute(int abs) {
    final first = inserts - entries.length;
    if (abs < first || abs >= inserts) return null;
    return entries[abs - first];
  }

  void _evict() {
    while (size > capacity && entries.isNotEmpty) {
      size -= _entrySize(entries.removeAt(0));
    }
  }
}

/// RFC 9204 encoder/decoder. Static table always; dynamic table when
/// [maxTableCapacity] > 0. Huffman is the RFC 7541 table.
final class QpackCodec {
  QpackCodec({int maxTableCapacity = qpackDefaultMaxTableCapacity})
    : _maxCapacity = maxTableCapacity {
    if (maxTableCapacity > 0) {
      _local.setCapacity(maxTableCapacity);
    }
  }

  final int _maxCapacity;
  final _DynTable _local = _DynTable();
  final _DynTable _remote = _DynTable();
  final BytesBuilder _encoderOut = BytesBuilder(copy: false);
  final BytesBuilder _decoderOut = BytesBuilder(copy: false);
  var _capacitySent = false;

  int get insertCount => _local.inserts;
  int get remoteInsertCount => _remote.inserts;
  int get maxTableCapacity => _maxCapacity;

  Uint8List takeEncoderStream() {
    if (_maxCapacity > 0 && !_capacitySent) {
      final prefix = BytesBuilder(copy: false);
      _writeInt(prefix, _maxCapacity, 5, qpackEncoderCapacity);
      final rest = _encoderOut.takeBytes();
      _capacitySent = true;
      return concatBytes([prefix.takeBytes(), rest]);
    }
    return _encoderOut.takeBytes();
  }

  Uint8List takeDecoderStream() => _decoderOut.takeBytes();

  /// Encode a field section. Uses static indexed lines, then dynamic if
  /// [useDynamic] and the table has room; otherwise literals.
  Uint8List encodeFieldSection(
    List<HpackHeader> headers, {
    bool huffman = false,
    bool useDynamic = false,
  }) {
    if (useDynamic && _maxCapacity > 0) {
      for (final h in headers) {
        if (_findStatic(h) != null) continue;
        if (_findDynamic(_local, h) != null) continue;
        _insertForEncode(h, huffman: huffman);
      }
    }
    final ric = useDynamic ? _local.inserts : 0;
    final base = ric;
    final b = BytesBuilder(copy: false);
    _writeEncodedRic(b, ric);
    _writeInt(b, 0, 7, 0);
    for (final h in headers) {
      final si = _findStatic(h);
      if (si != null) {
        _writeInt(b, si, 6, qpackIndexedMask | 0x40);
        continue;
      }
      if (useDynamic) {
        final abs = _findDynamic(_local, h);
        if (abs != null) {
          final rel = base - abs - 1;
          _writeInt(b, rel, 6, qpackIndexedMask);
          continue;
        }
        final nameAbs = _findDynamicName(_local, h.name);
        if (nameAbs != null) {
          final rel = base - nameAbs - 1;
          _writeInt(b, rel, 4, qpackLiteralNameRef);
          _writeString(b, h.value, huffman: huffman);
          continue;
        }
      }
      final nameSi = _findStaticName(h.name);
      if (nameSi != null) {
        _writeInt(b, nameSi, 4, qpackLiteralNameRef | 0x10);
        _writeString(b, h.value, huffman: huffman);
        continue;
      }
      final nameBytes = huffman
          ? hpackHuffmanEncode(utf8.encode(h.name))
          : utf8.encode(h.name);
      _writeInt(
        b,
        nameBytes.length,
        3,
        qpackLiteralName | (huffman ? 0x08 : 0),
      );
      b.add(nameBytes);
      _writeString(b, h.value, huffman: huffman);
    }
    return b.takeBytes();
  }

  Result<List<HpackHeader>, PqTransportError> decodeFieldSection(
    Uint8List wire,
  ) {
    if (wire.isEmpty) {
      return Result.failure(PqTransportError.decodeFailure('qpack empty'));
    }
    final ricEnc = _readInt(wire, 0, 8);
    if (ricEnc.isFailure) return Result.failure(ricEnc.errorOrNull!);
    var (encRic, i) = ricEnc.valueOrNull!;
    final ric = _decodeRic(encRic);
    if (ric < 0) {
      return Result.failure(PqTransportError.decodeFailure('qpack ric'));
    }
    if (ric > _remote.inserts) {
      return Result.failure(PqTransportError.decodeFailure('qpack blocked'));
    }
    if (i >= wire.length) {
      return Result.failure(PqTransportError.decodeFailure('qpack base'));
    }
    final sBit = (wire[i] & 0x80) != 0;
    final db = _readInt(wire, i, 7);
    if (db.isFailure) return Result.failure(db.errorOrNull!);
    final (deltaBase, j) = db.valueOrNull!;
    i = j;
    final base = sBit ? ric - deltaBase - 1 : ric + deltaBase;
    if (base < 0) {
      return Result.failure(PqTransportError.decodeFailure('qpack base'));
    }
    final out = <HpackHeader>[];
    while (i < wire.length) {
      final b0 = wire[i];
      if ((b0 & qpackIndexedMask) != 0) {
        final tStatic = (b0 & 0x40) != 0;
        final idx = _readInt(wire, i, 6);
        if (idx.isFailure) return Result.failure(idx.errorOrNull!);
        final (index, ni) = idx.valueOrNull!;
        i = ni;
        final h = tStatic
            ? _staticAt(index)
            : _remote.atAbsolute(base - index - 1);
        if (h == null) {
          return Result.failure(PqTransportError.decodeFailure('qpack idx'));
        }
        out.add(h);
        continue;
      }
      if ((b0 & qpackLiteralNameRefMask) == qpackLiteralNameRef) {
        final tStatic = (b0 & 0x10) != 0;
        final idx = _readInt(wire, i, 4);
        if (idx.isFailure) return Result.failure(idx.errorOrNull!);
        final (index, ni) = idx.valueOrNull!;
        i = ni;
        final nameH = tStatic
            ? _staticAt(index)
            : _remote.atAbsolute(base - index - 1);
        if (nameH == null) {
          return Result.failure(
            PqTransportError.decodeFailure('qpack name ref'),
          );
        }
        final val = _readString(wire, i);
        if (val.isFailure) return Result.failure(val.errorOrNull!);
        final (value, vi) = val.valueOrNull!;
        i = vi;
        out.add(HpackHeader(nameH.name, value));
        continue;
      }
      if ((b0 & qpackLiteralNameMask) == qpackLiteralName) {
        final name = _readPrefixedString(wire, i, 3);
        if (name.isFailure) return Result.failure(name.errorOrNull!);
        final (n, ni) = name.valueOrNull!;
        i = ni;
        final val = _readString(wire, i);
        if (val.isFailure) return Result.failure(val.errorOrNull!);
        final (value, vi) = val.valueOrNull!;
        i = vi;
        out.add(HpackHeader(n, value));
        continue;
      }
      if ((b0 & qpackIndexedPostBaseMask) == qpackIndexedPostBase) {
        final idx = _readInt(wire, i, 4);
        if (idx.isFailure) return Result.failure(idx.errorOrNull!);
        final (index, ni) = idx.valueOrNull!;
        i = ni;
        final h = _remote.atAbsolute(base + index);
        if (h == null) {
          return Result.failure(
            PqTransportError.decodeFailure('qpack post-base'),
          );
        }
        out.add(h);
        continue;
      }
      if ((b0 & qpackLiteralPostBaseMask) == qpackLiteralPostBase) {
        final idx = _readInt(wire, i, 3);
        if (idx.isFailure) return Result.failure(idx.errorOrNull!);
        final (index, ni) = idx.valueOrNull!;
        i = ni;
        final nameH = _remote.atAbsolute(base + index);
        if (nameH == null) {
          return Result.failure(
            PqTransportError.decodeFailure('qpack post-base name'),
          );
        }
        final val = _readString(wire, i);
        if (val.isFailure) return Result.failure(val.errorOrNull!);
        final (value, vi) = val.valueOrNull!;
        i = vi;
        out.add(HpackHeader(nameH.name, value));
        continue;
      }
      return Result.failure(PqTransportError.decodeFailure('qpack line'));
    }
    return Result.success(out);
  }

  Result<void, PqTransportError> ingestEncoderStream(Uint8List wire) {
    var i = 0;
    while (i < wire.length) {
      final b0 = wire[i];
      if ((b0 & qpackEncoderInsertNameRef) != 0) {
        final tStatic = (b0 & 0x40) != 0;
        final idx = _readInt(wire, i, 6);
        if (idx.isFailure) return Result.failure(idx.errorOrNull!);
        final (index, ni) = idx.valueOrNull!;
        i = ni;
        final nameH = tStatic
            ? _staticAt(index)
            : _remote.atAbsolute(_remote.inserts - index - 1);
        if (nameH == null) {
          return Result.failure(
            PqTransportError.decodeFailure('qpack enc name'),
          );
        }
        final val = _readString(wire, i);
        if (val.isFailure) return Result.failure(val.errorOrNull!);
        final (value, vi) = val.valueOrNull!;
        i = vi;
        _remote.insert(HpackHeader(nameH.name, value));
        continue;
      }
      if ((b0 & qpackEncoderInsertLiteralMask) == qpackEncoderInsertLiteral) {
        final name = _readPrefixedString(wire, i, 5);
        if (name.isFailure) return Result.failure(name.errorOrNull!);
        final (n, ni) = name.valueOrNull!;
        i = ni;
        final val = _readString(wire, i);
        if (val.isFailure) return Result.failure(val.errorOrNull!);
        final (value, vi) = val.valueOrNull!;
        i = vi;
        _remote.insert(HpackHeader(n, value));
        continue;
      }
      if ((b0 & qpackEncoderCapacityMask) == qpackEncoderCapacity) {
        final cap = _readInt(wire, i, 5);
        if (cap.isFailure) return Result.failure(cap.errorOrNull!);
        final (c, ni) = cap.valueOrNull!;
        i = ni;
        if (_maxCapacity > 0 && c > _maxCapacity) {
          return Result.failure(
            PqTransportError.decodeFailure('qpack capacity'),
          );
        }
        _remote.setCapacity(c);
        continue;
      }
      final dup = _readInt(wire, i, 5);
      if (dup.isFailure) return Result.failure(dup.errorOrNull!);
      final (index, ni) = dup.valueOrNull!;
      i = ni;
      final src = _remote.atAbsolute(_remote.inserts - index - 1);
      if (src == null) {
        return Result.failure(PqTransportError.decodeFailure('qpack dup'));
      }
      _remote.insert(src);
    }
    return const Result.success(null);
  }

  Result<void, PqTransportError> ingestDecoderStream(Uint8List wire) {
    var i = 0;
    while (i < wire.length) {
      final b0 = wire[i];
      if ((b0 & qpackDecoderSectionAck) != 0) {
        final id = _readInt(wire, i, 7);
        if (id.isFailure) return Result.failure(id.errorOrNull!);
        i = id.valueOrNull!.$2;
        _local.knownReceived = _local.inserts;
        continue;
      }
      if ((b0 & qpackDecoderStreamCancelMask) == qpackDecoderStreamCancel) {
        final id = _readInt(wire, i, 6);
        if (id.isFailure) return Result.failure(id.errorOrNull!);
        i = id.valueOrNull!.$2;
        continue;
      }
      final inc = _readInt(wire, i, 6);
      if (inc.isFailure) return Result.failure(inc.errorOrNull!);
      final (n, ni) = inc.valueOrNull!;
      i = ni;
      _local.knownReceived += n;
    }
    return const Result.success(null);
  }

  void ackSection(int streamId) {
    _writeInt(_decoderOut, streamId, 7, qpackDecoderSectionAck);
  }

  void cancelStream(int streamId) {
    _writeInt(_decoderOut, streamId, 6, qpackDecoderStreamCancel);
  }

  void incrementInsertCount(int n) {
    _writeInt(_decoderOut, n, 6, 0);
  }

  void _insertForEncode(HpackHeader h, {required bool huffman}) {
    final nameSi = _findStaticName(h.name);
    if (nameSi != null) {
      _writeInt(_encoderOut, nameSi, 6, qpackEncoderInsertNameRef | 0x40);
      _writeString(_encoderOut, h.value, huffman: huffman);
      _local.insert(h);
      return;
    }
    final nameAbs = _findDynamicName(_local, h.name);
    if (nameAbs != null) {
      final rel = _local.inserts - nameAbs - 1;
      _writeInt(_encoderOut, rel, 6, qpackEncoderInsertNameRef);
      _writeString(_encoderOut, h.value, huffman: huffman);
      _local.insert(h);
      return;
    }
    final nameBytes = huffman
        ? hpackHuffmanEncode(utf8.encode(h.name))
        : utf8.encode(h.name);
    _writeInt(
      _encoderOut,
      nameBytes.length,
      5,
      qpackEncoderInsertLiteral | (huffman ? 0x20 : 0),
    );
    _encoderOut.add(nameBytes);
    _writeString(_encoderOut, h.value, huffman: huffman);
    _local.insert(h);
  }

  void _writeEncodedRic(BytesBuilder b, int ric) {
    if (ric == 0) {
      _writeInt(b, 0, 8, 0);
      return;
    }
    final maxEntries = _maxCapacity ~/ hpackEntryOverheadBytes;
    if (maxEntries <= 0) {
      _writeInt(b, 0, 8, 0);
      return;
    }
    _writeInt(b, (ric % (2 * maxEntries)) + 1, 8, 0);
  }

  int _decodeRic(int enc) {
    if (enc == 0) return 0;
    final maxEntries = _remote.capacity ~/ hpackEntryOverheadBytes;
    if (maxEntries <= 0) return -1;
    final fullRange = 2 * maxEntries;
    if (enc > fullRange) return -1;
    final maxValue = _remote.inserts + maxEntries;
    final maxWrapped = (maxValue ~/ fullRange) * fullRange;
    var ric = maxWrapped + enc - 1;
    if (ric > maxValue) {
      if (ric <= maxValue + fullRange) {
        ric -= fullRange;
      } else {
        return -1;
      }
    }
    return ric;
  }

  static int? _findStatic(HpackHeader h) {
    for (var i = 0; i < qpackStaticTable.length; i++) {
      final e = qpackStaticTable[i];
      if (e.name == h.name && e.value == h.value) return i;
    }
    return null;
  }

  static int? _findStaticName(String name) {
    for (var i = 0; i < qpackStaticTable.length; i++) {
      if (qpackStaticTable[i].name == name) return i;
    }
    return null;
  }

  static int? _findDynamic(_DynTable t, HpackHeader h) {
    final first = t.inserts - t.entries.length;
    for (var i = 0; i < t.entries.length; i++) {
      final e = t.entries[i];
      if (e.name == h.name && e.value == h.value) return first + i;
    }
    return null;
  }

  static int? _findDynamicName(_DynTable t, String name) {
    final first = t.inserts - t.entries.length;
    for (var i = 0; i < t.entries.length; i++) {
      if (t.entries[i].name == name) return first + i;
    }
    return null;
  }

  static HpackHeader? _staticAt(int index) {
    if (index < 0 || index >= qpackStaticTable.length) return null;
    return qpackStaticTable[index];
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
      return Result.failure(PqTransportError.decodeFailure('qpack int'));
    }
    final max = (1 << prefixBits) - 1;
    final first = buf[offset] & max;
    var i = offset + 1;
    if (first < max) return Result.success((first, i));
    var value = first;
    var shift = 0;
    while (true) {
      if (i >= buf.length) {
        return Result.failure(PqTransportError.decodeFailure('qpack int'));
      }
      if (shift > hpackMaxIntegerShift) {
        return Result.failure(
          PqTransportError.decodeFailure('qpack int overflow'),
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
    return _readPrefixedString(buf, offset, 7);
  }

  static Result<(String, int), PqTransportError> _readPrefixedString(
    Uint8List buf,
    int offset,
    int prefixBits,
  ) {
    if (offset >= buf.length) {
      return Result.failure(PqTransportError.decodeFailure('qpack str'));
    }
    final huffman = (buf[offset] & (1 << prefixBits)) != 0;
    final n = _readInt(buf, offset, prefixBits);
    if (n.isFailure) return Result.failure(n.errorOrNull!);
    final (len, i) = n.valueOrNull!;
    if (len < 0 || i + len > buf.length) {
      return Result.failure(PqTransportError.decodeFailure('qpack str len'));
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
      return Result.failure(PqTransportError.decodeFailure('qpack utf8'));
    }
  }
}
