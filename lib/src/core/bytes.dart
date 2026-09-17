import 'dart:typed_data';

import 'package:swissarmyknife/swissarmyknife.dart';

import 'errors.dart';

/// Length-filter before any deserialize-to-crypto.
Result<Uint8List, PqTransportError> requireLength(
  Uint8List bytes,
  int expected,
  PqLengthLabel label,
) {
  if (bytes.length != expected) {
    return Result.failure(
      PqTransportError.illegalParameter(label, bytes.length, expected),
    );
  }
  return Result.success(bytes);
}

Result<Uint8List, PqTransportError> requireMinLength(
  Uint8List bytes,
  int minimum,
  PqLengthLabel label,
) {
  if (bytes.length < minimum) {
    return Result.failure(
      PqTransportError.illegalParameter(label, bytes.length, minimum),
    );
  }
  return Result.success(bytes);
}

bool isAllZeros(Uint8List bytes) {
  var acc = 0;
  for (final b in bytes) {
    acc |= b;
  }
  return acc == 0;
}

Uint8List concatBytes(List<Uint8List> parts) {
  var total = 0;
  for (final p in parts) {
    total += p.length;
  }
  final out = Uint8List(total);
  var offset = 0;
  for (final p in parts) {
    out.setRange(offset, offset + p.length, p);
    offset += p.length;
  }
  return out;
}

Uint8List slice(Uint8List src, int start, int end) =>
    Uint8List.fromList(src.sublist(start, end));

void writeUint16(BytesBuilder builder, int value) {
  builder.addByte((value >> 8) & 0xff);
  builder.addByte(value & 0xff);
}

void writeUint24(BytesBuilder builder, int value) {
  builder.addByte((value >> 16) & 0xff);
  builder.addByte((value >> 8) & 0xff);
  builder.addByte(value & 0xff);
}

void writeUint32(BytesBuilder builder, int value) {
  builder.addByte((value >> 24) & 0xff);
  builder.addByte((value >> 16) & 0xff);
  builder.addByte((value >> 8) & 0xff);
  builder.addByte(value & 0xff);
}

void writeUint64(BytesBuilder builder, int value) {
  writeUint32(builder, (value >> 32) & 0xffffffff);
  writeUint32(builder, value & 0xffffffff);
}

int readUint16(Uint8List bytes, int offset) =>
    ((bytes[offset] << 8) | bytes[offset + 1]) & 0xffff;

int readUint24(Uint8List bytes, int offset) =>
    ((bytes[offset] << 16) | (bytes[offset + 1] << 8) | bytes[offset + 2]) &
    0xffffff;

int readUint32(Uint8List bytes, int offset) =>
    ((bytes[offset] << 24) |
        (bytes[offset + 1] << 16) |
        (bytes[offset + 2] << 8) |
        bytes[offset + 3]) &
    0xffffffff;

int readUint64(Uint8List bytes, int offset) {
  final hi = readUint32(bytes, offset);
  final lo = readUint32(bytes, offset + 4);
  return (hi << 32) | lo;
}

/// Cursor over a buffer for Result-typed codecs.
final class ByteReader {
  ByteReader(this.bytes);

  final Uint8List bytes;
  int offset = 0;

  int get remaining => bytes.length - offset;

  bool get isDone => remaining == 0;

  Result<Uint8List, PqTransportError> take(int n, PqLengthLabel label) {
    if (n < 0 || remaining < n) {
      return Result.failure(
        PqTransportError.decodeFailure(
          '${label.name}: need $n bytes, have $remaining',
        ),
      );
    }
    final out = slice(bytes, offset, offset + n);
    offset += n;
    return Result.success(out);
  }

  Result<int, PqTransportError> u8() {
    if (remaining < 1) {
      return Result.failure(PqTransportError.decodeFailure('truncated u8'));
    }
    return Result.success(bytes[offset++]);
  }

  Result<int, PqTransportError> u16() {
    if (remaining < 2) {
      return Result.failure(PqTransportError.decodeFailure('truncated u16'));
    }
    final v = readUint16(bytes, offset);
    offset += 2;
    return Result.success(v);
  }

  Result<int, PqTransportError> u24() {
    if (remaining < 3) {
      return Result.failure(PqTransportError.decodeFailure('truncated u24'));
    }
    final v = readUint24(bytes, offset);
    offset += 3;
    return Result.success(v);
  }

  Result<int, PqTransportError> u32() {
    if (remaining < 4) {
      return Result.failure(PqTransportError.decodeFailure('truncated u32'));
    }
    final v = readUint32(bytes, offset);
    offset += 4;
    return Result.success(v);
  }

  Result<int, PqTransportError> u64() {
    if (remaining < 8) {
      return Result.failure(PqTransportError.decodeFailure('truncated u64'));
    }
    final v = readUint64(bytes, offset);
    offset += 8;
    return Result.success(v);
  }
}
