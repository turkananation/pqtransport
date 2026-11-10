import 'dart:typed_data';

import '../core/bytes.dart';
import '../quic/packet.dart';

/// RFC 9297 §3.2. One capsule. Unknown types are skipped by the
/// receiver. They are not a connection error.
final class HttpCapsule {
  const HttpCapsule({required this.type, required this.value});

  /// RFC 9297 §3.5. The value is one HTTP datagram payload.
  static const int datagram = 0x00;

  final int type;
  final Uint8List value;

  Uint8List encode() {
    final b = BytesBuilder(copy: false);
    writeQuicVarint(b, type);
    writeQuicVarint(b, value.length);
    b.add(value);
    return b.takeBytes();
  }
}

/// One complete capsule, or null when [wire] is a short but legal prefix.
({HttpCapsule capsule, int consumed})? tryDecodeHttpCapsule(Uint8List wire) {
  final reader = ByteReader(wire);
  final type = readVarint(reader);
  if (type < 0) return null;
  final length = readVarint(reader);
  if (length < 0) return null;
  if (reader.remaining < length) return null;
  final value = slice(wire, reader.offset, reader.offset + length);
  return (
    capsule: HttpCapsule(type: type, value: value),
    consumed: reader.offset + length,
  );
}
