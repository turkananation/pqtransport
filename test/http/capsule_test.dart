import 'dart:typed_data';

import 'package:pqtransport/pqtransport.dart';
import 'package:test/test.dart';

void main() {
  test('RFC 9297 DATAGRAM capsule, unknown type, short prefix', () {
    final wire = concatBytes([
      HttpCapsule(
        type: HttpCapsule.datagram,
        value: Uint8List.fromList([9, 8, 7]),
      ).encode(),
      HttpCapsule(type: 0x17, value: Uint8List.fromList([1])).encode(),
    ]);
    final first = tryDecodeHttpCapsule(wire);
    expect(first, isNotNull);
    expect(first!.capsule.type, HttpCapsule.datagram);
    expect(first.capsule.value, [9, 8, 7]);
    final rest = slice(wire, first.consumed, wire.length);
    final second = tryDecodeHttpCapsule(rest);
    expect(second, isNotNull);
    expect(second!.capsule.type, 0x17);
    expect(second.capsule.value, [1]);
    expect(tryDecodeHttpCapsule(Uint8List.fromList([0x00])), isNull);
    expect(second.consumed, rest.length);
  });
}
