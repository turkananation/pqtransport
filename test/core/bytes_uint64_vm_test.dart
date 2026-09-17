@TestOn('vm')
library;

import 'dart:typed_data';

import 'package:pqtransport/pqtransport.dart';
import 'package:test/test.dart';

void main() {
  test('uint64 round trip above 2^53', () {
    final b = BytesBuilder(copy: false);
    writeUint64(b, 0x0102030405060708);
    expect(readUint64(b.takeBytes(), 0), 0x0102030405060708);
  });
}
