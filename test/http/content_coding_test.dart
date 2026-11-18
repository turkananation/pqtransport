@TestOn('vm')
library;

import 'dart:io';
import 'dart:typed_data';

import 'package:pqtransport/src/http/content_coding.dart';
import 'package:test/test.dart';

void main() {
  test('q-values pick deflate ahead of gzip when deflate is preferred', () {
    expect(selectContentCoding('gzip;q=0.5, deflate;q=1.0, br'), 'deflate');
    expect(selectContentCoding('gzip, deflate;q=0'), 'gzip');
    expect(selectContentCoding('br, zstd'), isNull);
  });

  test('deflate is the zlib wrapper, not raw DEFLATE', () {
    final clear = Uint8List.fromList('pq-deflate'.codeUnits);
    final wire = zlib.encode(clear);
    expect(wire[0], 0x78);
    final back = decodeContentCoding('deflate', Uint8List.fromList(wire));
    expect(back.isSuccess, isTrue);
    expect(back.valueOrNull, clear);
    final again = encodeContentCoding('deflate', clear);
    expect(
      decodeContentCoding('deflate', again.valueOrNull!).valueOrNull,
      clear,
    );
  });
}
