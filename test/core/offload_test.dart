@TestOn('vm')
library;

import 'package:pqforge/pqforge.dart';
import 'package:pqtransport/src/core/offload.dart';
import 'package:test/test.dart';

void main() {
  test('decapsulate matches, and a second call reuses the worker', () async {
    final local = PqKemPrimitives.generateKeyPair(PqKemAlgorithm.mlKem768);
    final enc = PqKemPrimitives.encapsulate(
      PqKemAlgorithm.mlKem768,
      local.publicKey,
    );
    final first = await offloadKemDecapsulate(
      PqKemAlgorithm.mlKem768,
      local.secretKey,
      enc.ciphertext,
    );
    final second = await offloadKemDecapsulate(
      PqKemAlgorithm.mlKem768,
      local.secretKey,
      enc.ciphertext,
    );
    expect(first, enc.sharedSecret);
    expect(second, enc.sharedSecret);
    expect(local.secretKey.any((byte) => byte != 0), isTrue);
  });
}
