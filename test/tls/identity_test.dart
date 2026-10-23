import 'dart:typed_data';

import 'package:pqtransport/pqtransport.dart';
import 'package:test/test.dart';

void main() {
  test('ML-DSA-65 PEM round-trips and the private key matches', () {
    final crypto = PqTransportCrypto();
    final identity = PqTlsServerIdentity.generate(crypto);
    final loaded = PqTlsServerIdentity.parsePem(
      identity.publicKeyPem,
      identity.privateKeyPem,
    );
    expect(loaded.isSuccess, isTrue, reason: '${loaded.errorOrNull}');
    expect(loaded.valueOrNull!.publicKey, identity.publicKey);
    expect(loaded.valueOrNull!.secretKey, identity.secretKey);
    final message = Uint8List.fromList([1, 2, 3]);
    final sig = crypto.mlDsaSign(
      secretKey: loaded.valueOrNull!.secretKey,
      message: message,
    );
    expect(
      crypto.mlDsaVerify(
        publicKey: identity.publicKey,
        message: message,
        signatureBytes: sig,
      ),
      isTrue,
    );
  });

  test('encrypted PEM and a mismatched raw key are refused', () {
    final crypto = PqTransportCrypto();
    final identity = PqTlsServerIdentity.generate(crypto);
    final encrypted = PqTlsServerIdentity.parsePem(
      identity.publicKeyPem,
      '-----BEGIN ENCRYPTED PRIVATE KEY-----\nAAAA\n'
      '-----END ENCRYPTED PRIVATE KEY-----\n',
    );
    expect(encrypted.isFailure, isTrue);
    final other = PqTlsServerIdentity.generate(crypto);
    final mismatch = PqTlsServerIdentity.parse(
      identity.publicKey,
      other.secretKey,
    );
    expect(mismatch.isFailure, isTrue);
  });
}
