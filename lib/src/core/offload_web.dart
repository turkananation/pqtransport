import 'dart:typed_data';

import 'package:pqforge/pqforge.dart';

import 'lengths.dart';

/// Web path. No isolate exists here, so the call runs on this turn.
Future<({Uint8List publicKey, Uint8List secretKey})> offloadKemKeyGen(
  PqKemAlgorithm algorithm, {
  Uint8List? seed,
}) async {
  final kp = PqKemPrimitives.generateKeyPair(algorithm, seed: seed);
  return (publicKey: kp.publicKey, secretKey: kp.secretKey);
}

Future<({Uint8List sharedSecret, Uint8List ciphertext})> offloadKemEncapsulate(
  PqKemAlgorithm algorithm,
  Uint8List publicKey,
) async {
  final enc = PqKemPrimitives.encapsulate(algorithm, publicKey);
  return (sharedSecret: enc.sharedSecret, ciphertext: enc.ciphertext);
}

Future<Uint8List> offloadKemDecapsulate(
  PqKemAlgorithm algorithm,
  Uint8List secretKey,
  Uint8List ciphertext,
) async {
  return PqKemPrimitives.decapsulate(algorithm, secretKey, ciphertext);
}

Future<Uint8List> offloadMlDsaSign({
  required PqSignatureAlgorithm algorithm,
  required Uint8List secretKey,
  required Uint8List message,
  Uint8List? context,
}) async {
  return PqSignaturePrimitives.sign(
    algorithm,
    secretKey,
    message,
    context: context,
  );
}

Future<bool> offloadMlDsaVerify({
  required Uint8List publicKey,
  required Uint8List message,
  required Uint8List signatureBytes,
  Uint8List? context,
}) async {
  final algorithm = switch ((publicKey.length, signatureBytes.length)) {
    (mlDsa65PublicKeyBytes, mlDsa65SignatureBytes) =>
      PqSignatureAlgorithm.mlDsa65,
    (mlDsa87PublicKeyBytes, mlDsa87SignatureBytes) =>
      PqSignatureAlgorithm.mlDsa87,
    _ => null,
  };
  if (algorithm == null) return false;
  return PqSignaturePrimitives.verify(
    algorithm,
    publicKey,
    message,
    signatureBytes,
    context: context,
  );
}
