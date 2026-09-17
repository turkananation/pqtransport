import 'dart:convert';
import 'dart:typed_data';

import 'package:swissarmyknife/swissarmyknife.dart';

import '../core/crypto.dart';
import '../core/errors.dart';
import '../core/lengths.dart';
import '../dns/records.dart';

const String pqsigTxtKey = 'pqsig';
const String pqpkTxtKey = 'pqpk';

/// Split a buffer into 255-byte TXT strings. Never truncates.
List<String> splitTxt(Uint8List bytes) {
  final out = <String>[];
  for (var i = 0; i < bytes.length; i += 255) {
    final end = i + 255 > bytes.length ? bytes.length : i + 255;
    out.add(base64Encode(bytes.sublist(i, end)));
  }
  return out;
}

Uint8List joinTxt(List<String> parts) {
  final b = BytesBuilder(copy: false);
  for (final p in parts) {
    b.add(base64Decode(p));
  }
  return b.takeBytes();
}

Result<DnsTxt, PqTransportError> signTxt({
  required PqTransportCrypto crypto,
  required Uint8List secretKey,
  required String name,
  required List<String> body,
}) {
  final payload = Uint8List.fromList(utf8.encode(body.join('\n')));
  final sig = crypto.mlDsaSign(secretKey: secretKey, message: payload);
  if (sig.length != mlDsa65SignatureBytes &&
      sig.length != crypto.signature.signatureBytes) {
    return Result.failure(
      PqTransportError.illegalParameter(
        PqLengthLabel.mlDsa65Signature,
        sig.length,
        crypto.signature.signatureBytes,
      ),
    );
  }
  final strings = [...body, '$pqsigTxtKey=${splitTxt(sig).join('')}'];
  return Result.success(DnsTxt(name: name, strings: strings));
}

Result<void, PqTransportError> verifyTxt({
  required PqTransportCrypto crypto,
  required Uint8List publicKey,
  required DnsTxt txt,
}) {
  String? sigField;
  final body = <String>[];
  for (final s in txt.strings) {
    if (s.startsWith('$pqsigTxtKey=')) {
      sigField = s.substring(pqsigTxtKey.length + 1);
    } else {
      body.add(s);
    }
  }
  if (sigField == null) {
    return Result.failure(PqTransportError.decodeFailure('missing pqsig'));
  }
  final sig = base64Decode(sigField);
  final payload = Uint8List.fromList(utf8.encode(body.join('\n')));
  final ok = crypto.mlDsaVerify(
    publicKey: publicKey,
    message: payload,
    signatureBytes: sig,
  );
  if (!ok) {
    return Result.failure(PqTransportError.decryptError('mdns ml-dsa'));
  }
  return const Result.success(null);
}
