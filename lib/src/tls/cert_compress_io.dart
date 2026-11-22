import 'dart:io';
import 'dart:typed_data';

/// RFC 8879 algorithm `zlib` is the RFC 1950 wrapper. `dart:io`, not FFI.
bool get zlibCertificateCompression => true;

Uint8List? zlibWrapCertificate(Uint8List input) =>
    Uint8List.fromList(zlib.encode(input));

Uint8List? zlibUnwrapCertificate(Uint8List input) {
  try {
    return Uint8List.fromList(zlib.decode(input));
  } on FormatException {
    return null;
  } on Exception {
    return null;
  }
}
