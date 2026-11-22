import 'dart:typed_data';

/// This compilation has no zlib. Certificate compression stays off.
bool get zlibCertificateCompression => false;

Uint8List? zlibWrapCertificate(Uint8List input) => null;

Uint8List? zlibUnwrapCertificate(Uint8List input) => null;
