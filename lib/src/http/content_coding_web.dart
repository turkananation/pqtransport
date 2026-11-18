import 'dart:typed_data';

import 'package:swissarmyknife/swissarmyknife.dart';

import '../core/errors.dart';

/// This compilation has no zlib. A compressed body fails closed.
Result<Uint8List, PqTransportError> decodeContentCoding(
  String coding,
  Uint8List body,
) {
  return Result.failure(PqTransportError.unsupported('content-encoding'));
}

Result<Uint8List, PqTransportError> encodeContentCoding(
  String coding,
  Uint8List body,
) {
  return Result.failure(PqTransportError.unsupported('content-encoding'));
}
