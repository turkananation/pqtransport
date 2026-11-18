import 'dart:io';
import 'dart:typed_data';

import 'package:swissarmyknife/swissarmyknife.dart';

import '../core/errors.dart';

/// zlib wrapper for `deflate`, gzip wrapper for `gzip`. Both are
/// `dart:io`. There is no `dart:ffi`.
Result<Uint8List, PqTransportError> decodeContentCoding(
  String coding,
  Uint8List body,
) {
  try {
    return Result.success(switch (coding) {
      'deflate' => Uint8List.fromList(zlib.decode(body)),
      'gzip' => Uint8List.fromList(gzip.decode(body)),
      _ => throw FormatException(coding),
    });
  } on FormatException {
    return Result.failure(PqTransportError.decodeFailure('content-encoding'));
  } on Object {
    return Result.failure(PqTransportError.decodeFailure('content-encoding'));
  }
}

Result<Uint8List, PqTransportError> encodeContentCoding(
  String coding,
  Uint8List body,
) {
  try {
    return Result.success(switch (coding) {
      'deflate' => Uint8List.fromList(zlib.encode(body)),
      'gzip' => Uint8List.fromList(gzip.encode(body)),
      _ => throw FormatException(coding),
    });
  } on FormatException {
    return Result.failure(PqTransportError.decodeFailure('content-encoding'));
  }
}
