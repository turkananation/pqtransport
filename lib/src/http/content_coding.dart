import 'dart:typed_data';

import 'package:swissarmyknife/swissarmyknife.dart';

import '../core/errors.dart';
import 'content_coding_codec.dart';

export 'content_coding_codec.dart';

/// RFC 9110 content coding this stack can apply. `deflate` is the
/// zlib wrapper (RFC 1950), not raw DEFLATE. `gzip` is RFC 1952.
/// The order and q-values of [header] decide. Unknown codings are
/// skipped. A q of 0 is a refusal.
String? selectContentCoding(String header) {
  String? best;
  var bestQ = -1.0;
  var bestAt = 1 << 30;
  final parts = header.split(',');
  for (var i = 0; i < parts.length; i++) {
    final bits = parts[i].split(';');
    final name = bits.first.trim().toLowerCase();
    if (name != 'deflate' && name != 'gzip') continue;
    var q = 1.0;
    for (final param in bits.skip(1)) {
      final text = param.trim().toLowerCase();
      if (!text.startsWith('q=')) continue;
      q = double.tryParse(text.substring(2)) ?? 0;
    }
    if (q <= 0) continue;
    if (q > bestQ || (q == bestQ && i < bestAt)) {
      best = name;
      bestQ = q;
      bestAt = i;
    }
  }
  return best;
}

/// One content coding, applied to a message body. A comma-separated
/// list is a failure: the peer would have to be decoded in order and
/// this stack accepts one.
Result<Uint8List, PqTransportError> decodeContentCodingHeader(
  String header,
  Uint8List body,
) {
  final name = header.trim().toLowerCase();
  if (name.contains(',')) {
    return Result.failure(PqTransportError.decodeFailure('content-encoding'));
  }
  return decodeContentCoding(name, body);
}
