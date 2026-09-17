import 'dart:typed_data';

import 'package:pqforge/pqforge.dart';

import 'bytes.dart';
import 'lengths.dart';

/// Running handshake transcript. [snapshot] is SHA-256 of [bytes].
final class Transcript {
  Transcript();

  final BytesBuilder _buf = BytesBuilder(copy: false);

  void add(Uint8List message) => _buf.add(message);

  Uint8List get bytes => Uint8List.fromList(_buf.toBytes());

  Uint8List snapshot() => PqBytes.sha256(bytes);

  int get length => _buf.length;

  void clear() => _buf.clear();
}

Uint8List hashTranscript(List<Uint8List> messages) {
  return PqBytes.sha256(concatBytes(messages));
}

Uint8List udpSessionInfo(String roleContext) {
  return PqBytes.utf8Bytes('$udpSessionInfoPrefix|$roleContext');
}
