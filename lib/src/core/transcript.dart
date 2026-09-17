import 'dart:typed_data';

import 'package:pqforge/pqforge.dart';

import 'bytes.dart';
import 'lengths.dart';

/// Transcript hash. TLS `0x1302` is SHA-384; `0x1303` is SHA-256.
enum TranscriptHashKind { sha256, sha384 }

/// Running handshake transcript. [snapshot] is Hash of [bytes].
final class Transcript {
  Transcript({this.hashKind = TranscriptHashKind.sha384});

  TranscriptHashKind hashKind;
  final BytesBuilder _buf = BytesBuilder(copy: false);

  void add(Uint8List message) => _buf.add(message);

  Uint8List get bytes => Uint8List.fromList(_buf.toBytes());

  Uint8List snapshot() => switch (hashKind) {
    TranscriptHashKind.sha256 => PqBytes.sha256(bytes),
    TranscriptHashKind.sha384 => PqBytes.sha384(bytes),
  };

  int get length => _buf.length;

  void clear() => _buf.clear();
}

Uint8List hashTranscript(
  List<Uint8List> messages, {
  TranscriptHashKind hashKind = TranscriptHashKind.sha384,
}) {
  final data = concatBytes(messages);
  return switch (hashKind) {
    TranscriptHashKind.sha256 => PqBytes.sha256(data),
    TranscriptHashKind.sha384 => PqBytes.sha384(data),
  };
}

Uint8List udpSessionInfo(String roleContext) {
  return PqBytes.utf8Bytes('$udpSessionInfoPrefix|$roleContext');
}
