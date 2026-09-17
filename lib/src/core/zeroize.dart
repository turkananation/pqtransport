import 'dart:typed_data';

/// Best-effort overwrite of a buffer that held secret material.
///
/// Dart cannot guarantee the GC will not have copied the bytes, and compiled
/// backends may elide the stores. Do not describe this as hard memory erasure.
void zeroize(Uint8List? bytes) {
  if (bytes == null || bytes.isEmpty) {
    return;
  }
  bytes.fillRange(0, bytes.length, 0);
}

/// Runs [body] and best-effort wipes [secrets] afterwards.
T withSecrets<T>(List<Uint8List> secrets, T Function() body) {
  try {
    return body();
  } finally {
    for (final s in secrets) {
      zeroize(s);
    }
  }
}
