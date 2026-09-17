import '../core/lengths.dart';

/// IANA TLS 1.3 cipher suites this package will put on the wire.
///
/// Hash and AEAD are bound together. [aes256GcmSha384] is SHA-384 + AES-256-GCM
/// (`0x1302`). [chacha20Poly1305Sha256] is SHA-256 + ChaCha20-Poly1305
/// (`0x1303`). Private-use `0xFF00` is retired.
enum TlsCipherSuite {
  aes256GcmSha384,
  chacha20Poly1305Sha256;

  int get codepoint => switch (this) {
    TlsCipherSuite.aes256GcmSha384 => tlsCipherAes256GcmSha384,
    TlsCipherSuite.chacha20Poly1305Sha256 => tlsCipherChaCha20Poly1305Sha256,
  };

  int get hashBytes => switch (this) {
    TlsCipherSuite.aes256GcmSha384 => sha384HashBytes,
    TlsCipherSuite.chacha20Poly1305Sha256 => sha256HashBytes,
  };

  bool get usesSha384 => this == TlsCipherSuite.aes256GcmSha384;

  bool get usesChaCha => this == TlsCipherSuite.chacha20Poly1305Sha256;

  static TlsCipherSuite? byCodepoint(int codepoint) {
    for (final s in TlsCipherSuite.values) {
      if (s.codepoint == codepoint) return s;
    }
    return null;
  }

  /// Server preference: IANA `0x1302` first, then `0x1303`.
  /// [chachaOk] is false on dart2js (PointyCastle Poly1305 needs 64-bit ints).
  static TlsCipherSuite? select(List<int> offered, {bool chachaOk = true}) {
    if (offered.contains(tlsCipherAes256GcmSha384)) {
      return TlsCipherSuite.aes256GcmSha384;
    }
    if (chachaOk && offered.contains(tlsCipherChaCha20Poly1305Sha256)) {
      return TlsCipherSuite.chacha20Poly1305Sha256;
    }
    return null;
  }
}

const List<int> tlsDefaultOfferedCipherSuites = [
  tlsCipherAes256GcmSha384,
  tlsCipherChaCha20Poly1305Sha256,
];

/// Suites this runtime can complete. dart2js drops `0x1303`.
List<int> tlsOfferedCipherSuitesForRuntime({required bool chachaOk}) =>
    chachaOk ? tlsDefaultOfferedCipherSuites : const [tlsCipherAes256GcmSha384];
