import 'dart:convert';
import 'dart:typed_data';

import '../core/bytes.dart';
import '../core/crypto.dart';
import '../core/lengths.dart';
import '../core/zeroize.dart';
import 'cipher_suite.dart';

/// RFC 8446 key schedule. Hash and AEAD follow [suite].
///
/// Default is IANA `TLS_AES_256_GCM_SHA384` (`0x1302`): HKDF-SHA-384, 48-byte
/// Hash, 32-byte AES-256-GCM keys. `0x1303` switches Hash to SHA-256 and AEAD
/// to ChaCha20-Poly1305. Expand-Label stays in this file.
final class TlsKeySchedule {
  TlsKeySchedule(this.crypto, {this.suite = TlsCipherSuite.aes256GcmSha384});

  final PqTransportCrypto crypto;
  TlsCipherSuite suite;

  int get hashLen => suite.hashBytes;

  TransportAead get aead => suite.usesChaCha
      ? TransportAead.chacha20Poly1305
      : TransportAead.aes256Gcm;

  late final Uint8List clientHandshakeTraffic;
  late final Uint8List serverHandshakeTraffic;
  late Uint8List clientApplicationTraffic;
  late Uint8List serverApplicationTraffic;
  late Uint8List exporterMaster;
  late final Uint8List clientHandshakeIv;
  late final Uint8List serverHandshakeIv;
  late Uint8List clientApplicationIv;
  late Uint8List serverApplicationIv;
  late final Uint8List clientFinishedKey;
  late final Uint8List serverFinishedKey;

  Uint8List _extract(Uint8List salt, Uint8List ikm) => suite.usesSha384
      ? crypto.hkdfExtractSha384(salt, ikm)
      : crypto.hkdfExtract(salt, ikm);

  Uint8List _expand(Uint8List prk, Uint8List info, int length) =>
      suite.usesSha384
      ? crypto.hkdfExpandSha384(prk, info, length)
      : crypto.hkdfExpand(prk, info, length);

  Uint8List transcriptHash(Uint8List data) =>
      suite.usesSha384 ? crypto.sha384(data) : crypto.sha256(data);

  Uint8List finishedMac(Uint8List finishedKey, Uint8List transcriptHashBytes) =>
      suite.usesSha384
      ? crypto.hmacSha384(finishedKey, transcriptHashBytes)
      : crypto.hmac(finishedKey, transcriptHashBytes);

  void derive({
    required Uint8List hybridSharedSecret,
    required Uint8List handshakeTranscriptHash,
    required Uint8List applicationTranscriptHash,
  }) {
    final zeros = Uint8List(hashLen);
    final early = _extract(zeros, zeros);
    final derivedEarly = deriveSecret(early, tlsLabelDerived, zeros);
    final handshake = _extract(derivedEarly, hybridSharedSecret);
    clientHandshakeTraffic = deriveSecret(
      handshake,
      tlsLabelCHsTraffic,
      handshakeTranscriptHash,
    );
    serverHandshakeTraffic = deriveSecret(
      handshake,
      tlsLabelSHsTraffic,
      handshakeTranscriptHash,
    );
    final derivedHs = deriveSecret(handshake, tlsLabelDerived, zeros);
    final master = _extract(derivedHs, zeros);
    clientApplicationTraffic = deriveSecret(
      master,
      tlsLabelCApTraffic,
      applicationTranscriptHash,
    );
    serverApplicationTraffic = deriveSecret(
      master,
      tlsLabelSApTraffic,
      applicationTranscriptHash,
    );
    exporterMaster = deriveSecret(
      master,
      tlsLabelExpMaster,
      applicationTranscriptHash,
    );
    clientHandshakeIv = expandLabel(
      clientHandshakeTraffic,
      tlsLabelIv,
      Uint8List(0),
      aeadNonceBytes,
    );
    serverHandshakeIv = expandLabel(
      serverHandshakeTraffic,
      tlsLabelIv,
      Uint8List(0),
      aeadNonceBytes,
    );
    clientApplicationIv = expandLabel(
      clientApplicationTraffic,
      tlsLabelIv,
      Uint8List(0),
      aeadNonceBytes,
    );
    serverApplicationIv = expandLabel(
      serverApplicationTraffic,
      tlsLabelIv,
      Uint8List(0),
      aeadNonceBytes,
    );
    clientFinishedKey = deriveSecret(
      clientHandshakeTraffic,
      tlsLabelFinished,
      Uint8List(0),
    );
    serverFinishedKey = deriveSecret(
      serverHandshakeTraffic,
      tlsLabelFinished,
      Uint8List(0),
    );
    zeroize(early);
    zeroize(derivedEarly);
    zeroize(handshake);
    zeroize(derivedHs);
    zeroize(master);
  }

  void deriveHandshake({
    required Uint8List hybridSharedSecret,
    required Uint8List handshakeTranscriptHash,
  }) {
    derive(
      hybridSharedSecret: hybridSharedSecret,
      handshakeTranscriptHash: handshakeTranscriptHash,
      applicationTranscriptHash: handshakeTranscriptHash,
    );
  }

  void deriveApplication({
    required Uint8List hybridSharedSecret,
    required Uint8List applicationTranscriptHash,
  }) {
    final zeros = Uint8List(hashLen);
    final early = _extract(zeros, zeros);
    final derivedEarly = deriveSecret(early, tlsLabelDerived, zeros);
    final handshake = _extract(derivedEarly, hybridSharedSecret);
    final derivedHs = deriveSecret(handshake, tlsLabelDerived, zeros);
    final master = _extract(derivedHs, zeros);
    clientApplicationTraffic = deriveSecret(
      master,
      tlsLabelCApTraffic,
      applicationTranscriptHash,
    );
    serverApplicationTraffic = deriveSecret(
      master,
      tlsLabelSApTraffic,
      applicationTranscriptHash,
    );
    exporterMaster = deriveSecret(
      master,
      tlsLabelExpMaster,
      applicationTranscriptHash,
    );
    clientApplicationIv = expandLabel(
      clientApplicationTraffic,
      tlsLabelIv,
      Uint8List(0),
      aeadNonceBytes,
    );
    serverApplicationIv = expandLabel(
      serverApplicationTraffic,
      tlsLabelIv,
      Uint8List(0),
      aeadNonceBytes,
    );
    zeroize(early);
    zeroize(derivedEarly);
    zeroize(handshake);
    zeroize(derivedHs);
    zeroize(master);
  }

  Uint8List deriveSecret(Uint8List secret, String label, Uint8List context) {
    return expandLabel(secret, label, context, hashLen);
  }

  Uint8List expandLabel(
    Uint8List secret,
    String label,
    Uint8List context,
    int length,
  ) {
    final labelBytes = utf8.encode('$tlsHkdfLabelPrefix$label');
    final b = BytesBuilder(copy: false);
    writeUint16(b, length);
    b.addByte(labelBytes.length);
    b.add(labelBytes);
    b.addByte(context.length);
    b.add(context);
    return _expand(secret, b.takeBytes(), length);
  }

  Uint8List exporter(String label, Uint8List context, int length) {
    final derived = expandLabel(
      exporterMaster,
      label,
      transcriptHash(context),
      hashLen,
    );
    return expandLabel(derived, tlsLabelExporter, context, length);
  }

  Uint8List nonce(Uint8List iv, int sequence) {
    final n = Uint8List.fromList(iv);
    for (var i = 0; i < 8; i++) {
      n[n.length - 1 - i] ^= (sequence >> (8 * i)) & 0xff;
    }
    return n;
  }

  Uint8List trafficKey(Uint8List trafficSecret) =>
      expandLabel(trafficSecret, tlsLabelKey, Uint8List(0), aeadKeyBytes);
}
