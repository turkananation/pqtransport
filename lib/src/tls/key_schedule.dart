import 'dart:convert';
import 'dart:typed_data';

import '../core/bytes.dart';
import '../core/crypto.dart';
import '../core/lengths.dart';
import '../core/zeroize.dart';

/// RFC 8446 key schedule over HKDF-SHA-256 (pqforge HMAC).
///
/// Traffic keys are 32-byte AES-256-GCM keys. TLS_AES_256_GCM_SHA384 is not
/// offered: pqforge does not export HKDF-SHA-384. Cipher on the wire is
/// AES-256-GCM with SHA-256 schedule (documented, not an IANA codepoint).
final class TlsKeySchedule {
  TlsKeySchedule(this.crypto);

  final PqTransportCrypto crypto;

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

  void derive({
    required Uint8List hybridSharedSecret,
    required Uint8List handshakeTranscriptHash,
    required Uint8List applicationTranscriptHash,
  }) {
    final zeros = Uint8List(transcriptHashBytes);
    final early = crypto.hkdfExtract(zeros, zeros);
    final derivedEarly = deriveSecret(early, tlsLabelDerived, zeros);
    final handshake = crypto.hkdfExtract(derivedEarly, hybridSharedSecret);
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
    final master = crypto.hkdfExtract(derivedHs, zeros);
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
    final zeros = Uint8List(transcriptHashBytes);
    final early = crypto.hkdfExtract(zeros, zeros);
    final derivedEarly = deriveSecret(early, tlsLabelDerived, zeros);
    final handshake = crypto.hkdfExtract(derivedEarly, hybridSharedSecret);
    final derivedHs = deriveSecret(handshake, tlsLabelDerived, zeros);
    final master = crypto.hkdfExtract(derivedHs, zeros);
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
    return expandLabel(secret, label, context, transcriptHashBytes);
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
    return crypto.hkdfExpand(secret, b.takeBytes(), length);
  }

  Uint8List exporter(String label, Uint8List context, int length) {
    final derived = expandLabel(
      exporterMaster,
      label,
      crypto.sha256(context),
      transcriptHashBytes,
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
