import 'lengths.dart';

/// Protocol / codec failure. Never includes secret bytes in [message].
final class PqTransportError implements Exception {
  const PqTransportError._({
    required this.code,
    required this.message,
    this.alert,
  });

  factory PqTransportError.illegalParameter(
    PqLengthLabel label,
    int actual,
    int expected,
  ) => PqTransportError._(
    code: PqTransportErrorCode.illegalParameter,
    message:
        'illegal_parameter: ${label.name} length $actual, expected $expected',
    alert: tlsAlertIllegalParameter,
  );

  /// Wrong-on-the-wire KEM key that passed length but failed FIPS 203 §7.2.
  factory PqTransportError.illegalKemKey(PqLengthLabel label) =>
      PqTransportError._(
        code: PqTransportErrorCode.illegalParameter,
        message:
            'illegal_parameter: ${label.name} failed FIPS 203 §7.2 '
            'encapsulation-key check',
        alert: tlsAlertIllegalParameter,
      );

  factory PqTransportError.decodeFailure(String why) => PqTransportError._(
    code: PqTransportErrorCode.decodeFailure,
    message: 'decode_failure: $why',
    alert: tlsAlertDecodeError,
  );

  factory PqTransportError.unexpectedMessage(String why) => PqTransportError._(
    code: PqTransportErrorCode.unexpectedMessage,
    message: 'unexpected_message: $why',
    alert: tlsAlertUnexpectedMessage,
  );

  factory PqTransportError.handshakeFailure(String why) => PqTransportError._(
    code: PqTransportErrorCode.handshakeFailure,
    message: 'handshake_failure: $why',
    alert: tlsAlertHandshakeFailure,
  );

  factory PqTransportError.internalError(String why) => PqTransportError._(
    code: PqTransportErrorCode.internalError,
    message: 'internal_error: $why',
    alert: tlsAlertInternalError,
  );

  factory PqTransportError.decryptError(String why) => PqTransportError._(
    code: PqTransportErrorCode.decryptError,
    message: 'decrypt_error: $why',
    alert: tlsAlertDecryptError,
  );

  factory PqTransportError.circuitOpen(String why) => PqTransportError._(
    code: PqTransportErrorCode.circuitOpen,
    message: 'circuit_open: $why',
  );

  factory PqTransportError.replay(String why) => PqTransportError._(
    code: PqTransportErrorCode.replay,
    message: 'replay: $why',
  );

  factory PqTransportError.throttled(String why) => PqTransportError._(
    code: PqTransportErrorCode.throttled,
    message: 'throttled: $why',
  );

  factory PqTransportError.closed(String why) => PqTransportError._(
    code: PqTransportErrorCode.closed,
    message: 'closed: $why',
  );

  factory PqTransportError.unsupported(String why) => PqTransportError._(
    code: PqTransportErrorCode.unsupported,
    message: 'unsupported: $why',
  );

  final PqTransportErrorCode code;
  final String message;
  final int? alert;

  @override
  String toString() => 'PqTransportError($code: $message)';
}

enum PqTransportErrorCode {
  illegalParameter,
  decodeFailure,
  unexpectedMessage,
  handshakeFailure,
  internalError,
  decryptError,
  circuitOpen,
  replay,
  throttled,
  closed,
  unsupported,
}

/// Named length filter labels (never log the bytes themselves).
enum PqLengthLabel {
  mlKem768PublicKey,
  mlKem768Ciphertext,
  mlKem768SharedSecret,
  mlKem1024PublicKey,
  mlKem1024Ciphertext,
  mlKem1024SharedSecret,
  x25519Share,
  x25519SharedSecret,
  secp256r1Share,
  secp256r1SharedSecret,
  secp384r1Share,
  secp384r1SharedSecret,
  hybridClientShare,
  hybridServerShare,
  hybridSharedSecret,
  mlDsa65PublicKey,
  mlDsa65Signature,
  nonce,
  aeadNonce,
  aeadTag,
  aeadKey,
  transcriptHash,
  sessionKey,
  handshakeRandom,
  verifyData,
  datagram,
}

const int tlsAlertDecodeError = 50;
