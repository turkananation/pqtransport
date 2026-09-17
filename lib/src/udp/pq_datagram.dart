import 'dart:typed_data';

import 'package:swissarmyknife/swissarmyknife.dart';

import '../core/bytes.dart';
import '../core/crypto.dart';
import '../core/errors.dart';
import '../core/lengths.dart';

/// Versioned PQ datagram: `version || header_len || header || nonce || ct||tag`.
///
/// Sequence lives in the header and is bound as AAD. Default AEAD is AES-256-GCM
/// from pqforge.
final class PqDatagram {
  const PqDatagram({
    required this.sequence,
    required this.payload,
    this.version = datagramVersion,
  });

  final int version;
  final int sequence;
  final Uint8List payload;

  Uint8List get header {
    final b = BytesBuilder(copy: false);
    writeUint64(b, sequence);
    return b.takeBytes();
  }

  Uint8List aad() {
    final b = BytesBuilder(copy: false);
    b.addByte(version);
    final hdr = header;
    b.addByte(hdr.length);
    b.add(hdr);
    return b.takeBytes();
  }
}

/// Cheap sequence peek used for replay defense **before** AEAD open.
Result<int, PqTransportError> peekDatagramSequence(Uint8List wire) {
  final minOk = requireMinLength(
    wire,
    datagramMinHeaderBytes,
    PqLengthLabel.datagram,
  );
  if (minOk.isFailure) return Result.failure(minOk.errorOrNull!);
  if (wire[0] != datagramVersion) {
    return Result.failure(
      PqTransportError.decodeFailure('unsupported datagram version ${wire[0]}'),
    );
  }
  final hdrLen = wire[1];
  if (hdrLen < datagramSequenceBytes) {
    return Result.failure(PqTransportError.decodeFailure('short header'));
  }
  if (wire.length < datagramVersionBytes + datagramHeaderLenBytes + hdrLen) {
    return Result.failure(PqTransportError.decodeFailure('truncated header'));
  }
  return Result.success(
    readUint64(wire, datagramVersionBytes + datagramHeaderLenBytes),
  );
}

final class PqDatagramCodec {
  PqDatagramCodec({
    required this.key,
    PqTransportCrypto? crypto,
    this.maxPayloadBytes = datagramDefaultMaxPayloadBytes,
  }) : crypto = crypto ?? const PqTransportCrypto();

  final Uint8List key;
  final PqTransportCrypto crypto;
  final int maxPayloadBytes;

  Result<Uint8List, PqTransportError> seal(
    PqDatagram datagram, {
    required Uint8List nonce,
  }) {
    final keyOk = requireLength(key, aeadKeyBytes, PqLengthLabel.aeadKey);
    if (keyOk.isFailure) return Result.failure(keyOk.errorOrNull!);
    final nonceOk = requireLength(
      nonce,
      aeadNonceBytes,
      PqLengthLabel.aeadNonce,
    );
    if (nonceOk.isFailure) return Result.failure(nonceOk.errorOrNull!);
    if (datagram.payload.length > maxPayloadBytes) {
      return Result.failure(
        PqTransportError.illegalParameter(
          PqLengthLabel.datagram,
          datagram.payload.length,
          maxPayloadBytes,
        ),
      );
    }
    final aad = datagram.aad();
    final body = crypto.aeadSeal(
      key: key,
      nonce: nonce,
      plaintext: datagram.payload,
      aad: aad,
    );
    final out = BytesBuilder(copy: false);
    out.add(aad);
    out.add(nonce);
    out.add(body);
    return Result.success(out.takeBytes());
  }

  Result<PqDatagram, PqTransportError> open(Uint8List wire) {
    final min = datagramMinHeaderBytes + aeadNonceBytes + aeadTagBytes;
    final minOk = requireMinLength(wire, min, PqLengthLabel.datagram);
    if (minOk.isFailure) return Result.failure(minOk.errorOrNull!);
    final reader = ByteReader(wire);
    final version = reader.u8();
    if (version.isFailure) return Result.failure(version.errorOrNull!);
    if (version.valueOrNull != datagramVersion) {
      return Result.failure(
        PqTransportError.decodeFailure(
          'unsupported datagram version ${version.valueOrNull}',
        ),
      );
    }
    final hdrLen = reader.u8();
    if (hdrLen.isFailure) return Result.failure(hdrLen.errorOrNull!);
    final header = reader.take(hdrLen.valueOrNull!, PqLengthLabel.datagram);
    if (header.isFailure) return Result.failure(header.errorOrNull!);
    if (header.valueOrNull!.length < datagramSequenceBytes) {
      return Result.failure(PqTransportError.decodeFailure('short header'));
    }
    final sequence = readUint64(header.valueOrNull!, 0);
    final nonce = reader.take(aeadNonceBytes, PqLengthLabel.aeadNonce);
    if (nonce.isFailure) return Result.failure(nonce.errorOrNull!);
    final ct = reader.take(reader.remaining, PqLengthLabel.datagram);
    if (ct.isFailure) return Result.failure(ct.errorOrNull!);
    final aad = wire.sublist(
      0,
      datagramVersionBytes + datagramHeaderLenBytes + hdrLen.valueOrNull!,
    );
    try {
      final payload = crypto.aeadOpen(
        key: key,
        nonce: nonce.valueOrNull!,
        ciphertextWithTag: ct.valueOrNull!,
        aad: Uint8List.fromList(aad),
      );
      return Result.success(
        PqDatagram(
          version: version.valueOrNull!,
          sequence: sequence,
          payload: payload,
        ),
      );
    } on Object catch (e) {
      return Result.failure(
        PqTransportError.decryptError('aead open failed: ${e.runtimeType}'),
      );
    }
  }
}
