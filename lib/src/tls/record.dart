import 'dart:typed_data';

import 'package:swissarmyknife/swissarmyknife.dart';

import '../core/bytes.dart';
import '../core/crypto.dart';
import '../core/errors.dart';
import '../core/lengths.dart';
import 'key_schedule.dart';

/// RFC 8446 epoch: handshake and application sequences are independent.
enum TlsRecordEpoch { handshake, application }

final class TlsRecord {
  const TlsRecord({required this.type, required this.payload});

  final int type;
  final Uint8List payload;
}

Uint8List encodePlainRecord(TlsRecord record) {
  final b = BytesBuilder(copy: false);
  b.addByte(record.type);
  writeUint16(b, tlsLegacyVersion);
  writeUint16(b, record.payload.length);
  b.add(record.payload);
  return b.takeBytes();
}

Result<TlsRecord, PqTransportError> decodePlainRecord(Uint8List wire) {
  if (wire.length < tlsRecordHeaderBytes) {
    return Result.failure(PqTransportError.decodeFailure('short record'));
  }
  final type = wire[0];
  final length = readUint16(wire, 3);
  if (wire.length != tlsRecordHeaderBytes + length) {
    return Result.failure(
      PqTransportError.decodeFailure('record length mismatch'),
    );
  }
  if (length > tlsMaxPlaintextBytes) {
    return Result.failure(PqTransportError.decodeFailure('record too large'));
  }
  return Result.success(
    TlsRecord(
      type: type,
      payload: slice(wire, tlsRecordHeaderBytes, wire.length),
    ),
  );
}

Uint8List encodeHandshake(int msgType, Uint8List body) {
  final b = BytesBuilder(copy: false);
  b.addByte(msgType);
  writeUint24(b, body.length);
  b.add(body);
  return b.takeBytes();
}

Result<(int, Uint8List), PqTransportError> decodeHandshake(Uint8List payload) {
  if (payload.length < tlsHandshakeHeaderBytes) {
    return Result.failure(PqTransportError.decodeFailure('short handshake'));
  }
  final type = payload[0];
  final length = readUint24(payload, 1);
  if (payload.length != tlsHandshakeHeaderBytes + length) {
    return Result.failure(
      PqTransportError.decodeFailure('handshake length mismatch'),
    );
  }
  return Result.success((
    type,
    slice(payload, tlsHandshakeHeaderBytes, payload.length),
  ));
}

final class TlsRecordLayer {
  TlsRecordLayer(this.crypto, this.schedule);

  final PqTransportCrypto crypto;
  final TlsKeySchedule schedule;
  var _hsWrite = 0;
  var _hsRead = 0;
  var _appWrite = 0;
  var _appRead = 0;

  int get handshakeWriteSequence => _hsWrite;
  int get applicationWriteSequence => _appWrite;

  int _nextWrite(TlsRecordEpoch epoch) =>
      epoch == TlsRecordEpoch.handshake ? _hsWrite++ : _appWrite++;

  int _nextRead(TlsRecordEpoch epoch) =>
      epoch == TlsRecordEpoch.handshake ? _hsRead++ : _appRead++;

  Uint8List protectWith({
    required Uint8List trafficSecret,
    required Uint8List iv,
    required TlsRecord inner,
    TlsRecordEpoch epoch = TlsRecordEpoch.handshake,
  }) {
    final key = schedule.trafficKey(trafficSecret);
    final nonce = schedule.nonce(iv, _nextWrite(epoch));
    final innerBytes = concatBytes([
      inner.payload,
      Uint8List.fromList([inner.type]),
    ]);
    final sealed = crypto.aeadSeal(
      key: key,
      nonce: nonce,
      plaintext: innerBytes,
      aead: schedule.aead,
    );
    final b = BytesBuilder(copy: false);
    b.addByte(tlsContentApplicationData);
    writeUint16(b, tlsLegacyVersion);
    writeUint16(b, sealed.length);
    b.add(sealed);
    return b.takeBytes();
  }

  Result<TlsRecord, PqTransportError> openWith({
    required Uint8List trafficSecret,
    required Uint8List iv,
    required Uint8List wire,
    TlsRecordEpoch epoch = TlsRecordEpoch.handshake,
  }) {
    final rec = decodePlainRecord(wire);
    if (rec.isFailure) return Result.failure(rec.errorOrNull!);
    final key = schedule.trafficKey(trafficSecret);
    final nonce = schedule.nonce(iv, _nextRead(epoch));
    try {
      final plain = crypto.aeadOpen(
        key: key,
        nonce: nonce,
        ciphertextWithTag: rec.valueOrNull!.payload,
        aead: schedule.aead,
      );
      if (plain.isEmpty) {
        return Result.failure(PqTransportError.decodeFailure('empty inner'));
      }
      final type = plain.last;
      return Result.success(
        TlsRecord(type: type, payload: slice(plain, 0, plain.length - 1)),
      );
    } on Object catch (e) {
      return Result.failure(
        PqTransportError.decryptError('record open ${e.runtimeType}'),
      );
    }
  }
}
