import 'dart:typed_data';

import 'package:swissarmyknife/swissarmyknife.dart';

import '../core/bytes.dart';
import '../core/crypto.dart';
import '../core/errors.dart';
import '../core/lengths.dart';

enum QuicConnectionState { idle, handshake, ready, draining, closed, failed }

enum QuicConnectionEvent { start, handshakeDone, close, fatal, drain }

enum QuicStreamState { idle, open, halfClosed, closed, reset }

enum QuicStreamEvent { open, data, fin, reset, close }

StateMachine<QuicConnectionState, QuicConnectionEvent> quicConnMachine() {
  final m = StateMachine<QuicConnectionState, QuicConnectionEvent>(
    initialState: QuicConnectionState.idle,
  );
  m.addTransition(
    QuicConnectionState.idle,
    QuicConnectionEvent.start,
    QuicConnectionState.handshake,
  );
  m.addTransition(
    QuicConnectionState.idle,
    QuicConnectionEvent.fatal,
    QuicConnectionState.failed,
  );
  m.addTransition(
    QuicConnectionState.idle,
    QuicConnectionEvent.close,
    QuicConnectionState.closed,
  );
  m.addTransition(
    QuicConnectionState.handshake,
    QuicConnectionEvent.handshakeDone,
    QuicConnectionState.ready,
  );
  m.addTransition(
    QuicConnectionState.handshake,
    QuicConnectionEvent.fatal,
    QuicConnectionState.failed,
  );
  m.addTransition(
    QuicConnectionState.handshake,
    QuicConnectionEvent.close,
    QuicConnectionState.closed,
  );
  m.addTransition(
    QuicConnectionState.ready,
    QuicConnectionEvent.drain,
    QuicConnectionState.draining,
  );
  m.addTransition(
    QuicConnectionState.ready,
    QuicConnectionEvent.close,
    QuicConnectionState.closed,
  );
  m.addTransition(
    QuicConnectionState.ready,
    QuicConnectionEvent.fatal,
    QuicConnectionState.failed,
  );
  m.addTransition(
    QuicConnectionState.draining,
    QuicConnectionEvent.close,
    QuicConnectionState.closed,
  );
  m.addTransition(
    QuicConnectionState.failed,
    QuicConnectionEvent.close,
    QuicConnectionState.closed,
  );
  return m;
}

StateMachine<QuicStreamState, QuicStreamEvent> quicStreamMachine() {
  final m = StateMachine<QuicStreamState, QuicStreamEvent>(
    initialState: QuicStreamState.idle,
  );
  m.addTransition(
    QuicStreamState.idle,
    QuicStreamEvent.open,
    QuicStreamState.open,
  );
  m.addTransition(
    QuicStreamState.idle,
    QuicStreamEvent.reset,
    QuicStreamState.reset,
  );
  m.addTransition(
    QuicStreamState.open,
    QuicStreamEvent.data,
    QuicStreamState.open,
  );
  m.addTransition(
    QuicStreamState.open,
    QuicStreamEvent.fin,
    QuicStreamState.halfClosed,
  );
  m.addTransition(
    QuicStreamState.open,
    QuicStreamEvent.reset,
    QuicStreamState.reset,
  );
  m.addTransition(
    QuicStreamState.halfClosed,
    QuicStreamEvent.close,
    QuicStreamState.closed,
  );
  m.addTransition(
    QuicStreamState.halfClosed,
    QuicStreamEvent.reset,
    QuicStreamState.reset,
  );
  return m;
}

final class QuicCryptoFrame {
  const QuicCryptoFrame({required this.offset, required this.data});
  final int offset;
  final Uint8List data;

  Uint8List encode() {
    final b = BytesBuilder(copy: false);
    b.addByte(quicFrameCrypto);
    _varint(b, offset);
    _varint(b, data.length);
    b.add(data);
    return b.takeBytes();
  }

  static Result<QuicCryptoFrame, PqTransportError> decode(Uint8List wire) {
    final r = ByteReader(wire);
    final type = r.u8();
    if (type.isFailure) return Result.failure(type.errorOrNull!);
    if (type.valueOrNull != quicFrameCrypto) {
      return Result.failure(PqTransportError.decodeFailure('not CRYPTO frame'));
    }
    final offset = readVarint(r);
    final len = readVarint(r);
    if (offset < 0 || len < 0) {
      return Result.failure(PqTransportError.decodeFailure('crypto varint'));
    }
    final data = r.take(len, PqLengthLabel.datagram);
    if (data.isFailure) return Result.failure(data.errorOrNull!);
    return Result.success(
      QuicCryptoFrame(offset: offset, data: data.valueOrNull!),
    );
  }
}

final class QuicStreamFrame {
  const QuicStreamFrame({
    required this.id,
    required this.offset,
    required this.data,
    this.fin = false,
  });
  final int id;
  final int offset;
  final Uint8List data;
  final bool fin;

  Uint8List encode() {
    final b = BytesBuilder(copy: false);
    b.addByte(quicFrameStream | 0x04 | 0x02 | (fin ? 0x01 : 0));
    _varint(b, id);
    _varint(b, offset);
    _varint(b, data.length);
    b.add(data);
    return b.takeBytes();
  }
}

void _varint(BytesBuilder b, int v) {
  if (v < 64) {
    b.addByte(v);
  } else if (v < 16384) {
    writeUint16(b, v | 0x4000);
  } else {
    writeUint32(b, v | 0x80000000);
  }
}

int readVarint(ByteReader r) {
  if (r.remaining < 1) return -1;
  final first = r.bytes[r.offset];
  final prefix = first >> 6;
  final len = 1 << prefix;
  if (r.remaining < len) return -1;
  var v = first & 0x3f;
  r.offset++;
  for (var i = 1; i < len; i++) {
    v = (v << 8) | r.bytes[r.offset++];
  }
  return v;
}

/// 1-RTT packet: 1-byte flags || dcid(8) || pn(4) || AEAD(payload||tag)
final class QuicPacketCodec {
  QuicPacketCodec({required this.crypto, required this.key, required this.iv});

  final PqTransportCrypto crypto;
  final Uint8List key;
  final Uint8List iv;

  Result<Uint8List, PqTransportError> protect({
    required Uint8List dcid,
    required int packetNumber,
    required Uint8List payload,
  }) {
    if (dcid.length != 8) {
      return Result.failure(PqTransportError.decodeFailure('dcid'));
    }
    final nonce = Uint8List.fromList(iv);
    for (var i = 0; i < 4; i++) {
      nonce[nonce.length - 1 - i] ^= (packetNumber >> (8 * i)) & 0xff;
    }
    final header = BytesBuilder(copy: false);
    header.addByte(0x40);
    header.add(dcid);
    writeUint32(header, packetNumber);
    final hdr = header.takeBytes();
    final body = crypto.aeadSeal(
      key: key,
      nonce: nonce,
      plaintext: payload,
      aad: hdr,
    );
    return Result.success(concatBytes([hdr, body]));
  }

  Result<({int packetNumber, Uint8List payload}), PqTransportError> open(
    Uint8List wire,
  ) {
    if (wire.length < 1 + 8 + 4 + aeadTagBytes) {
      return Result.failure(PqTransportError.decodeFailure('short quic'));
    }
    final hdr = slice(wire, 0, 13);
    final pn = readUint32(wire, 9);
    final nonce = Uint8List.fromList(iv);
    for (var i = 0; i < 4; i++) {
      nonce[nonce.length - 1 - i] ^= (pn >> (8 * i)) & 0xff;
    }
    try {
      final payload = crypto.aeadOpen(
        key: key,
        nonce: nonce,
        ciphertextWithTag: slice(wire, 13, wire.length),
        aad: hdr,
      );
      return Result.success((packetNumber: pn, payload: payload));
    } on Object catch (e) {
      return Result.failure(
        PqTransportError.decryptError('quic ${e.runtimeType}'),
      );
    }
  }
}

final class QuicFlowControl {
  QuicFlowControl({
    this.maxData = quicMaxDataDefault,
    this.maxStreamData = quicMaxStreamDataDefault,
  });

  final int maxData;
  final int maxStreamData;
  int sentData = 0;
  final Map<int, int> sentStream = {};

  Result<void, PqTransportError> consume(int streamId, int bytes) {
    sentData += bytes;
    sentStream[streamId] = (sentStream[streamId] ?? 0) + bytes;
    if (sentData > maxData) {
      return Result.failure(
        PqTransportError.handshakeFailure('MAX_DATA exceeded'),
      );
    }
    if ((sentStream[streamId] ?? 0) > maxStreamData) {
      return Result.failure(
        PqTransportError.handshakeFailure('MAX_STREAM_DATA exceeded'),
      );
    }
    return const Result.success(null);
  }
}
