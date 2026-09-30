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

  static Result<QuicCryptoFrame, PqTransportError> decode(Uint8List wire) =>
      read(ByteReader(wire));

  static Result<QuicCryptoFrame, PqTransportError> read(ByteReader r) {
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

final class QuicAckFrame {
  const QuicAckFrame({
    required this.largest,
    required this.delay,
    required this.firstRange,
    this.additional = const [],
  });

  final int largest;
  final int delay;
  final int firstRange;
  final List<(int gap, int range)> additional;

  /// Packet numbers acknowledged by this frame, descending.
  List<int> packetNumbers() {
    final out = <int>[];
    var high = largest;
    void range(int length) {
      for (var i = 0; i <= length; i++) {
        out.add(high - i);
      }
    }

    range(firstRange);
    var smallest = largest - firstRange;
    for (final (gap, ackRange) in additional) {
      high = smallest - gap - 2;
      range(ackRange);
      smallest = high - ackRange;
    }
    return out;
  }

  Uint8List encode() {
    final b = BytesBuilder(copy: false);
    b.addByte(quicFrameAck);
    _varint(b, largest);
    _varint(b, delay);
    _varint(b, additional.length);
    _varint(b, firstRange);
    for (final (gap, range) in additional) {
      _varint(b, gap);
      _varint(b, range);
    }
    return b.takeBytes();
  }

  static Result<QuicAckFrame, PqTransportError> decode(Uint8List wire) =>
      read(ByteReader(wire));

  static Result<QuicAckFrame, PqTransportError> read(ByteReader r) {
    final type = r.u8();
    if (type.isFailure) return Result.failure(type.errorOrNull!);
    if (type.valueOrNull != quicFrameAck) {
      return Result.failure(PqTransportError.decodeFailure('not ACK frame'));
    }
    final largest = readVarint(r);
    final delay = readVarint(r);
    final count = readVarint(r);
    final first = readVarint(r);
    if (largest < 0 || delay < 0 || count < 0 || first < 0) {
      return Result.failure(PqTransportError.decodeFailure('ack varint'));
    }
    final extra = <(int, int)>[];
    for (var i = 0; i < count; i++) {
      final gap = readVarint(r);
      final range = readVarint(r);
      if (gap < 0 || range < 0) {
        return Result.failure(PqTransportError.decodeFailure('ack range'));
      }
      extra.add((gap, range));
    }
    return Result.success(
      QuicAckFrame(
        largest: largest,
        delay: delay,
        firstRange: first,
        additional: extra,
      ),
    );
  }
}

/// Tracks received packet numbers and in-flight sent packets (RFC 9000 ACK).
final class QuicAckProcessor {
  final Set<int> received = <int>{};
  final Map<int, Uint8List> inFlight = {};

  void onReceived(int packetNumber) => received.add(packetNumber);

  void onSent(int packetNumber, Uint8List payload) {
    inFlight[packetNumber] = payload;
  }

  Result<QuicAckFrame, PqTransportError> pendingAck({int delay = 0}) {
    if (received.isEmpty) {
      return Result.failure(PqTransportError.decodeFailure('no packets'));
    }
    final nums = received.toList()..sort();
    final largest = nums.last;
    var firstRange = 0;
    for (var pn = largest - 1; pn >= 0 && received.contains(pn); pn--) {
      firstRange++;
    }
    final additional = <(int, int)>[];
    var cursor = largest - firstRange - 1;
    while (cursor >= 0) {
      var gap = 0;
      while (cursor >= 0 && !received.contains(cursor)) {
        gap++;
        cursor--;
      }
      if (cursor < 0) break;
      var range = 0;
      while (cursor >= 0 && received.contains(cursor)) {
        range++;
        cursor--;
      }
      additional.add((gap - 1, range - 1));
    }
    return Result.success(
      QuicAckFrame(
        largest: largest,
        delay: delay,
        firstRange: firstRange,
        additional: additional,
      ),
    );
  }

  /// Newly acknowledged packet numbers, removed from [inFlight].
  List<int> applyAck(QuicAckFrame ack) {
    final newly = <int>[];
    for (final pn in ack.packetNumbers()) {
      if (inFlight.remove(pn) != null) newly.add(pn);
    }
    return newly;
  }
}

/// CRYPTO + ACK frames from a QUIC packet payload. PADDING and PING are
/// skipped. Unknown types fail closed.
final class QuicPayload {
  const QuicPayload({this.crypto = const [], this.acks = const []});

  final List<QuicCryptoFrame> crypto;
  final List<QuicAckFrame> acks;
}

Result<QuicPayload, PqTransportError> decodeQuicPayload(Uint8List payload) {
  final r = ByteReader(payload);
  final crypto = <QuicCryptoFrame>[];
  final acks = <QuicAckFrame>[];
  while (r.remaining > 0) {
    final type = r.bytes[r.offset];
    if (type == quicFramePadding || type == quicFramePing) {
      r.offset++;
      continue;
    }
    if (type == quicFrameCrypto) {
      final f = QuicCryptoFrame.read(r);
      if (f.isFailure) return Result.failure(f.errorOrNull!);
      crypto.add(f.valueOrNull!);
      continue;
    }
    if (type == quicFrameAck) {
      final f = QuicAckFrame.read(r);
      if (f.isFailure) return Result.failure(f.errorOrNull!);
      acks.add(f.valueOrNull!);
      continue;
    }
    return Result.failure(
      PqTransportError.decodeFailure(
        'unsupported quic frame 0x${type.toRadixString(16)}',
      ),
    );
  }
  return Result.success(QuicPayload(crypto: crypto, acks: acks));
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

/// RFC 9001 §5.3: left-pad the packet number to the IV length, then XOR.
Uint8List quicAeadNonce(Uint8List iv, int packetNumber) {
  final nonce = Uint8List.fromList(iv);
  for (var i = 0; i < 8; i++) {
    nonce[nonce.length - 1 - i] ^= (packetNumber >> (8 * i)) & 0xff;
  }
  return nonce;
}

void writePacketNumber(BytesBuilder b, int packetNumber, int length) {
  for (var i = length - 1; i >= 0; i--) {
    b.addByte((packetNumber >> (8 * i)) & 0xff);
  }
}

int readPacketNumber(Uint8List bytes, int offset, int length) {
  var v = 0;
  for (var i = 0; i < length; i++) {
    v = (v << 8) | bytes[offset + i];
  }
  return v;
}

bool quicHeaderProtectionSampleFits(int packetLength, int pnOffset) =>
    packetLength >=
    pnOffset + quicPacketNumberMaxBytes + quicHeaderProtectionSampleBytes;

Uint8List quicHeaderProtectionMask({
  required PqTransportCrypto crypto,
  required Uint8List hpKey,
  required Uint8List packet,
  required int pnOffset,
}) {
  final sampleOff = pnOffset + quicPacketNumberMaxBytes;
  return crypto.aesEncryptBlock(
    key: hpKey,
    block: slice(
      packet,
      sampleOff,
      sampleOff + quicHeaderProtectionSampleBytes,
    ),
  );
}

/// RFC 9001 Figure 6. Sample is always taken 4 bytes after [pnOffset].
void applyQuicHeaderProtection(
  Uint8List packet, {
  required Uint8List mask,
  required int pnOffset,
  required int pnLength,
  required bool longHeader,
}) {
  packet[0] ^= mask[0] & (longHeader ? 0x0f : 0x1f);
  for (var i = 0; i < pnLength; i++) {
    packet[pnOffset + i] ^= mask[1 + i];
  }
}

/// RFC 9001 §5.1 packet protection keys for one direction.
final class QuicPacketKeys {
  const QuicPacketKeys({required this.key, required this.iv, required this.hp});

  final Uint8List key;
  final Uint8List iv;
  final Uint8List hp;
}

/// 1-RTT short header: RFC 9000 §17.3 + §5.4 header protection.
///
/// `flags(1) || dcid(8) || pn(4) || AEAD(payload||tag)` then HP on the first
/// byte (low 5 bits) and the packet number.
final class QuicPacketCodec {
  QuicPacketCodec({
    required this.crypto,
    required this.key,
    required this.iv,
    required this.hpKey,
    this.aead = TransportAead.aes256Gcm,
  });

  final PqTransportCrypto crypto;
  final Uint8List key;
  final Uint8List iv;
  final Uint8List hpKey;
  final TransportAead aead;

  static const pnLength = 4;

  factory QuicPacketCodec.fromKeys(
    PqTransportCrypto crypto,
    QuicPacketKeys keys, {
    TransportAead aead = TransportAead.aes256Gcm,
  }) => QuicPacketCodec(
    crypto: crypto,
    key: keys.key,
    iv: keys.iv,
    hpKey: keys.hp,
    aead: aead,
  );

  Result<Uint8List, PqTransportError> protect({
    required Uint8List dcid,
    required int packetNumber,
    required Uint8List payload,
    int packetNumberLength = pnLength,
  }) {
    if (aead == TransportAead.chacha20Poly1305) {
      return Result.failure(
        PqTransportError.unsupported(
          'QUIC ChaCha20 header protection is not implemented',
        ),
      );
    }
    if (packetNumberLength < 1 ||
        packetNumberLength > quicPacketNumberMaxBytes) {
      return Result.failure(PqTransportError.decodeFailure('pn length'));
    }
    if (dcid.length != quicShortDcidBytes) {
      return Result.failure(PqTransportError.decodeFailure('dcid'));
    }
    final nonce = quicAeadNonce(iv, packetNumber);
    final header = BytesBuilder(copy: false);
    header.addByte(0x40 | (packetNumberLength - 1));
    header.add(dcid);
    writePacketNumber(header, packetNumber, packetNumberLength);
    final hdr = header.takeBytes();
    final body = crypto.aeadSeal(
      key: key,
      nonce: nonce,
      plaintext: payload,
      aad: hdr,
      aead: aead,
    );
    final packet = concatBytes([hdr, body]);
    final pnOff = 1 + quicShortDcidBytes;
    if (!quicHeaderProtectionSampleFits(packet.length, pnOff)) {
      return Result.failure(PqTransportError.decodeFailure('hp sample'));
    }
    final mask = quicHeaderProtectionMask(
      crypto: crypto,
      hpKey: hpKey,
      packet: packet,
      pnOffset: pnOff,
    );
    applyQuicHeaderProtection(
      packet,
      mask: mask,
      pnOffset: pnOff,
      pnLength: packetNumberLength,
      longHeader: false,
    );
    return Result.success(packet);
  }

  Result<({int packetNumber, Uint8List payload}), PqTransportError> open(
    Uint8List wire,
  ) {
    const minLen =
        1 +
        quicShortDcidBytes +
        quicPacketNumberMaxBytes +
        quicHeaderProtectionSampleBytes;
    if (wire.length < minLen) {
      return Result.failure(PqTransportError.decodeFailure('short quic'));
    }
    final packet = Uint8List.fromList(wire);
    if ((packet[0] & 0x80) != 0) {
      return Result.failure(PqTransportError.decodeFailure('not short header'));
    }
    final pnOff = 1 + quicShortDcidBytes;
    if (!quicHeaderProtectionSampleFits(packet.length, pnOff)) {
      return Result.failure(PqTransportError.decodeFailure('hp sample'));
    }
    final mask = quicHeaderProtectionMask(
      crypto: crypto,
      hpKey: hpKey,
      packet: packet,
      pnOffset: pnOff,
    );
    packet[0] ^= mask[0] & 0x1f;
    final pnLen = (packet[0] & 0x03) + 1;
    if (pnOff + pnLen > packet.length) {
      return Result.failure(PqTransportError.decodeFailure('pn length'));
    }
    for (var i = 0; i < pnLen; i++) {
      packet[pnOff + i] ^= mask[1 + i];
    }
    final pn = readPacketNumber(packet, pnOff, pnLen);
    final hdr = slice(packet, 0, pnOff + pnLen);
    try {
      final payload = crypto.aeadOpen(
        key: key,
        nonce: quicAeadNonce(iv, pn),
        ciphertextWithTag: slice(packet, pnOff + pnLen, packet.length),
        aad: hdr,
        aead: aead,
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
