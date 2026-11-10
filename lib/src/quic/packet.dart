import 'dart:typed_data';

import 'package:swissarmyknife/swissarmyknife.dart';

import '../core/bytes.dart';
import '../core/crypto.dart';
import '../core/errors.dart';
import '../core/lengths.dart';
import 'multipath.dart';

enum QuicConnectionState {
  idle,
  handshake,
  ready,
  draining,
  closed,
  failed,
  zeroRtt,
}

enum QuicConnectionEvent { start, handshakeDone, close, fatal, drain, early }

enum QuicStreamState { idle, open, halfClosed, closed, reset, zeroRtt }

enum QuicStreamEvent { open, data, fin, reset, close, early, confirm }

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
  m.addTransition(
    QuicConnectionState.handshake,
    QuicConnectionEvent.early,
    QuicConnectionState.zeroRtt,
  );
  m.addTransition(
    QuicConnectionState.zeroRtt,
    QuicConnectionEvent.handshakeDone,
    QuicConnectionState.ready,
  );
  m.addTransition(
    QuicConnectionState.zeroRtt,
    QuicConnectionEvent.fatal,
    QuicConnectionState.failed,
  );
  m.addTransition(
    QuicConnectionState.zeroRtt,
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
  m.addTransition(
    QuicStreamState.idle,
    QuicStreamEvent.early,
    QuicStreamState.zeroRtt,
  );
  m.addTransition(
    QuicStreamState.zeroRtt,
    QuicStreamEvent.confirm,
    QuicStreamState.open,
  );
  m.addTransition(
    QuicStreamState.zeroRtt,
    QuicStreamEvent.fin,
    QuicStreamState.halfClosed,
  );
  m.addTransition(
    QuicStreamState.zeroRtt,
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
    writeQuicVarint(b, offset);
    writeQuicVarint(b, data.length);
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
    this.hasOffset = true,
    this.hasLength = true,
  });
  final int id;
  final int offset;
  final Uint8List data;
  final bool fin;
  final bool hasOffset;
  final bool hasLength;

  int get typeByte {
    var t = quicFrameStream;
    if (hasOffset) t |= quicFrameStreamOffBit;
    if (hasLength) t |= quicFrameStreamLenBit;
    if (fin) t |= quicFrameStreamFinBit;
    return t;
  }

  Uint8List encode() {
    final b = BytesBuilder(copy: false);
    b.addByte(typeByte);
    writeQuicVarint(b, id);
    if (hasOffset) writeQuicVarint(b, offset);
    if (hasLength) writeQuicVarint(b, data.length);
    b.add(data);
    return b.takeBytes();
  }

  static Result<QuicStreamFrame, PqTransportError> decode(Uint8List wire) =>
      read(ByteReader(wire), remainingIsData: true);

  static Result<QuicStreamFrame, PqTransportError> read(
    ByteReader r, {
    required bool remainingIsData,
  }) {
    final type = r.u8();
    if (type.isFailure) return Result.failure(type.errorOrNull!);
    final t = type.valueOrNull!;
    if ((t & quicFrameStreamTypeMask) != quicFrameStream) {
      return Result.failure(PqTransportError.decodeFailure('not STREAM frame'));
    }
    final hasOff = (t & quicFrameStreamOffBit) != 0;
    final hasLen = (t & quicFrameStreamLenBit) != 0;
    final fin = (t & quicFrameStreamFinBit) != 0;
    final id = readVarint(r);
    if (id < 0) {
      return Result.failure(PqTransportError.decodeFailure('stream id'));
    }
    var offset = 0;
    if (hasOff) {
      offset = readVarint(r);
      if (offset < 0) {
        return Result.failure(PqTransportError.decodeFailure('stream offset'));
      }
    }
    int len;
    if (hasLen) {
      len = readVarint(r);
      if (len < 0) {
        return Result.failure(PqTransportError.decodeFailure('stream len'));
      }
    } else if (remainingIsData) {
      len = r.remaining;
    } else {
      return Result.failure(
        PqTransportError.decodeFailure('stream missing len'),
      );
    }
    final data = r.take(len, PqLengthLabel.quicStream);
    if (data.isFailure) return Result.failure(data.errorOrNull!);
    return Result.success(
      QuicStreamFrame(
        id: id,
        offset: offset,
        data: data.valueOrNull!,
        fin: fin,
        hasOffset: hasOff,
        hasLength: hasLen,
      ),
    );
  }
}

final class QuicAckFrame {
  const QuicAckFrame({
    required this.largest,
    required this.delay,
    required this.firstRange,
    this.additional = const [],
    this.ecn = false,
    this.ect0 = 0,
    this.ect1 = 0,
    this.ce = 0,
  });

  final int largest;
  final int delay;
  final int firstRange;
  final List<(int gap, int range)> additional;
  final bool ecn;
  final int ect0;
  final int ect1;
  final int ce;

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
    b.addByte(ecn ? quicFrameAckEcn : quicFrameAck);
    writeQuicVarint(b, largest);
    writeQuicVarint(b, delay);
    writeQuicVarint(b, additional.length);
    writeQuicVarint(b, firstRange);
    for (final (gap, range) in additional) {
      writeQuicVarint(b, gap);
      writeQuicVarint(b, range);
    }
    if (ecn) {
      writeQuicVarint(b, ect0);
      writeQuicVarint(b, ect1);
      writeQuicVarint(b, ce);
    }
    return b.takeBytes();
  }

  static Result<QuicAckFrame, PqTransportError> decode(Uint8List wire) =>
      read(ByteReader(wire));

  static Result<QuicAckFrame, PqTransportError> read(ByteReader r) {
    final type = r.u8();
    if (type.isFailure) return Result.failure(type.errorOrNull!);
    if (type.valueOrNull != quicFrameAck &&
        type.valueOrNull != quicFrameAckEcn) {
      return Result.failure(PqTransportError.decodeFailure('not ACK frame'));
    }
    final ecn = type.valueOrNull == quicFrameAckEcn;
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
    var ect0 = 0;
    var ect1 = 0;
    var ce = 0;
    if (ecn) {
      ect0 = readVarint(r);
      ect1 = readVarint(r);
      ce = readVarint(r);
      if (ect0 < 0 || ect1 < 0 || ce < 0) {
        return Result.failure(PqTransportError.decodeFailure('ack ecn'));
      }
    }
    return Result.success(
      QuicAckFrame(
        largest: largest,
        delay: delay,
        firstRange: first,
        additional: extra,
        ecn: ecn,
        ect0: ect0,
        ect1: ect1,
        ce: ce,
      ),
    );
  }
}

/// Tracks received packet numbers and which sent numbers an acknowledgement
/// has not yet removed (RFC 9000 §19.3).
///
/// Loss, the probe timeout, and the congestion window are not this type.
/// [QuicLossRecovery] keeps one processor per packet number space and uses
/// [applyAck] as the newly-acknowledged set.
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

/// RFC 9221 DATAGRAM. Not retransmitted. [lengthPrefixed] is type 0x31.
final class QuicDatagramFrame {
  const QuicDatagramFrame(this.payload, {required this.lengthPrefixed});

  final Uint8List payload;
  final bool lengthPrefixed;

  int get encodedLength =>
      1 +
      (lengthPrefixed ? quicVarintLength(payload.length) : 0) +
      payload.length;

  Uint8List encode() {
    final b = BytesBuilder(copy: false);
    b.addByte(lengthPrefixed ? quicFrameDatagramLen : quicFrameDatagram);
    if (lengthPrefixed) writeQuicVarint(b, payload.length);
    b.add(payload);
    return b.takeBytes();
  }
}

/// CRYPTO + ACK + STREAM + flow-control and path frames.
/// PADDING and PING are skipped. [ackEliciting] is set when any frame
/// other than ACK, PADDING, or CONNECTION_CLOSE was present (RFC 9002
/// §2 / RFC 9000 §13.2.1). Unknown types fail closed. ECN counts are
/// parsed and are not a congestion signal on a memory datagram.
final class QuicPayload {
  const QuicPayload({
    this.crypto = const [],
    this.acks = const [],
    this.streams = const [],
    this.maxData = const [],
    this.maxStreamData = const [],
    this.dataBlocked = const [],
    this.streamDataBlocked = const [],
    this.resets = const [],
    this.closes = const [],
    this.stopSending = const [],
    this.maxStreams = const [],
    this.streamsBlocked = const [],
    this.newConnectionIds = const [],
    this.retireConnectionIds = const [],
    this.newTokens = const [],
    this.pathChallenges = const [],
    this.pathResponses = const [],
    this.datagrams = const [],
    this.multipath = const [],
    this.handshakeDone = false,
    this.ackEliciting = false,
  });

  final List<QuicCryptoFrame> crypto;
  final List<QuicAckFrame> acks;
  final List<QuicStreamFrame> streams;
  final List<QuicMaxDataFrame> maxData;
  final List<QuicMaxStreamDataFrame> maxStreamData;
  final List<QuicDataBlockedFrame> dataBlocked;
  final List<QuicStreamDataBlockedFrame> streamDataBlocked;
  final List<QuicResetStreamFrame> resets;
  final List<QuicConnectionCloseFrame> closes;
  final List<QuicStopSendingFrame> stopSending;
  final List<QuicMaxStreamsFrame> maxStreams;
  final List<QuicStreamsBlockedFrame> streamsBlocked;
  final List<QuicNewConnectionIdFrame> newConnectionIds;
  final List<QuicRetireConnectionIdFrame> retireConnectionIds;
  final List<QuicNewTokenFrame> newTokens;
  final List<QuicPathChallengeFrame> pathChallenges;
  final List<QuicPathResponseFrame> pathResponses;
  final List<QuicDatagramFrame> datagrams;
  final List<QuicMultipathFrame> multipath;
  final bool handshakeDone;
  final bool ackEliciting;
}

Result<QuicPayload, PqTransportError> decodeQuicPayload(Uint8List payload) {
  final r = ByteReader(payload);
  final crypto = <QuicCryptoFrame>[];
  final acks = <QuicAckFrame>[];
  final streams = <QuicStreamFrame>[];
  final maxData = <QuicMaxDataFrame>[];
  final maxStreamData = <QuicMaxStreamDataFrame>[];
  final dataBlocked = <QuicDataBlockedFrame>[];
  final streamDataBlocked = <QuicStreamDataBlockedFrame>[];
  final resets = <QuicResetStreamFrame>[];
  final closes = <QuicConnectionCloseFrame>[];
  final stopSending = <QuicStopSendingFrame>[];
  final maxStreams = <QuicMaxStreamsFrame>[];
  final streamsBlocked = <QuicStreamsBlockedFrame>[];
  final newConnectionIds = <QuicNewConnectionIdFrame>[];
  final retireConnectionIds = <QuicRetireConnectionIdFrame>[];
  final newTokens = <QuicNewTokenFrame>[];
  final pathChallenges = <QuicPathChallengeFrame>[];
  final pathResponses = <QuicPathResponseFrame>[];
  final datagrams = <QuicDatagramFrame>[];
  final multipath = <QuicMultipathFrame>[];
  var handshakeDone = false;
  var ackEliciting = false;
  while (r.remaining > 0) {
    final type = r.bytes[r.offset];
    if (type == quicFramePadding) {
      r.offset++;
      continue;
    }
    if (type == quicFramePing) {
      ackEliciting = true;
      r.offset++;
      continue;
    }
    if (type == quicFrameCrypto) {
      final f = QuicCryptoFrame.read(r);
      if (f.isFailure) return Result.failure(f.errorOrNull!);
      crypto.add(f.valueOrNull!);
      ackEliciting = true;
      continue;
    }
    if (type == quicFrameAck || type == quicFrameAckEcn) {
      final f = QuicAckFrame.read(r);
      if (f.isFailure) return Result.failure(f.errorOrNull!);
      acks.add(f.valueOrNull!);
      continue;
    }
    if ((type & quicFrameStreamTypeMask) == quicFrameStream) {
      final hasLen = (type & quicFrameStreamLenBit) != 0;
      final f = QuicStreamFrame.read(r, remainingIsData: !hasLen);
      if (f.isFailure) return Result.failure(f.errorOrNull!);
      streams.add(f.valueOrNull!);
      ackEliciting = true;
      continue;
    }
    if (type == quicFrameMaxData) {
      final f = QuicMaxDataFrame.read(r);
      if (f.isFailure) return Result.failure(f.errorOrNull!);
      maxData.add(f.valueOrNull!);
      ackEliciting = true;
      continue;
    }
    if (type == quicFrameMaxStreamData) {
      final f = QuicMaxStreamDataFrame.read(r);
      if (f.isFailure) return Result.failure(f.errorOrNull!);
      maxStreamData.add(f.valueOrNull!);
      ackEliciting = true;
      continue;
    }
    if (type == quicFrameDataBlocked) {
      final f = QuicDataBlockedFrame.read(r);
      if (f.isFailure) return Result.failure(f.errorOrNull!);
      dataBlocked.add(f.valueOrNull!);
      ackEliciting = true;
      continue;
    }
    if (type == quicFrameStreamDataBlocked) {
      final f = QuicStreamDataBlockedFrame.read(r);
      if (f.isFailure) return Result.failure(f.errorOrNull!);
      streamDataBlocked.add(f.valueOrNull!);
      ackEliciting = true;
      continue;
    }
    if (type == quicFrameResetStream) {
      final f = QuicResetStreamFrame.read(r);
      if (f.isFailure) return Result.failure(f.errorOrNull!);
      resets.add(f.valueOrNull!);
      ackEliciting = true;
      continue;
    }
    if (type == quicFrameConnectionClose ||
        type == quicFrameConnectionCloseApp) {
      final f = QuicConnectionCloseFrame.read(r);
      if (f.isFailure) return Result.failure(f.errorOrNull!);
      closes.add(f.valueOrNull!);
      continue;
    }
    if (type == quicFrameStopSending) {
      final f = QuicStopSendingFrame.read(r);
      if (f.isFailure) return Result.failure(f.errorOrNull!);
      stopSending.add(f.valueOrNull!);
      ackEliciting = true;
      continue;
    }
    if (type == quicFrameMaxStreamsBidi || type == quicFrameMaxStreamsUni) {
      final f = QuicMaxStreamsFrame.read(r);
      if (f.isFailure) return Result.failure(f.errorOrNull!);
      maxStreams.add(f.valueOrNull!);
      ackEliciting = true;
      continue;
    }
    if (type == quicFrameStreamsBlockedBidi ||
        type == quicFrameStreamsBlockedUni) {
      final f = QuicStreamsBlockedFrame.read(r);
      if (f.isFailure) return Result.failure(f.errorOrNull!);
      streamsBlocked.add(f.valueOrNull!);
      ackEliciting = true;
      continue;
    }
    if (type == quicFrameNewConnectionId) {
      final f = QuicNewConnectionIdFrame.read(r);
      if (f.isFailure) return Result.failure(f.errorOrNull!);
      newConnectionIds.add(f.valueOrNull!);
      ackEliciting = true;
      continue;
    }
    if (type == quicFrameRetireConnectionId) {
      final f = QuicRetireConnectionIdFrame.read(r);
      if (f.isFailure) return Result.failure(f.errorOrNull!);
      retireConnectionIds.add(f.valueOrNull!);
      ackEliciting = true;
      continue;
    }
    if (type == quicFrameNewToken) {
      final f = QuicNewTokenFrame.read(r);
      if (f.isFailure) return Result.failure(f.errorOrNull!);
      newTokens.add(f.valueOrNull!);
      ackEliciting = true;
      continue;
    }
    if (type == quicFramePathChallenge) {
      final f = QuicPathChallengeFrame.read(r);
      if (f.isFailure) return Result.failure(f.errorOrNull!);
      pathChallenges.add(f.valueOrNull!);
      ackEliciting = true;
      continue;
    }
    if (type == quicFramePathResponse) {
      final f = QuicPathResponseFrame.read(r);
      if (f.isFailure) return Result.failure(f.errorOrNull!);
      pathResponses.add(f.valueOrNull!);
      ackEliciting = true;
      continue;
    }
    if (type == quicFrameHandshakeDone) {
      r.offset++;
      handshakeDone = true;
      ackEliciting = true;
      continue;
    }
    if (type == quicFrameDatagram || type == quicFrameDatagramLen) {
      r.offset++;
      final prefixed = type == quicFrameDatagramLen;
      Uint8List payload;
      if (prefixed) {
        final len = readVarint(r);
        if (len < 0 || r.remaining < len) {
          return Result.failure(PqTransportError.decodeFailure('datagram'));
        }
        final taken = r.take(len, PqLengthLabel.datagram);
        if (taken.isFailure) return Result.failure(taken.errorOrNull!);
        payload = taken.valueOrNull!;
      } else {
        final taken = r.take(r.remaining, PqLengthLabel.datagram);
        if (taken.isFailure) return Result.failure(taken.errorOrNull!);
        payload = taken.valueOrNull!;
      }
      final frame = QuicDatagramFrame(payload, lengthPrefixed: prefixed);
      if (frame.encodedLength > quicLocalMaxDatagramFrameSize) {
        return Result.failure(
          PqTransportError.decodeFailure('datagram too large'),
        );
      }
      datagrams.add(frame);
      ackEliciting = true;
      continue;
    }
    final multi = readQuicMultipathFrame(r);
    if (multi != null) {
      if (multi.isFailure) return Result.failure(multi.errorOrNull!);
      final frame = multi.valueOrNull!;
      multipath.add(frame);
      if (frame.ackEliciting) ackEliciting = true;
      continue;
    }
    return Result.failure(
      PqTransportError.decodeFailure(
        'unsupported quic frame 0x${type.toRadixString(16)}',
      ),
    );
  }
  return Result.success(
    QuicPayload(
      crypto: crypto,
      acks: acks,
      streams: streams,
      maxData: maxData,
      maxStreamData: maxStreamData,
      dataBlocked: dataBlocked,
      streamDataBlocked: streamDataBlocked,
      resets: resets,
      closes: closes,
      stopSending: stopSending,
      maxStreams: maxStreams,
      streamsBlocked: streamsBlocked,
      newConnectionIds: newConnectionIds,
      retireConnectionIds: retireConnectionIds,
      newTokens: newTokens,
      pathChallenges: pathChallenges,
      pathResponses: pathResponses,
      datagrams: datagrams,
      multipath: multipath,
      handshakeDone: handshakeDone,
      ackEliciting: ackEliciting,
    ),
  );
}

void writeQuicVarint(BytesBuilder b, int v) {
  if (v < 0) {
    b.addByte(0);
    return;
  }
  if (v <= quicVarintMax1) {
    b.addByte(v);
  } else if (v <= quicVarintMax2) {
    writeUint16(b, v | quicVarint2Prefix);
  } else if (v <= quicVarintMax4) {
    writeUint32(b, v | quicVarint4Prefix);
  } else {
    // `>>` is a signed int32 on dart2js, so 2^32 encoded as all zeros
    // and the initial_max_path_id limit never fired in Chrome.
    var rest = v;
    final bytes = Uint8List(8);
    for (var i = 7; i >= 0; i--) {
      bytes[i] = rest % 256;
      rest ~/= 256;
    }
    bytes[0] = (bytes[0] & quicVarintPrefixMask) | quicVarint8Prefix;
    b.add(bytes);
  }
}

int readVarint(ByteReader r) {
  if (r.remaining < 1) return -1;
  final first = r.bytes[r.offset];
  final prefix = first >> quicVarintPrefixShift;
  final len = 1 << prefix;
  if (r.remaining < len) return -1;
  var v = first & quicVarintPrefixMask;
  r.offset++;
  for (var i = 1; i < len; i++) {
    final byte = r.bytes[r.offset++];
    // Eight-byte values pass 2^31. A shift would wrap them on dart2js.
    v = len == 8 ? v * 256 + byte : (v << 8) | byte;
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
  required TransportAead aead,
}) {
  final sampleOff = pnOffset + quicPacketNumberMaxBytes;
  final sample = slice(
    packet,
    sampleOff,
    sampleOff + quicHeaderProtectionSampleBytes,
  );
  if (aead == TransportAead.chacha20Poly1305) {
    // RFC 9001 §5.4.4. Arithmetic, not `<<`, so the counter stays a
    // non-negative integer on dart2js (bitwise shifts are signed int32).
    final counter =
        sample[0] +
        (sample[1] * 256) +
        (sample[2] * 65536) +
        (sample[3] * 16777216);
    return crypto.chacha20(
      key: hpKey,
      nonce: slice(sample, 4, sample.length),
      counter: counter,
      length: 5,
    );
  }
  return crypto.aesEncryptBlock(key: hpKey, block: sample);
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
    this.keyPhase = false,
    this.dcidLength = quicShortDcidBytes,
  });

  final PqTransportCrypto crypto;
  final Uint8List key;
  final Uint8List iv;
  final Uint8List hpKey;
  final TransportAead aead;

  /// RFC 9001 §6. The short-header key phase bit.
  final bool keyPhase;

  /// DCID length on packets this codec opens. Short headers omit it.
  final int dcidLength;

  static const pnLength = 4;

  factory QuicPacketCodec.fromKeys(
    PqTransportCrypto crypto,
    QuicPacketKeys keys, {
    TransportAead aead = TransportAead.aes256Gcm,
    bool keyPhase = false,
    int dcidLength = quicShortDcidBytes,
  }) => QuicPacketCodec(
    crypto: crypto,
    key: keys.key,
    iv: keys.iv,
    hpKey: keys.hp,
    aead: aead,
    keyPhase: keyPhase,
    dcidLength: dcidLength,
  );

  Result<Uint8List, PqTransportError> protect({
    required Uint8List dcid,
    required int packetNumber,
    required Uint8List payload,
    int packetNumberLength = pnLength,
    int pathId = 0,
    bool multipath = false,
  }) {
    if (packetNumberLength < 1 ||
        packetNumberLength > quicPacketNumberMaxBytes) {
      return Result.failure(PqTransportError.decodeFailure('pn length'));
    }
    if (dcid.length > quicMaxConnectionIdBytes) {
      return Result.failure(PqTransportError.decodeFailure('dcid'));
    }
    final nonce = multipath
        ? quicMultipathNonce(iv, pathId, packetNumber)
        : quicAeadNonce(iv, packetNumber);
    final header = BytesBuilder(copy: false);
    header.addByte((keyPhase ? 0x44 : 0x40) | (packetNumberLength - 1));
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
    final pnOff = 1 + dcid.length;
    if (!quicHeaderProtectionSampleFits(packet.length, pnOff)) {
      return Result.failure(PqTransportError.decodeFailure('hp sample'));
    }
    final mask = quicHeaderProtectionMask(
      crypto: crypto,
      hpKey: hpKey,
      packet: packet,
      pnOffset: pnOff,
      aead: aead,
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

  Result<
    ({int packetNumber, Uint8List payload, bool keyPhase}),
    PqTransportError
  >
  open(Uint8List wire, {int pathId = 0, bool multipath = false}) {
    const minTail = quicPacketNumberMaxBytes + quicHeaderProtectionSampleBytes;
    if (wire.length < 1 + dcidLength + minTail) {
      return Result.failure(PqTransportError.decodeFailure('short quic'));
    }
    final packet = Uint8List.fromList(wire);
    if ((packet[0] & 0x80) != 0) {
      return Result.failure(PqTransportError.decodeFailure('not short header'));
    }
    final pnOff = 1 + dcidLength;
    if (!quicHeaderProtectionSampleFits(packet.length, pnOff)) {
      return Result.failure(PqTransportError.decodeFailure('hp sample'));
    }
    final mask = quicHeaderProtectionMask(
      crypto: crypto,
      hpKey: hpKey,
      packet: packet,
      pnOffset: pnOff,
      aead: aead,
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
        nonce: multipath
            ? quicMultipathNonce(iv, pathId, pn)
            : quicAeadNonce(iv, pn),
        ciphertextWithTag: slice(packet, pnOff + pnLen, packet.length),
        aad: hdr,
        aead: aead,
      );
      return Result.success((
        packetNumber: pn,
        payload: payload,
        keyPhase: (packet[0] & 0x04) != 0,
      ));
    } on Object catch (e) {
      return Result.failure(
        PqTransportError.decryptError('quic ${e.runtimeType}'),
      );
    }
  }
}

final class QuicMaxDataFrame {
  const QuicMaxDataFrame(this.maximum);

  final int maximum;

  Uint8List encode() {
    final b = BytesBuilder(copy: false);
    b.addByte(quicFrameMaxData);
    writeQuicVarint(b, maximum);
    return b.takeBytes();
  }

  static Result<QuicMaxDataFrame, PqTransportError> read(ByteReader r) {
    final type = r.u8();
    if (type.isFailure) return Result.failure(type.errorOrNull!);
    final maximum = readVarint(r);
    if (maximum < 0) {
      return Result.failure(PqTransportError.decodeFailure('MAX_DATA'));
    }
    return Result.success(QuicMaxDataFrame(maximum));
  }
}

final class QuicMaxStreamDataFrame {
  const QuicMaxStreamDataFrame(this.id, this.maximum);

  final int id;
  final int maximum;

  Uint8List encode() {
    final b = BytesBuilder(copy: false);
    b.addByte(quicFrameMaxStreamData);
    writeQuicVarint(b, id);
    writeQuicVarint(b, maximum);
    return b.takeBytes();
  }

  static Result<QuicMaxStreamDataFrame, PqTransportError> read(ByteReader r) {
    final type = r.u8();
    if (type.isFailure) return Result.failure(type.errorOrNull!);
    final id = readVarint(r);
    final maximum = readVarint(r);
    if (id < 0 || maximum < 0) {
      return Result.failure(PqTransportError.decodeFailure('MAX_STREAM_DATA'));
    }
    return Result.success(QuicMaxStreamDataFrame(id, maximum));
  }
}

final class QuicDataBlockedFrame {
  const QuicDataBlockedFrame(this.maximum);

  final int maximum;

  Uint8List encode() {
    final b = BytesBuilder(copy: false);
    b.addByte(quicFrameDataBlocked);
    writeQuicVarint(b, maximum);
    return b.takeBytes();
  }

  static Result<QuicDataBlockedFrame, PqTransportError> read(ByteReader r) {
    final type = r.u8();
    if (type.isFailure) return Result.failure(type.errorOrNull!);
    final maximum = readVarint(r);
    if (maximum < 0) {
      return Result.failure(PqTransportError.decodeFailure('DATA_BLOCKED'));
    }
    return Result.success(QuicDataBlockedFrame(maximum));
  }
}

final class QuicStreamDataBlockedFrame {
  const QuicStreamDataBlockedFrame(this.id, this.maximum);

  final int id;
  final int maximum;

  Uint8List encode() {
    final b = BytesBuilder(copy: false);
    b.addByte(quicFrameStreamDataBlocked);
    writeQuicVarint(b, id);
    writeQuicVarint(b, maximum);
    return b.takeBytes();
  }

  static Result<QuicStreamDataBlockedFrame, PqTransportError> read(
    ByteReader r,
  ) {
    final type = r.u8();
    if (type.isFailure) return Result.failure(type.errorOrNull!);
    final id = readVarint(r);
    final maximum = readVarint(r);
    if (id < 0 || maximum < 0) {
      return Result.failure(
        PqTransportError.decodeFailure('STREAM_DATA_BLOCKED'),
      );
    }
    return Result.success(QuicStreamDataBlockedFrame(id, maximum));
  }
}

final class QuicResetStreamFrame {
  const QuicResetStreamFrame({
    required this.id,
    required this.errorCode,
    required this.finalSize,
  });

  final int id;
  final int errorCode;
  final int finalSize;

  Uint8List encode() {
    final b = BytesBuilder(copy: false);
    b.addByte(quicFrameResetStream);
    writeQuicVarint(b, id);
    writeQuicVarint(b, errorCode);
    writeQuicVarint(b, finalSize);
    return b.takeBytes();
  }

  static Result<QuicResetStreamFrame, PqTransportError> read(ByteReader r) {
    final type = r.u8();
    if (type.isFailure) return Result.failure(type.errorOrNull!);
    final id = readVarint(r);
    final errorCode = readVarint(r);
    final finalSize = readVarint(r);
    if (id < 0 || errorCode < 0 || finalSize < 0) {
      return Result.failure(PqTransportError.decodeFailure('RESET_STREAM'));
    }
    return Result.success(
      QuicResetStreamFrame(id: id, errorCode: errorCode, finalSize: finalSize),
    );
  }
}

final class QuicConnectionCloseFrame {
  const QuicConnectionCloseFrame({
    required this.application,
    required this.errorCode,
    this.frameType = 0,
    this.reason = const [],
  });

  /// RFC 9000 §19.19. Application close is type `0x1d` and has no frame type.
  final bool application;
  final int errorCode;
  final int frameType;
  final List<int> reason;

  Uint8List encode() {
    final b = BytesBuilder(copy: false);
    b.addByte(
      application ? quicFrameConnectionCloseApp : quicFrameConnectionClose,
    );
    writeQuicVarint(b, errorCode);
    if (!application) writeQuicVarint(b, frameType);
    writeQuicVarint(b, reason.length);
    b.add(reason);
    return b.takeBytes();
  }

  static Result<QuicConnectionCloseFrame, PqTransportError> read(ByteReader r) {
    final type = r.u8();
    if (type.isFailure) return Result.failure(type.errorOrNull!);
    final application = type.valueOrNull == quicFrameConnectionCloseApp;
    final errorCode = readVarint(r);
    final frameType = application ? 0 : readVarint(r);
    final length = readVarint(r);
    if (errorCode < 0 || frameType < 0 || length < 0) {
      return Result.failure(PqTransportError.decodeFailure('CONNECTION_CLOSE'));
    }
    final reason = r.take(length, PqLengthLabel.datagram);
    if (reason.isFailure) return Result.failure(reason.errorOrNull!);
    return Result.success(
      QuicConnectionCloseFrame(
        application: application,
        errorCode: errorCode,
        frameType: frameType,
        reason: reason.valueOrNull!,
      ),
    );
  }
}

/// How many bytes of one write fit the peer's advertised credit.
final class QuicSendBudget {
  const QuicSendBudget({
    required this.allowed,
    required this.streamBlocked,
    required this.connectionBlocked,
  });

  final int allowed;
  final bool streamBlocked;
  final bool connectionBlocked;

  bool get blocked => streamBlocked || connectionBlocked;
}

/// RFC 9000 §4 connection and stream data limits.
///
/// Send credit is what the peer has advertised. Receive credit is what
/// this endpoint advertises. A limit only moves forward. [onConsumed]
/// advertises [window] bytes beyond the bytes the application has read.
/// [window] `0` does not send MAX frames. There is no hidden multiplier.
final class QuicFlowControl {
  QuicFlowControl({
    int maxData = quicMaxDataDefault,
    int maxStreamData = quicMaxStreamDataDefault,
    int? sendMaxData,
    int? sendMaxStreamData,
    int? recvMaxData,
    int? recvMaxStreamData,
  }) : _peerMaxData = sendMaxData ?? maxData,
       _localMaxData = recvMaxData ?? maxData,
       _initialSendStream = sendMaxStreamData ?? maxStreamData,
       _initialRecvStream = recvMaxStreamData ?? maxStreamData;

  int _peerMaxData;
  int _localMaxData;
  int _initialSendStream;
  final int _initialRecvStream;
  final Map<int, int> _peerStream = {};
  final Map<int, int> _localStream = {};
  final Map<int, int> _sendHigh = {};
  final Map<int, int> _recvHigh = {};
  var _sendSum = 0;
  var _recvSum = 0;
  var _consumedConn = 0;
  final Map<int, int> _consumedStream = {};

  int get peerMaxData => _peerMaxData;
  int get localMaxData => _localMaxData;

  int peerStreamMax(int id) => _peerStream[id] ?? _initialSendStream;

  int localStreamMax(int id) => _localStream[id] ?? _initialRecvStream;

  QuicSendBudget budget({
    required int streamId,
    required int offset,
    required int length,
  }) {
    if (length < 0) {
      return const QuicSendBudget(
        allowed: 0,
        streamBlocked: true,
        connectionBlocked: true,
      );
    }
    final oldHigh = _sendHigh[streamId] ?? 0;
    final streamLimit = peerStreamMax(streamId);
    var allowed = 0;
    var streamBlocked = false;
    var connectionBlocked = false;
    var high = oldHigh;
    var sum = _sendSum;
    for (var i = 0; i < length; i++) {
      final end = offset + i + 1;
      final nextHigh = end > high ? end : high;
      if (nextHigh > streamLimit) {
        streamBlocked = true;
        break;
      }
      final nextSum = sum - high + nextHigh;
      if (nextSum > _peerMaxData) {
        connectionBlocked = true;
        break;
      }
      high = nextHigh;
      sum = nextSum;
      allowed++;
    }
    return QuicSendBudget(
      allowed: allowed,
      streamBlocked: streamBlocked,
      connectionBlocked: connectionBlocked,
    );
  }

  void commitSend(int streamId, int endOffset) {
    final old = _sendHigh[streamId] ?? 0;
    if (endOffset <= old) return;
    _sendSum += endOffset - old;
    _sendHigh[streamId] = endOffset;
  }

  /// Absolute end offset of received STREAM data. A retransmission of
  /// the same bytes does not consume the limit twice. Past either limit
  /// is FLOW_CONTROL_ERROR and does not move the high-water mark.
  Result<void, PqTransportError> receive(int streamId, int endOffset) {
    final old = _recvHigh[streamId] ?? 0;
    final high = endOffset > old ? endOffset : old;
    if (high > localStreamMax(streamId)) {
      return Result.failure(
        PqTransportError.flowControl('MAX_STREAM_DATA exceeded'),
      );
    }
    final next = _recvSum - old + high;
    if (next > _localMaxData) {
      return Result.failure(PqTransportError.flowControl('MAX_DATA exceeded'));
    }
    _recvHigh[streamId] = high;
    _recvSum = next;
    return const Result.success(null);
  }

  void adoptPeerInitial({required int maxData, required int maxStreamData}) {
    _peerMaxData = maxData;
    _initialSendStream = maxStreamData;
    _peerStream.clear();
  }

  void onMaxData(int limit) {
    if (limit > _peerMaxData) _peerMaxData = limit;
  }

  void onMaxStreamData(int id, int limit) {
    if (limit > peerStreamMax(id)) _peerStream[id] = limit;
  }

  /// Application read of [bytes]. When [window] is positive, advertise
  /// `consumed + window` if that is above the current receive limit.
  List<Uint8List> onConsumed({
    required int streamId,
    required int bytes,
    required int window,
  }) {
    if (bytes < 0) return const [];
    _consumedStream[streamId] = (_consumedStream[streamId] ?? 0) + bytes;
    _consumedConn += bytes;
    if (window <= 0 || bytes == 0) return const [];
    final frames = <Uint8List>[];
    final nextStream = _consumedStream[streamId]! + window;
    if (nextStream > localStreamMax(streamId)) {
      _localStream[streamId] = nextStream;
      frames.add(QuicMaxStreamDataFrame(streamId, nextStream).encode());
    }
    final nextConn = _consumedConn + window;
    if (nextConn > _localMaxData) {
      _localMaxData = nextConn;
      frames.add(QuicMaxDataFrame(nextConn).encode());
    }
    return frames;
  }
}

final class QuicStopSendingFrame {
  const QuicStopSendingFrame(this.id, this.errorCode);

  final int id;
  final int errorCode;

  Uint8List encode() {
    final b = BytesBuilder(copy: false);
    b.addByte(quicFrameStopSending);
    writeQuicVarint(b, id);
    writeQuicVarint(b, errorCode);
    return b.takeBytes();
  }

  static Result<QuicStopSendingFrame, PqTransportError> read(ByteReader r) {
    final type = r.u8();
    if (type.isFailure) return Result.failure(type.errorOrNull!);
    final id = readVarint(r);
    final code = readVarint(r);
    if (id < 0 || code < 0) {
      return Result.failure(PqTransportError.decodeFailure('stop_sending'));
    }
    return Result.success(QuicStopSendingFrame(id, code));
  }
}

final class QuicMaxStreamsFrame {
  const QuicMaxStreamsFrame({
    required this.bidirectional,
    required this.maximum,
  });

  final bool bidirectional;
  final int maximum;

  Uint8List encode() {
    final b = BytesBuilder(copy: false);
    b.addByte(bidirectional ? quicFrameMaxStreamsBidi : quicFrameMaxStreamsUni);
    writeQuicVarint(b, maximum);
    return b.takeBytes();
  }

  static Result<QuicMaxStreamsFrame, PqTransportError> read(ByteReader r) {
    final type = r.u8();
    if (type.isFailure) return Result.failure(type.errorOrNull!);
    final value = type.valueOrNull!;
    final maximum = readVarint(r);
    if (maximum < 0) {
      return Result.failure(PqTransportError.decodeFailure('max_streams'));
    }
    return Result.success(
      QuicMaxStreamsFrame(
        bidirectional: value == quicFrameMaxStreamsBidi,
        maximum: maximum,
      ),
    );
  }
}

final class QuicStreamsBlockedFrame {
  const QuicStreamsBlockedFrame({
    required this.bidirectional,
    required this.maximum,
  });

  final bool bidirectional;
  final int maximum;

  Uint8List encode() {
    final b = BytesBuilder(copy: false);
    b.addByte(
      bidirectional ? quicFrameStreamsBlockedBidi : quicFrameStreamsBlockedUni,
    );
    writeQuicVarint(b, maximum);
    return b.takeBytes();
  }

  static Result<QuicStreamsBlockedFrame, PqTransportError> read(ByteReader r) {
    final type = r.u8();
    if (type.isFailure) return Result.failure(type.errorOrNull!);
    final value = type.valueOrNull!;
    final maximum = readVarint(r);
    if (maximum < 0) {
      return Result.failure(PqTransportError.decodeFailure('streams_blocked'));
    }
    return Result.success(
      QuicStreamsBlockedFrame(
        bidirectional: value == quicFrameStreamsBlockedBidi,
        maximum: maximum,
      ),
    );
  }
}

final class QuicNewConnectionIdFrame {
  const QuicNewConnectionIdFrame({
    required this.sequence,
    required this.retirePriorTo,
    required this.connectionId,
    required this.statelessResetToken,
  });

  final int sequence;
  final int retirePriorTo;
  final Uint8List connectionId;
  final Uint8List statelessResetToken;

  Uint8List encode() {
    final b = BytesBuilder(copy: false);
    b.addByte(quicFrameNewConnectionId);
    writeQuicVarint(b, sequence);
    writeQuicVarint(b, retirePriorTo);
    b.addByte(connectionId.length);
    b.add(connectionId);
    b.add(statelessResetToken);
    return b.takeBytes();
  }

  static Result<QuicNewConnectionIdFrame, PqTransportError> read(ByteReader r) {
    final type = r.u8();
    if (type.isFailure) return Result.failure(type.errorOrNull!);
    final sequence = readVarint(r);
    final retire = readVarint(r);
    final len = r.u8();
    if (sequence < 0 || retire < 0 || len.isFailure || retire > sequence) {
      return Result.failure(
        PqTransportError.decodeFailure('new_connection_id'),
      );
    }
    final n = len.valueOrNull!;
    if (n < 1 || n > quicMaxConnectionIdBytes) {
      return Result.failure(PqTransportError.decodeFailure('connection id'));
    }
    final cid = r.take(n, PqLengthLabel.tlsExtension);
    if (cid.isFailure) return Result.failure(cid.errorOrNull!);
    final token = r.take(
      quicStatelessResetTokenBytes,
      PqLengthLabel.tlsExtension,
    );
    if (token.isFailure) return Result.failure(token.errorOrNull!);
    return Result.success(
      QuicNewConnectionIdFrame(
        sequence: sequence,
        retirePriorTo: retire,
        connectionId: cid.valueOrNull!,
        statelessResetToken: token.valueOrNull!,
      ),
    );
  }
}

final class QuicRetireConnectionIdFrame {
  const QuicRetireConnectionIdFrame(this.sequence);

  final int sequence;

  Uint8List encode() {
    final b = BytesBuilder(copy: false);
    b.addByte(quicFrameRetireConnectionId);
    writeQuicVarint(b, sequence);
    return b.takeBytes();
  }

  static Result<QuicRetireConnectionIdFrame, PqTransportError> read(
    ByteReader r,
  ) {
    final type = r.u8();
    if (type.isFailure) return Result.failure(type.errorOrNull!);
    final sequence = readVarint(r);
    if (sequence < 0) {
      return Result.failure(
        PqTransportError.decodeFailure('retire_connection_id'),
      );
    }
    return Result.success(QuicRetireConnectionIdFrame(sequence));
  }
}

final class QuicNewTokenFrame {
  const QuicNewTokenFrame(this.token);

  final Uint8List token;

  Uint8List encode() {
    final b = BytesBuilder(copy: false);
    b.addByte(quicFrameNewToken);
    writeQuicVarint(b, token.length);
    b.add(token);
    return b.takeBytes();
  }

  static Result<QuicNewTokenFrame, PqTransportError> read(ByteReader r) {
    final type = r.u8();
    if (type.isFailure) return Result.failure(type.errorOrNull!);
    final len = readVarint(r);
    if (len < 1) {
      return Result.failure(PqTransportError.decodeFailure('new_token'));
    }
    final token = r.take(len, PqLengthLabel.tlsExtension);
    if (token.isFailure) return Result.failure(token.errorOrNull!);
    return Result.success(QuicNewTokenFrame(token.valueOrNull!));
  }
}

final class QuicPathChallengeFrame {
  const QuicPathChallengeFrame(this.data);

  final Uint8List data;

  Uint8List encode() {
    final b = BytesBuilder(copy: false);
    b.addByte(quicFramePathChallenge);
    b.add(data);
    return b.takeBytes();
  }

  static Result<QuicPathChallengeFrame, PqTransportError> read(ByteReader r) {
    final type = r.u8();
    if (type.isFailure) return Result.failure(type.errorOrNull!);
    final data = r.take(quicPathChallengeBytes, PqLengthLabel.tlsExtension);
    if (data.isFailure) return Result.failure(data.errorOrNull!);
    return Result.success(QuicPathChallengeFrame(data.valueOrNull!));
  }
}

final class QuicPathResponseFrame {
  const QuicPathResponseFrame(this.data);

  final Uint8List data;

  Uint8List encode() {
    final b = BytesBuilder(copy: false);
    b.addByte(quicFramePathResponse);
    b.add(data);
    return b.takeBytes();
  }

  static Result<QuicPathResponseFrame, PqTransportError> read(ByteReader r) {
    final type = r.u8();
    if (type.isFailure) return Result.failure(type.errorOrNull!);
    final data = r.take(quicPathChallengeBytes, PqLengthLabel.tlsExtension);
    if (data.isFailure) return Result.failure(data.errorOrNull!);
    return Result.success(QuicPathResponseFrame(data.valueOrNull!));
  }
}
