import 'dart:typed_data';

import 'package:swissarmyknife/swissarmyknife.dart';

import '../core/bytes.dart';
import '../core/errors.dart';
import '../core/lengths.dart';
import 'packet.dart';

/// RFC 10069 §2.4. 96-bit path-and-packet-number, left-padded with
/// zeros when the IV is longer than 12 bytes, then XORed with the IV.
///
/// Path 0 is the RFC 9001 nonce: the path identifier is zero, so only
/// the packet number changes the IV. A path identifier above 2^32-1
/// is rejected by the transport parameter, not by this function.
Uint8List quicMultipathNonce(Uint8List iv, int pathId, int packetNumber) {
  final nonce = Uint8List.fromList(iv);
  final ppn = Uint8List(12);
  ppn[0] = (pathId >> 24) & 0xff;
  ppn[1] = (pathId >> 16) & 0xff;
  ppn[2] = (pathId >> 8) & 0xff;
  ppn[3] = pathId & 0xff;
  for (var i = 0; i < 8; i++) {
    ppn[11 - i] = (packetNumber >> (8 * i)) & 0xff;
  }
  // The two bits between the path identifier and the 62-bit packet number
  // are zero. A packet number that already fits in 62 bits needs no mask.
  final start = nonce.length - ppn.length;
  if (start >= 0) {
    for (var i = 0; i < ppn.length; i++) {
      nonce[start + i] ^= ppn[i];
    }
  } else {
    for (var i = 0; i < nonce.length; i++) {
      nonce[i] ^= ppn[i - start];
    }
  }
  return nonce;
}

/// True when [a] and [b] are the same nonce. Used to prove path 0.
bool quicNonceEqual(Uint8List a, Uint8List b) {
  if (a.length != b.length) return false;
  for (var i = 0; i < a.length; i++) {
    if (a[i] != b[i]) return false;
  }
  return true;
}

/// One RFC 10069 frame. [ackEliciting] follows the ACK rule: PATH_ACK
/// does not elicit an acknowledgement. Every other frame does.
sealed class QuicMultipathFrame {
  const QuicMultipathFrame();

  int get type;
  bool get ackEliciting =>
      type != quicFramePathAck && type != quicFramePathAckEcn;

  Uint8List encode();
}

final class QuicPathAckFrame extends QuicMultipathFrame {
  const QuicPathAckFrame({
    required this.pathId,
    required this.largest,
    required this.delay,
    required this.firstRange,
    this.additional = const [],
    this.ecn = false,
    this.ect0 = 0,
    this.ect1 = 0,
    this.ce = 0,
  });

  final int pathId;
  final int largest;
  final int delay;
  final int firstRange;
  final List<(int gap, int range)> additional;
  final bool ecn;
  final int ect0;
  final int ect1;
  final int ce;

  @override
  int get type => ecn ? quicFramePathAckEcn : quicFramePathAck;

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

  @override
  Uint8List encode() {
    final b = BytesBuilder(copy: false);
    writeQuicVarint(b, type);
    writeQuicVarint(b, pathId);
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
}

final class QuicPathAbandonFrame extends QuicMultipathFrame {
  const QuicPathAbandonFrame(this.pathId, this.errorCode);

  final int pathId;
  final int errorCode;

  @override
  int get type => quicFramePathAbandon;

  @override
  Uint8List encode() {
    final b = BytesBuilder(copy: false);
    writeQuicVarint(b, type);
    writeQuicVarint(b, pathId);
    writeQuicVarint(b, errorCode);
    return b.takeBytes();
  }
}

final class QuicPathStatusFrame extends QuicMultipathFrame {
  const QuicPathStatusFrame({
    required this.pathId,
    required this.sequence,
    required this.backup,
  });

  final int pathId;
  final int sequence;
  final bool backup;

  @override
  int get type =>
      backup ? quicFramePathStatusBackup : quicFramePathStatusAvailable;

  @override
  Uint8List encode() {
    final b = BytesBuilder(copy: false);
    writeQuicVarint(b, type);
    writeQuicVarint(b, pathId);
    writeQuicVarint(b, sequence);
    return b.takeBytes();
  }
}

final class QuicPathNewConnectionIdFrame extends QuicMultipathFrame {
  const QuicPathNewConnectionIdFrame({
    required this.pathId,
    required this.sequence,
    required this.retirePriorTo,
    required this.connectionId,
    required this.statelessResetToken,
  });

  final int pathId;
  final int sequence;
  final int retirePriorTo;
  final Uint8List connectionId;
  final Uint8List statelessResetToken;

  @override
  int get type => quicFramePathNewConnectionId;

  @override
  Uint8List encode() {
    final b = BytesBuilder(copy: false);
    writeQuicVarint(b, type);
    writeQuicVarint(b, pathId);
    writeQuicVarint(b, sequence);
    writeQuicVarint(b, retirePriorTo);
    b.addByte(connectionId.length);
    b.add(connectionId);
    b.add(statelessResetToken);
    return b.takeBytes();
  }
}

final class QuicPathRetireConnectionIdFrame extends QuicMultipathFrame {
  const QuicPathRetireConnectionIdFrame(this.pathId, this.sequence);

  final int pathId;
  final int sequence;

  @override
  int get type => quicFramePathRetireConnectionId;

  @override
  Uint8List encode() {
    final b = BytesBuilder(copy: false);
    writeQuicVarint(b, type);
    writeQuicVarint(b, pathId);
    writeQuicVarint(b, sequence);
    return b.takeBytes();
  }
}

final class QuicMaxPathIdFrame extends QuicMultipathFrame {
  const QuicMaxPathIdFrame(this.maximum);

  final int maximum;

  @override
  int get type => quicFrameMaxPathId;

  @override
  Uint8List encode() {
    final b = BytesBuilder(copy: false);
    writeQuicVarint(b, type);
    writeQuicVarint(b, maximum);
    return b.takeBytes();
  }
}

final class QuicPathsBlockedFrame extends QuicMultipathFrame {
  const QuicPathsBlockedFrame(this.maximum);

  final int maximum;

  @override
  int get type => quicFramePathsBlocked;

  @override
  Uint8List encode() {
    final b = BytesBuilder(copy: false);
    writeQuicVarint(b, type);
    writeQuicVarint(b, maximum);
    return b.takeBytes();
  }
}

final class QuicPathCidsBlockedFrame extends QuicMultipathFrame {
  const QuicPathCidsBlockedFrame(this.pathId, this.nextSequence);

  final int pathId;
  final int nextSequence;

  @override
  int get type => quicFramePathCidsBlocked;

  @override
  Uint8List encode() {
    final b = BytesBuilder(copy: false);
    writeQuicVarint(b, type);
    writeQuicVarint(b, pathId);
    writeQuicVarint(b, nextSequence);
    return b.takeBytes();
  }
}

/// Reads one multipath frame. The reader is positioned at the type.
/// Returns null when the next byte is not a multipath type, so the
/// QUIC payload parser can keep its existing single-byte dispatch.
Result<QuicMultipathFrame, PqTransportError>? readQuicMultipathFrame(
  ByteReader r,
) {
  if (r.remaining < 1) return null;
  final first = r.bytes[r.offset];
  if (first != quicFramePathAck &&
      first != quicFramePathAckEcn &&
      first < 0x40) {
    return null;
  }
  final start = r.offset;
  final type = readVarint(r);
  if (type < 0) {
    return Result.failure(PqTransportError.decodeFailure('multipath type'));
  }
  if (!_multipathType(type)) {
    r.offset = start;
    return null;
  }
  switch (type) {
    case quicFramePathAck:
    case quicFramePathAckEcn:
      final pathId = readVarint(r);
      final largest = readVarint(r);
      final delay = readVarint(r);
      final count = readVarint(r);
      final firstRange = readVarint(r);
      if (pathId < 0 ||
          largest < 0 ||
          delay < 0 ||
          count < 0 ||
          firstRange < 0) {
        return Result.failure(PqTransportError.decodeFailure('PATH_ACK'));
      }
      final extra = <(int, int)>[];
      for (var i = 0; i < count; i++) {
        final gap = readVarint(r);
        final range = readVarint(r);
        if (gap < 0 || range < 0) {
          return Result.failure(PqTransportError.decodeFailure('PATH_ACK'));
        }
        extra.add((gap, range));
      }
      var ect0 = 0;
      var ect1 = 0;
      var ce = 0;
      final ecn = type == quicFramePathAckEcn;
      if (ecn) {
        ect0 = readVarint(r);
        ect1 = readVarint(r);
        ce = readVarint(r);
        if (ect0 < 0 || ect1 < 0 || ce < 0) {
          return Result.failure(PqTransportError.decodeFailure('PATH_ACK'));
        }
      }
      return Result.success(
        QuicPathAckFrame(
          pathId: pathId,
          largest: largest,
          delay: delay,
          firstRange: firstRange,
          additional: extra,
          ecn: ecn,
          ect0: ect0,
          ect1: ect1,
          ce: ce,
        ),
      );
    case quicFramePathAbandon:
      final pathId = readVarint(r);
      final code = readVarint(r);
      if (pathId < 0 || code < 0) {
        return Result.failure(PqTransportError.decodeFailure('PATH_ABANDON'));
      }
      return Result.success(QuicPathAbandonFrame(pathId, code));
    case quicFramePathStatusBackup:
    case quicFramePathStatusAvailable:
      final pathId = readVarint(r);
      final sequence = readVarint(r);
      if (pathId < 0 || sequence < 0) {
        return Result.failure(PqTransportError.decodeFailure('PATH_STATUS'));
      }
      return Result.success(
        QuicPathStatusFrame(
          pathId: pathId,
          sequence: sequence,
          backup: type == quicFramePathStatusBackup,
        ),
      );
    case quicFramePathNewConnectionId:
      final pathId = readVarint(r);
      final sequence = readVarint(r);
      final retire = readVarint(r);
      final len = r.u8();
      if (pathId < 0 ||
          sequence < 0 ||
          retire < 0 ||
          len.isFailure ||
          len.valueOrNull! == 0 ||
          len.valueOrNull! > quicMaxConnectionIdBytes) {
        return Result.failure(
          PqTransportError.decodeFailure('PATH_NEW_CONNECTION_ID'),
        );
      }
      final cid = r.take(len.valueOrNull!, PqLengthLabel.datagram);
      if (cid.isFailure) return Result.failure(cid.errorOrNull!);
      final token = r.take(
        quicStatelessResetTokenBytes,
        PqLengthLabel.datagram,
      );
      if (token.isFailure) return Result.failure(token.errorOrNull!);
      return Result.success(
        QuicPathNewConnectionIdFrame(
          pathId: pathId,
          sequence: sequence,
          retirePriorTo: retire,
          connectionId: cid.valueOrNull!,
          statelessResetToken: token.valueOrNull!,
        ),
      );
    case quicFramePathRetireConnectionId:
      final pathId = readVarint(r);
      final sequence = readVarint(r);
      if (pathId < 0 || sequence < 0) {
        return Result.failure(
          PqTransportError.decodeFailure('PATH_RETIRE_CONNECTION_ID'),
        );
      }
      return Result.success(QuicPathRetireConnectionIdFrame(pathId, sequence));
    case quicFrameMaxPathId:
      final maximum = readVarint(r);
      if (maximum < 0 || maximum > quicMaxPathId) {
        return Result.failure(PqTransportError.decodeFailure('MAX_PATH_ID'));
      }
      return Result.success(QuicMaxPathIdFrame(maximum));
    case quicFramePathsBlocked:
      final maximum = readVarint(r);
      if (maximum < 0) {
        return Result.failure(PqTransportError.decodeFailure('PATHS_BLOCKED'));
      }
      return Result.success(QuicPathsBlockedFrame(maximum));
    case quicFramePathCidsBlocked:
      final pathId = readVarint(r);
      final next = readVarint(r);
      if (pathId < 0 || next < 0) {
        return Result.failure(
          PqTransportError.decodeFailure('PATH_CIDS_BLOCKED'),
        );
      }
      return Result.success(QuicPathCidsBlockedFrame(pathId, next));
    default:
      r.offset = start;
      return null;
  }
}

bool _multipathType(int type) =>
    type == quicFramePathAck ||
    type == quicFramePathAckEcn ||
    type == quicFramePathAbandon ||
    type == quicFramePathStatusBackup ||
    type == quicFramePathStatusAvailable ||
    type == quicFramePathNewConnectionId ||
    type == quicFramePathRetireConnectionId ||
    type == quicFrameMaxPathId ||
    type == quicFramePathsBlocked ||
    type == quicFramePathCidsBlocked;

/// RFC 10069 path table. Scheduling across paths is not specified by
/// the RFC and is left to the caller. This object enforces the
/// identifier limits, the non-decreasing MAX_PATH_ID rule, and the
/// per-path connection-ID association.
final class QuicMultipath {
  QuicMultipath({required this.localInitialMax, required this.peerInitialMax})
    : localMax = localInitialMax,
      peerMax = peerInitialMax;

  final int localInitialMax;
  final int peerInitialMax;
  int localMax;
  int peerMax;

  final Set<int> abandoned = {};
  final Map<int, bool> backup = {};
  final Map<int, int> statusSequence = {};

  /// Connection IDs the peer asked us to send to, keyed by path.
  final Map<int, Uint8List> peerCidByPath = {};

  /// Connection IDs this endpoint issued, keyed by the CID bytes.
  final Map<String, int> issuedPathByCid = {};
  final List<QuicMultipathFrame> received = [];

  int get openLimit => localMax < peerMax ? localMax : peerMax;

  bool pathAllowed(int pathId) =>
      pathId >= 0 && pathId <= openLimit && !abandoned.contains(pathId);

  /// Applies one received frame. A MAX_PATH_ID below the advertised
  /// initial value is an error. A reordered MAX_PATH_ID below the
  /// highest value already accepted is ignored.
  Result<void, PqTransportError> apply(QuicMultipathFrame frame) {
    switch (frame) {
      case QuicMaxPathIdFrame():
        if (frame.maximum < peerInitialMax || frame.maximum > quicMaxPathId) {
          return Result.failure(PqTransportError.decodeFailure('MAX_PATH_ID'));
        }
        if (frame.maximum >= peerMax) peerMax = frame.maximum;
      case QuicPathAbandonFrame():
        if (frame.pathId > openLimit) {
          return Result.failure(PqTransportError.decodeFailure('PATH_ABANDON'));
        }
        abandoned.add(frame.pathId);
      case QuicPathStatusFrame():
        final prior = statusSequence[frame.pathId] ?? -1;
        if (frame.sequence >= prior) {
          statusSequence[frame.pathId] = frame.sequence;
          backup[frame.pathId] = frame.backup;
        }
      case QuicPathNewConnectionIdFrame():
        if (frame.pathId > peerMax) {
          return Result.failure(
            PqTransportError.decodeFailure('PATH_NEW_CONNECTION_ID'),
          );
        }
        peerCidByPath[frame.pathId] = frame.connectionId;
      case QuicPathAckFrame():
      case QuicPathRetireConnectionIdFrame():
      case QuicPathsBlockedFrame():
      case QuicPathCidsBlockedFrame():
        break;
    }
    received.add(frame);
    return const Result.success(null);
  }

  void rememberIssued(int pathId, Uint8List cid) {
    issuedPathByCid[_cidKey(cid)] = pathId;
  }

  int? pathForCid(Uint8List cid) => issuedPathByCid[_cidKey(cid)];

  static String _cidKey(Uint8List cid) => String.fromCharCodes(cid);
}
