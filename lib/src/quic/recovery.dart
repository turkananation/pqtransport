import 'dart:typed_data';

import 'package:swissarmyknife/swissarmyknife.dart';

import '../core/errors.dart';
import '../core/lengths.dart';
import 'congestion.dart';
import 'packet.dart';

/// Clock for loss detection. Tests use [QuicManualClock] so a dropped
/// packet can cross the PTO without waiting on the wall.
abstract interface class QuicClock {
  DateTime now();
}

/// Wall clock. Pair this with [PqQuicConn.bindLossTimer] in a process
/// that should retransmit on its own.
final class QuicSystemClock implements QuicClock {
  const QuicSystemClock();

  @override
  DateTime now() => DateTime.now();
}

/// Clock that moves only when [advance] is called.
final class QuicManualClock implements QuicClock {
  QuicManualClock([DateTime? start]) : _now = start ?? DateTime.utc(2026);

  DateTime _now;

  @override
  DateTime now() => _now;

  void advance(Duration by) {
    if (by.isNegative) {
      throw ArgumentError.value(by, 'by', 'clock does not move backwards');
    }
    _now = _now.add(by);
  }
}

/// RFC 9000 §12.3 packet number spaces. Numbers are never reused in a space.
///
/// 0-RTT is not a space this stack implements (LIM-05).
enum QuicPacketNumberSpace { initial, handshake, application }

/// Bytes that must be carried in a new packet when the original is lost
/// (RFC 9000 §13.3). The lost datagram itself is not sent again.
sealed class QuicRetransmittable {
  const QuicRetransmittable();

  QuicPacketNumberSpace get space;

  /// Identity of the data, not of the packet that carried it.
  String get token;

  Uint8List encode();
}

final class QuicRetransmitCrypto extends QuicRetransmittable {
  QuicRetransmitCrypto({
    required this.space,
    required this.offset,
    required this.data,
  });

  @override
  final QuicPacketNumberSpace space;
  final int offset;
  final Uint8List data;

  @override
  String get token => 'c:${space.name}:$offset:${data.length}';

  @override
  Uint8List encode() => QuicCryptoFrame(offset: offset, data: data).encode();
}

final class QuicRetransmitStream extends QuicRetransmittable {
  QuicRetransmitStream({
    required this.streamId,
    required this.offset,
    required this.data,
    this.fin = false,
  }) : space = QuicPacketNumberSpace.application;

  @override
  final QuicPacketNumberSpace space;
  final int streamId;
  final int offset;
  final Uint8List data;
  final bool fin;

  @override
  String get token => 's:$streamId:$offset:${data.length}:${fin ? 1 : 0}';

  @override
  Uint8List encode() => QuicStreamFrame(
    id: streamId,
    offset: offset,
    data: data,
    fin: fin,
  ).encode();
}

/// Ack-eliciting probe with no stream or CRYPTO bytes (RFC 9000 §19.2).
final class QuicRetransmitPing extends QuicRetransmittable {
  QuicRetransmitPing(this.space) : id = _nextPing++;

  static var _nextPing = 0;

  @override
  final QuicPacketNumberSpace space;
  final int id;

  @override
  String get token => 'p:$id';

  @override
  Uint8List encode() => Uint8List.fromList([quicFramePing]);
}

/// One packet remembered by loss detection.
final class QuicSentPacket {
  QuicSentPacket({
    required this.space,
    required this.packetNumber,
    required this.timeSent,
    required this.sentBytes,
    required this.ackEliciting,
    required this.inFlight,
    required this.appLimited,
    required this.frames,
  });

  final QuicPacketNumberSpace space;
  final int packetNumber;
  final DateTime timeSent;
  final int sentBytes;
  final bool ackEliciting;
  bool inFlight;
  final bool appLimited;
  final List<QuicRetransmittable> frames;
  var acknowledged = false;
  var declaredLost = false;
}

/// What changed when an acknowledgement arrived or the loss timer fired.
final class QuicRecoveryEvent {
  const QuicRecoveryEvent({
    this.newlyAcked = const [],
    this.lost = const [],
    this.retransmit = const [],
    this.probeSpace,
    this.persistentCongestion = false,
    this.congestionProbe = false,
  });

  final List<QuicSentPacket> newlyAcked;

  /// Packets declared lost. Their packet numbers stay retired.
  final List<QuicSentPacket> lost;

  /// CRYPTO and STREAM data to seal into a new packet number.
  final List<QuicRetransmittable> retransmit;

  /// Non-null when the caller must send one ack-eliciting probe in this
  /// space. PTO does not declare those packets lost (RFC 9002 §6.2).
  final QuicPacketNumberSpace? probeSpace;

  final bool persistentCongestion;

  /// One packet may ignore the congestion window (§7.3.2).
  final bool congestionProbe;

  static const empty = QuicRecoveryEvent();
}

/// RFC 9002 loss detection, PTO, and the NewReno window.
///
/// Compose this without a connection when another object owns the sockets.
/// Feed acknowledgements built by [QuicAckProcessor]. Newly acknowledged
/// packet numbers are the ones [QuicAckProcessor.applyAck] removes from
/// that processor's in-flight set — one processor per packet number space.
///
/// [PqQuicConn] does not mint Handshake packet-protection keys. The
/// Handshake space is still tracked so a caller that does have those keys
/// can record packets here. Call [markHandshakeKeysAvailable] when they
/// exist so an anti-deadlock probe can use that space (Appendix A.9).
///
/// Compose this without a connection:
/// 1. [peekPacketNumber], seal that number, then [canSend] the datagram.
/// 2. [allocatePacketNumber] (same number) and [onPacketSent].
/// 3. [onAck] with one acknowledgement per [QuicPacketNumberSpace].
/// 4. When [lossDetectionDeadline] is due, [onLossDetectionTimeout].
/// 5. Seal [QuicRecoveryEvent.retransmit] under a new packet number.
///    A lost number stays retired (RFC 9000 §12.3, §13.3).
///
/// ECN, connection migration, and multipath are not implemented.
/// The anti-amplification limit (RFC 9000 §8.1, RFC 9002 §6.2.2.1) is not
/// enforced: a raw ML-DSA server flight does not fit in three times one
/// client Initial. A silent peer still stops, because [maxPtoCount] stands
/// in for the idle timeout this stack does not negotiate.
/// Application Data PTO is disarmed until [markHandshakeConfirmed]
/// (RFC 9002 §6.2.1).
final class QuicLossRecovery {
  QuicLossRecovery({
    QuicClock? clock,
    this.maxDatagramSize = quicMinClientInitialUdpBytes,
    int maxAckDelay = quicMaxAckDelayMicros,
    this.maxPtoCount = quicMaxPtoCount,
    bool isServer = false,
  }) : clock = clock ?? const QuicSystemClock(),
       _maxAckDelay = maxAckDelay,
       // Public parameter stays `isServer`.
       // ignore: prefer_initializing_formals
       _isServer = isServer,
       controller = QuicNewReno(
         maxDatagramSize: maxDatagramSize,
         now: (clock ?? const QuicSystemClock()).now,
       ) {
    if (maxPtoCount < 1) {
      throw ArgumentError.value(maxPtoCount, 'maxPtoCount', 'at least one');
    }
    if (maxAckDelay < 0) {
      throw ArgumentError.value(maxAckDelay, 'maxAckDelay', 'negative');
    }
  }

  final QuicClock clock;
  final int maxDatagramSize;
  final int maxPtoCount;
  final int _maxAckDelay;
  final bool _isServer;

  /// The named controller (RFC 9002 §7 NewReno).
  final QuicNewReno controller;

  final Map<QuicPacketNumberSpace, QuicAckProcessor> _sentAck = {
    for (final space in QuicPacketNumberSpace.values) space: QuicAckProcessor(),
  };
  final Map<QuicPacketNumberSpace, Map<int, QuicSentPacket>> _outstanding = {
    for (final space in QuicPacketNumberSpace.values)
      space: <int, QuicSentPacket>{},
  };
  final Map<QuicPacketNumberSpace, Map<int, QuicSentPacket>> _lost = {
    for (final space in QuicPacketNumberSpace.values)
      space: <int, QuicSentPacket>{},
  };
  final Map<QuicPacketNumberSpace, Set<int>> _everSent = {
    for (final space in QuicPacketNumberSpace.values) space: <int>{},
  };
  final Map<QuicPacketNumberSpace, int> _nextPn = {
    for (final space in QuicPacketNumberSpace.values) space: 0,
  };
  final Map<QuicPacketNumberSpace, DateTime?> _lossTime = {
    for (final space in QuicPacketNumberSpace.values) space: null,
  };
  final Map<QuicPacketNumberSpace, DateTime?> _lastAckEliciting = {
    for (final space in QuicPacketNumberSpace.values) space: null,
  };
  final Map<QuicPacketNumberSpace, int?> _largestAcked = {
    for (final space in QuicPacketNumberSpace.values) space: null,
  };
  final List<QuicSentPacket> _history = [];
  final Set<String> _delivered = {};

  int _smoothedRtt = quicInitialRttMicros;
  int _rttvar = quicInitialRttMicros ~/ 2;
  int _latestRtt = quicInitialRttMicros;
  int _minRtt = quicInitialRttMicros;
  DateTime? _firstRttSample;
  var _ptoCount = 0;
  var _ptoBudgetExhausted = false;
  var _handshakeConfirmed = false;
  var _hasHandshakeKeys = false;
  var _peerAddressValidated = false;
  DateTime? _deadline;

  int get congestionWindow => controller.congestionWindow;
  int get bytesInFlight => controller.bytesInFlight;
  int get ssthresh => controller.ssthresh;
  int get smoothedRttMicros => _smoothedRtt;
  int get latestRttMicros => _latestRtt;
  int get ptoCount => _ptoCount;
  bool get ptoBudgetExhausted => _ptoBudgetExhausted;
  bool get handshakeConfirmed => _handshakeConfirmed;
  bool get inSlowStart => controller.inSlowStart;

  /// When [onLossDetectionTimeout] will do work. Null means the timer is
  /// disarmed (nothing in flight, or the PTO budget is spent).
  DateTime? get lossDetectionDeadline => _deadline;

  /// Largest payload a 1-RTT packet can carry and still be one
  /// [maxDatagramSize] datagram, header included.
  int get maxDatagramPayload {
    final room = maxDatagramSize - quicShortHeaderOverhead;
    return room > 0 ? room : 0;
  }

  bool packetNumberUsed(QuicPacketNumberSpace space, int packetNumber) =>
      _everSent[space]!.contains(packetNumber);

  Set<int> lostPacketNumbers(QuicPacketNumberSpace space) =>
      Set<int>.unmodifiable(_lost[space]!.keys);

  int largestSent(QuicPacketNumberSpace space) {
    var largest = -1;
    for (final pn in _everSent[space]!) {
      if (pn > largest) largest = pn;
    }
    return largest;
  }

  /// Sent packets in [space] that are not yet acknowledged or discarded.
  bool hasOutstanding(QuicPacketNumberSpace space) =>
      _outstanding[space]!.isNotEmpty;

  /// In-flight packets in [space]. Ack-only packets are not included.
  /// Initial and Handshake keys can be discarded when this is false
  /// (RFC 9002 §6.4).
  bool hasInFlight(QuicPacketNumberSpace space) {
    for (final packet in _outstanding[space]!.values) {
      if (packet.inFlight) return true;
    }
    return false;
  }

  /// Next packet number in [space], without retiring it.
  ///
  /// Seal with this number, then [allocatePacketNumber] only once [canSend]
  /// accepts the datagram. A number returned here and never allocated may
  /// still be used. A number that was allocated and not sent is skipped,
  /// never reused (RFC 9000 §12.3).
  int peekPacketNumber(QuicPacketNumberSpace space) => _nextPn[space]!;

  /// Next packet number in [space]. Retired numbers, including lost ones,
  /// are never returned (RFC 9000 §12.3).
  int allocatePacketNumber(QuicPacketNumberSpace space) {
    final pn = _nextPn[space]!;
    _nextPn[space] = pn + 1;
    return pn;
  }

  bool shouldSend(QuicRetransmittable frame) {
    if (frame is QuicRetransmitPing) return true;
    return !_delivered.contains(frame.token);
  }

  /// Oldest in-flight ack-eliciting data in [space], for a PTO probe.
  /// Does not declare the packet lost.
  List<QuicRetransmittable> oldestInFlightData(QuicPacketNumberSpace space) {
    final outstanding = _outstanding[space]!;
    final numbers = outstanding.keys.toList()..sort();
    for (final pn in numbers) {
      final packet = outstanding[pn]!;
      if (!packet.inFlight || !packet.ackEliciting) continue;
      final data = _unackedFrames(packet);
      if (data.isNotEmpty) return data;
    }
    return const [];
  }

  bool canSend(int bytes, {bool probe = false, bool inFlight = true}) {
    if (_ptoBudgetExhausted) return false;
    return controller.canSend(bytes, probe: probe, inFlight: inFlight);
  }

  void markHandshakeConfirmed() {
    _handshakeConfirmed = true;
    if (!_isServer) _peerAddressValidated = true;
    _setLossDetectionTimer();
  }

  void markHandshakeKeysAvailable() {
    _hasHandshakeKeys = true;
  }

  void markPeerAddressValidated() {
    _peerAddressValidated = true;
  }

  Result<void, PqTransportError> onPacketSent({
    required QuicPacketNumberSpace space,
    required int packetNumber,
    required int sentBytes,
    required bool ackEliciting,
    required bool inFlight,
    required List<QuicRetransmittable> frames,
    bool appLimited = false,
    bool probe = false,
  }) {
    if (_ptoBudgetExhausted) {
      return Result.failure(PqTransportError.closed('PTO budget exhausted'));
    }
    if (packetNumber < 0 || _everSent[space]!.contains(packetNumber)) {
      return Result.failure(
        PqTransportError.internalError('packet number reused'),
      );
    }
    final accounted = controller.onPacketSent(
      sentBytes,
      probe: probe,
      inFlight: inFlight,
    );
    if (accounted.isFailure) return accounted;
    final packet = QuicSentPacket(
      space: space,
      packetNumber: packetNumber,
      timeSent: clock.now(),
      sentBytes: sentBytes,
      ackEliciting: ackEliciting,
      inFlight: inFlight,
      appLimited: appLimited,
      frames: List<QuicRetransmittable>.unmodifiable(frames),
    );
    _everSent[space]!.add(packetNumber);
    if (packetNumber + 1 > _nextPn[space]!) {
      _nextPn[space] = packetNumber + 1;
    }
    _outstanding[space]![packetNumber] = packet;
    _history.add(packet);
    _sentAck[space]!.onSent(packetNumber, Uint8List(0));
    if (inFlight && ackEliciting) {
      _lastAckEliciting[space] = packet.timeSent;
    }
    if (inFlight) _setLossDetectionTimer();
    return const Result.success(null);
  }

  /// [ack] acknowledges [space] only. Build it with [QuicAckProcessor]
  /// on the receiver. Newly acknowledged numbers are taken from a
  /// per-space [QuicAckProcessor.applyAck] over packets this side sent.
  Result<QuicRecoveryEvent, PqTransportError> onAck(
    QuicPacketNumberSpace space,
    QuicAckFrame ack,
  ) {
    if (_ptoBudgetExhausted) {
      return Result.failure(PqTransportError.closed('PTO budget exhausted'));
    }
    final numbers = ack.packetNumbers();
    for (final pn in numbers) {
      if (pn < 0) {
        return Result.failure(PqTransportError.decodeFailure('ack range'));
      }
      if (!_everSent[space]!.contains(pn)) {
        return Result.failure(
          PqTransportError.unexpectedMessage('ack for unsent packet'),
        );
      }
    }

    for (final pn in numbers) {
      final lost = _lost[space]!.remove(pn);
      if (lost == null) continue;
      lost.acknowledged = true;
      _markDelivered(lost);
    }

    final previousLargest = _largestAcked[space];
    final largestIncreased =
        previousLargest == null || ack.largest > previousLargest;
    final largest = previousLargest == null
        ? ack.largest
        : (ack.largest > previousLargest ? ack.largest : previousLargest);
    _largestAcked[space] = largest;

    final newlyNumbers = _sentAck[space]!.applyAck(ack);
    final newly = <QuicSentPacket>[];
    for (final pn in newlyNumbers) {
      final packet = _outstanding[space]!.remove(pn);
      if (packet == null) continue;
      packet.acknowledged = true;
      _markDelivered(packet);
      newly.add(packet);
    }
    if (newly.isEmpty && !largestIncreased) {
      return const Result.success(QuicRecoveryEvent.empty);
    }

    if (newly.isNotEmpty) {
      newly.sort((a, b) => a.packetNumber.compareTo(b.packetNumber));
      final includesEliciting = newly.any((packet) => packet.ackEliciting);
      if (newly.last.packetNumber == ack.largest && includesEliciting) {
        final sample = clock
            .now()
            .difference(newly.last.timeSent)
            .inMicroseconds;
        _latestRtt = sample < 0 ? 0 : sample;
        final delay = space == QuicPacketNumberSpace.application
            ? ack.delay * (1 << quicAckDelayExponentDefault)
            : 0;
        _updateRtt(delay);
      }
    }

    final loss = _applyLoss(space);
    for (final packet in newly) {
      final wasInFlight = packet.inFlight;
      controller.onPacketAcked(
        sentBytes: packet.sentBytes,
        timeSent: packet.timeSent,
        inFlight: packet.inFlight,
        appLimited: packet.appLimited,
      );
      if (wasInFlight) packet.inFlight = false;
    }
    if (newly.isNotEmpty && _peerCompletedAddressValidation()) {
      _ptoCount = 0;
    }
    _setLossDetectionTimer();
    return Result.success(
      QuicRecoveryEvent(
        newlyAcked: newly,
        lost: loss.lost,
        retransmit: _retransmitOf(loss.lost),
        persistentCongestion: loss.persistent,
        congestionProbe: loss.congestionProbe,
      ),
    );
  }

  /// Appendix A.9. Time-threshold loss does not send a probe. A PTO does,
  /// and does not mark packets lost. Past [maxPtoCount] the path is closed.
  Result<QuicRecoveryEvent, PqTransportError> onLossDetectionTimeout() {
    if (_ptoBudgetExhausted) {
      return Result.failure(PqTransportError.closed('PTO budget exhausted'));
    }
    final deadline = _deadline;
    if (deadline == null || deadline.isAfter(clock.now())) {
      return const Result.success(QuicRecoveryEvent.empty);
    }
    final loss = _earliestLoss();
    if (loss != null) {
      final applied = _applyLoss(loss);
      _setLossDetectionTimer();
      return Result.success(
        QuicRecoveryEvent(
          lost: applied.lost,
          retransmit: _retransmitOf(applied.lost),
          persistentCongestion: applied.persistent,
          congestionProbe: applied.congestionProbe,
        ),
      );
    }

    if (_ptoCount >= maxPtoCount) {
      _ptoBudgetExhausted = true;
      _deadline = null;
      return Result.failure(PqTransportError.closed('PTO budget exhausted'));
    }
    final probe = _ptoSpace();
    _ptoCount++;
    _setLossDetectionTimer();
    return Result.success(QuicRecoveryEvent(probeSpace: probe));
  }

  /// Appendix A.11. Packet numbers in [space] stay retired.
  void onPacketNumberSpaceDiscarded(QuicPacketNumberSpace space) {
    if (space == QuicPacketNumberSpace.application) {
      throw ArgumentError.value(
        space,
        'space',
        'application data is not discarded',
      );
    }
    final outstanding = _outstanding[space]!;
    controller.removeFromBytesInFlight([
      for (final packet in outstanding.values)
        (sentBytes: packet.sentBytes, inFlight: packet.inFlight),
    ]);
    for (final packet in outstanding.values) {
      packet.inFlight = false;
      _sentAck[space]!.inFlight.remove(packet.packetNumber);
    }
    outstanding.clear();
    _lossTime[space] = null;
    _lastAckEliciting[space] = null;
    _ptoCount = 0;
    _setLossDetectionTimer();
  }

  /// RFC 9002 §6.1 then §7. Loss bytes are removed before the persistent
  /// congestion check so [QuicSentPacket.inFlight] still tells a padding
  /// packet from one that was never in flight. Acknowledgements in the
  /// same event are applied by the caller after this returns.
  ({List<QuicSentPacket> lost, bool persistent, bool congestionProbe})
  _applyLoss(QuicPacketNumberSpace space) {
    final lost = _detectAndRemoveLost(space);
    final persistent = _inPersistentCongestion(lost);
    final entered = controller.onPacketsLost(
      lost: [
        for (final packet in lost)
          (
            sentBytes: packet.sentBytes,
            timeSent: packet.timeSent,
            inFlight: packet.inFlight,
          ),
      ],
    );
    for (final packet in lost) {
      if (packet.inFlight) packet.inFlight = false;
    }
    if (persistent) {
      controller.onPersistentCongestion();
      _minRtt = _latestRtt;
    }
    return (
      lost: lost,
      persistent: persistent,
      congestionProbe: entered && controller.takeRecoverySend(),
    );
  }

  void _markDelivered(QuicSentPacket packet) {
    for (final frame in packet.frames) {
      if (frame is QuicRetransmitPing) continue;
      _delivered.add(frame.token);
    }
  }

  List<QuicRetransmittable> _unackedFrames(QuicSentPacket packet) {
    final out = <QuicRetransmittable>[];
    final seen = <String>{};
    for (final frame in packet.frames) {
      if (frame is QuicRetransmitPing) continue;
      if (_delivered.contains(frame.token) || !seen.add(frame.token)) {
        continue;
      }
      out.add(frame);
    }
    return out;
  }

  List<QuicRetransmittable> _retransmitOf(List<QuicSentPacket> lost) {
    final out = <QuicRetransmittable>[];
    final seen = <String>{};
    for (final packet in lost) {
      for (final frame in _unackedFrames(packet)) {
        if (seen.add(frame.token)) out.add(frame);
      }
    }
    return out;
  }

  void _updateRtt(int ackDelay) {
    if (_firstRttSample == null) {
      _minRtt = _latestRtt;
      _smoothedRtt = _latestRtt;
      _rttvar = _latestRtt ~/ 2;
      _firstRttSample = clock.now();
      return;
    }
    if (_latestRtt < _minRtt) _minRtt = _latestRtt;
    var delay = ackDelay;
    if (_handshakeConfirmed && delay > _maxAckDelay) delay = _maxAckDelay;
    var adjusted = _latestRtt;
    if (_latestRtt >= _minRtt + delay) adjusted = _latestRtt - delay;
    // RFC 9002 §5.3 updates smoothed_rtt before rttvar. Appendix A.7 lists
    // those two assignments in the other order; the section is the rule
    // (Appendix A.3 says both are "computed as described in Section 5.3").
    _smoothedRtt =
        (quicRttSmoothNumerator * _smoothedRtt + adjusted) ~/
        quicRttSmoothDenominator;
    final sample = (_smoothedRtt - adjusted).abs();
    _rttvar = (quicRttVarNumerator * _rttvar + sample) ~/ quicRttVarDenominator;
  }

  List<QuicSentPacket> _detectAndRemoveLost(QuicPacketNumberSpace space) {
    final largest = _largestAcked[space];
    if (largest == null) return const [];
    _lossTime[space] = null;
    final lossDelay = _lossDelayMicros();
    final lostSendTime = clock.now().subtract(
      Duration(microseconds: lossDelay),
    );
    final lost = <QuicSentPacket>[];
    final outstanding = _outstanding[space]!;
    final numbers = outstanding.keys.toList()..sort();
    for (final pn in numbers) {
      if (pn > largest) continue;
      final packet = outstanding[pn]!;
      // §6.1 declares loss only for unacknowledged in-flight packets.
      // An ack-only packet has nothing to retransmit; drop it once a
      // later number is acknowledged so it cannot pin the space open.
      if (!packet.inFlight) {
        if (!_hasRetransmittable(packet)) {
          outstanding.remove(pn);
          _sentAck[space]!.inFlight.remove(pn);
        }
        continue;
      }
      final byTime = !packet.timeSent.isAfter(lostSendTime);
      final byCount = largest >= pn + quicPacketThreshold;
      if (byTime || byCount) {
        outstanding.remove(pn);
        _sentAck[space]!.inFlight.remove(pn);
        packet.declaredLost = true;
        _lost[space]![pn] = packet;
        lost.add(packet);
        continue;
      }
      final when = packet.timeSent.add(Duration(microseconds: lossDelay));
      final current = _lossTime[space];
      if (current == null || when.isBefore(current)) _lossTime[space] = when;
    }
    return lost;
  }

  int _lossDelayMicros() {
    final rtt = _latestRtt > _smoothedRtt ? _latestRtt : _smoothedRtt;
    final scaled =
        quicTimeThresholdNumerator * rtt ~/ quicTimeThresholdDenominator;
    return scaled > quicGranularityMicros ? scaled : quicGranularityMicros;
  }

  bool _hasRetransmittable(QuicSentPacket packet) {
    for (final frame in packet.frames) {
      if (frame is! QuicRetransmitPing) return true;
    }
    return false;
  }

  /// RFC 9002 §7.6.2, not the shorter Appendix B predicate.
  ///
  /// Two ack-eliciting packets in this loss set, both sent after the first
  /// RTT sample, establish persistent congestion when the time between
  /// their send times exceeds the threshold. Every congestion-controlled
  /// packet sent in that inclusive window (any packet number space) must
  /// already be declared lost. An acknowledgement in the window, or an
  /// in-flight packet not yet lost, blocks the declaration. §7.6.3
  /// measures the span as newest minus oldest, not `now` minus oldest.
  /// Ack-only packets are not in flight and are not part of the window.
  bool _inPersistentCongestion(List<QuicSentPacket> lost) {
    if (_firstRttSample == null) return false;
    final sampleAt = _firstRttSample!;
    final considered = [
      for (final packet in lost)
        if (packet.ackEliciting && packet.timeSent.isAfter(sampleAt)) packet,
    ];
    if (considered.length < 2) return false;
    considered.sort((a, b) => a.timeSent.compareTo(b.timeSent));
    final oldest = considered.first.timeSent;
    final newest = considered.last.timeSent;
    final span = newest.difference(oldest).inMicroseconds;
    if (span <= _persistentMicros()) return false;
    for (final packet in _history) {
      if (packet.timeSent.isBefore(oldest)) continue;
      if (packet.timeSent.isAfter(newest)) continue;
      final counts =
          packet.inFlight || packet.declaredLost || packet.acknowledged;
      if (!counts) continue;
      if (packet.acknowledged || !packet.declaredLost) return false;
    }
    return true;
  }

  int _persistentMicros() {
    final variation = quicRttVarPtoMultiplier * _rttvar;
    final granularity = variation > quicGranularityMicros
        ? variation
        : quicGranularityMicros;
    return (_smoothedRtt + granularity + _maxAckDelay) *
        quicPersistentCongestionThreshold;
  }

  QuicPacketNumberSpace? _earliestLoss() {
    DateTime? best;
    QuicPacketNumberSpace? space;
    for (final candidate in QuicPacketNumberSpace.values) {
      final when = _lossTime[candidate];
      if (when == null || when.isAfter(clock.now())) continue;
      if (best == null || when.isBefore(best)) {
        best = when;
        space = candidate;
      }
    }
    return space;
  }

  bool _ackElicitingInFlight([QuicPacketNumberSpace? only]) {
    final spaces = only == null ? QuicPacketNumberSpace.values : [only];
    for (final space in spaces) {
      for (final packet in _outstanding[space]!.values) {
        if (packet.inFlight && packet.ackEliciting) return true;
      }
    }
    return false;
  }

  bool _peerCompletedAddressValidation() {
    if (_isServer) return true;
    return _peerAddressValidated || _handshakeConfirmed;
  }

  int _pow2(int exponent) {
    var value = 1;
    for (var i = 0; i < exponent; i++) {
      value *= 2;
    }
    return value;
  }

  int _ptoDurationMicros({required bool includeMaxAckDelay}) {
    final variation = quicRttVarPtoMultiplier * _rttvar;
    final granularity = variation > quicGranularityMicros
        ? variation
        : quicGranularityMicros;
    final backoff = _pow2(_ptoCount);
    var duration = (_smoothedRtt + granularity) * backoff;
    if (includeMaxAckDelay) duration += _maxAckDelay * backoff;
    if (duration < quicGranularityMicros) return quicGranularityMicros;
    return duration;
  }

  QuicPacketNumberSpace _ptoSpace() {
    if (!_ackElicitingInFlight()) {
      return _hasHandshakeKeys
          ? QuicPacketNumberSpace.handshake
          : QuicPacketNumberSpace.initial;
    }
    DateTime? best;
    var chosen = QuicPacketNumberSpace.initial;
    for (final space in QuicPacketNumberSpace.values) {
      if (!_ackElicitingInFlight(space)) continue;
      if (space == QuicPacketNumberSpace.application && !_handshakeConfirmed) {
        continue;
      }
      final includeDelay = space == QuicPacketNumberSpace.application;
      final last = _lastAckEliciting[space];
      if (last == null) continue;
      final when = last.add(
        Duration(
          microseconds: _ptoDurationMicros(includeMaxAckDelay: includeDelay),
        ),
      );
      if (best == null || when.isBefore(best)) {
        best = when;
        chosen = space;
      }
    }
    return chosen;
  }

  void _setLossDetectionTimer() {
    if (_ptoBudgetExhausted) {
      _deadline = null;
      return;
    }
    DateTime? earliest;
    for (final space in QuicPacketNumberSpace.values) {
      final when = _lossTime[space];
      if (when == null) continue;
      if (earliest == null || when.isBefore(earliest)) earliest = when;
    }
    if (earliest != null) {
      _deadline = earliest;
      return;
    }
    if (!_ackElicitingInFlight() && _peerCompletedAddressValidation()) {
      _deadline = null;
      return;
    }
    if (!_ackElicitingInFlight()) {
      final duration = _ptoDurationMicros(includeMaxAckDelay: false);
      _deadline = clock.now().add(Duration(microseconds: duration));
      return;
    }
    DateTime? best;
    for (final space in QuicPacketNumberSpace.values) {
      if (!_ackElicitingInFlight(space)) continue;
      if (space == QuicPacketNumberSpace.application && !_handshakeConfirmed) {
        continue;
      }
      final last = _lastAckEliciting[space];
      if (last == null) continue;
      final includeDelay = space == QuicPacketNumberSpace.application;
      final when = last.add(
        Duration(
          microseconds: _ptoDurationMicros(includeMaxAckDelay: includeDelay),
        ),
      );
      if (best == null || when.isBefore(best)) best = when;
    }
    _deadline = best;
  }
}
