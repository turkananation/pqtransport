import 'package:swissarmyknife/swissarmyknife.dart';

import '../core/errors.dart';
import '../core/lengths.dart';

/// RFC 9002 Section 7 congestion controller: NewReno (Appendix B).
///
/// This is the controller named by the RFC. It is not CUBIC and it does not
/// react to ECN. The window is in bytes. Slow start grows by the bytes just
/// acknowledged. Congestion avoidance grows by at most one maximum datagram
/// per window of acknowledged bytes (integer division, Appendix B.5).
///
/// A send that is not a PTO probe or the single recovery packet is rejected
/// when it would make [bytesInFlight] larger than [congestionWindow]
/// (Section 7, before §7.1).
final class QuicNewReno {
  QuicNewReno({required this.maxDatagramSize, required DateTime Function() now})
    : congestionWindow = quicInitialCongestionWindow(maxDatagramSize),
      _minimumWindow = quicMinimumCongestionWindow(maxDatagramSize),
      // Public parameter stays `now`. An initializing formal would rename it.
      // ignore: prefer_initializing_formals
      _now = now {
    if (maxDatagramSize < quicMinClientInitialUdpBytes) {
      throw ArgumentError.value(
        maxDatagramSize,
        'maxDatagramSize',
        'RFC 9002 minimum is $quicMinClientInitialUdpBytes',
      );
    }
  }

  final int maxDatagramSize;
  final DateTime Function() _now;

  int congestionWindow;
  int bytesInFlight = 0;
  int ssthresh = quicSsthreshInfinite;
  final int _minimumWindow;
  DateTime? _recoveryStart;
  var _recoverySendCredit = false;

  /// Bytes acknowledged in congestion avoidance that have not yet added
  /// a full maximum datagram (RFC 3465 §2.1, cited by RFC 9002 Appendix B.5).
  /// Integer division of a single packet would otherwise add zero forever.
  var _congestionAvoidanceBytes = 0;

  int get minimumWindow => _minimumWindow;

  DateTime? get recoveryStart => _recoveryStart;

  /// True while the window is below the slow-start threshold (RFC 9002 §7.3.1).
  bool get inSlowStart => congestionWindow < ssthresh;

  /// [bytes] more in-flight bytes fit, or [probe] ignores the window
  /// (RFC 9002 §7.5). Ack-only packets are not in flight and are not checked.
  bool canSend(int bytes, {bool probe = false, bool inFlight = true}) {
    if (!inFlight || probe) return true;
    return bytesInFlight + bytes <= congestionWindow;
  }

  /// Counts [sentBytes] toward the window. Fails closed when the window
  /// would be exceeded. Does not change the window size.
  Result<void, PqTransportError> onPacketSent(
    int sentBytes, {
    bool probe = false,
    bool inFlight = true,
  }) {
    if (!inFlight) return const Result.success(null);
    if (!canSend(sentBytes, probe: probe)) {
      return Result.failure(PqTransportError.throttled('congestion window'));
    }
    bytesInFlight += sentBytes;
    return const Result.success(null);
  }

  /// Appendix B.5. [appLimited] skips the increase (Section 7.8).
  void onPacketAcked({
    required int sentBytes,
    required DateTime timeSent,
    required bool inFlight,
    required bool appLimited,
  }) {
    if (!inFlight) return;
    bytesInFlight -= sentBytes;
    if (bytesInFlight < 0) bytesInFlight = 0;
    if (appLimited) return;
    if (_inRecovery(timeSent)) return;
    if (congestionWindow < ssthresh) {
      congestionWindow += sentBytes;
      _congestionAvoidanceBytes = 0;
      return;
    }
    // §7.3.3: at most one maximum datagram per acknowledged window.
    _congestionAvoidanceBytes += sentBytes;
    while (congestionWindow > 0 &&
        _congestionAvoidanceBytes >= congestionWindow) {
      _congestionAvoidanceBytes -= congestionWindow;
      congestionWindow += maxDatagramSize;
    }
  }

  /// Appendix B.8 byte accounting and the congestion event. Persistent
  /// congestion is decided by loss detection, which then calls
  /// [onPersistentCongestion].
  bool onPacketsLost({
    required List<({int sentBytes, DateTime timeSent, bool inFlight})> lost,
  }) {
    DateTime? newestInFlight;
    for (final packet in lost) {
      if (!packet.inFlight) continue;
      bytesInFlight -= packet.sentBytes;
      if (bytesInFlight < 0) bytesInFlight = 0;
      final sent = packet.timeSent;
      if (newestInFlight == null || sent.isAfter(newestInFlight)) {
        newestInFlight = sent;
      }
    }
    if (newestInFlight == null) return false;
    return _onCongestionEvent(newestInFlight);
  }

  /// Section 7.6. Collapses the window to the minimum and leaves recovery
  /// so the next acknowledgement can slow-start again.
  void onPersistentCongestion() {
    congestionWindow = _minimumWindow;
    _recoveryStart = null;
    _congestionAvoidanceBytes = 0;
  }

  /// One packet may ignore the window after a congestion event (§7.3.2).
  /// The credit is single-use.
  bool takeRecoverySend() {
    if (!_recoverySendCredit) return false;
    _recoverySendCredit = false;
    return true;
  }

  /// Appendix B.9. Packets dropped with discarded Initial or Handshake keys.
  void removeFromBytesInFlight(
    Iterable<({int sentBytes, bool inFlight})> packets,
  ) {
    for (final packet in packets) {
      if (!packet.inFlight) continue;
      bytesInFlight -= packet.sentBytes;
    }
    if (bytesInFlight < 0) bytesInFlight = 0;
  }

  bool _inRecovery(DateTime sentTime) {
    final start = _recoveryStart;
    if (start == null) return false;
    return !sentTime.isAfter(start);
  }

  bool _onCongestionEvent(DateTime sentTime) {
    if (_inRecovery(sentTime)) return false;
    _recoveryStart = _now();
    ssthresh =
        congestionWindow *
        quicLossReductionNumerator ~/
        quicLossReductionDenominator;
    final reduced = ssthresh > _minimumWindow ? ssthresh : _minimumWindow;
    congestionWindow = reduced;
    _congestionAvoidanceBytes = 0;
    _recoverySendCredit = true;
    return true;
  }
}
