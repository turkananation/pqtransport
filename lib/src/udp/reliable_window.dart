import 'package:swissarmyknife/swissarmyknife.dart';

import '../core/errors.dart';
import '../core/lengths.dart';

enum UdpState { idle, bound, reliableOpen, retransmit, failed, closed }

enum UdpEvent {
  bind,
  startReliable,
  peerAck,
  timeout,
  budgetExceeded,
  fatal,
  close,
}

StateMachine<UdpState, UdpEvent> udpStateMachine() {
  final m = StateMachine<UdpState, UdpEvent>(initialState: UdpState.idle);
  m.addTransition(UdpState.idle, UdpEvent.bind, UdpState.bound);
  m.addTransition(UdpState.idle, UdpEvent.close, UdpState.closed);
  m.addTransition(UdpState.idle, UdpEvent.fatal, UdpState.failed);
  m.addTransition(
    UdpState.bound,
    UdpEvent.startReliable,
    UdpState.reliableOpen,
  );
  m.addTransition(UdpState.bound, UdpEvent.close, UdpState.closed);
  m.addTransition(UdpState.bound, UdpEvent.fatal, UdpState.failed);
  m.addTransition(
    UdpState.reliableOpen,
    UdpEvent.peerAck,
    UdpState.reliableOpen,
  );
  m.addTransition(UdpState.reliableOpen, UdpEvent.timeout, UdpState.retransmit);
  m.addTransition(UdpState.reliableOpen, UdpEvent.close, UdpState.closed);
  m.addTransition(UdpState.reliableOpen, UdpEvent.fatal, UdpState.failed);
  m.addTransition(UdpState.retransmit, UdpEvent.peerAck, UdpState.reliableOpen);
  m.addTransition(
    UdpState.retransmit,
    UdpEvent.budgetExceeded,
    UdpState.failed,
  );
  m.addTransition(UdpState.retransmit, UdpEvent.close, UdpState.closed);
  m.addTransition(UdpState.retransmit, UdpEvent.fatal, UdpState.failed);
  m.addTransition(UdpState.failed, UdpEvent.close, UdpState.closed);
  return m;
}

/// Sliding-window anti-replay. Drop duplicates **before** AEAD open when the
/// sequence is already in the window; after open, mark received.
final class ReplayWindow {
  ReplayWindow({this.size = datagramReplayWindowSize});

  final int size;
  final Set<int> _seen = <int>{};
  int _max = -1;

  bool isDuplicate(int sequence) {
    if (sequence < 0) return true;
    if (_seen.contains(sequence)) return true;
    if (_max >= 0 && sequence < _max - size) return true;
    return false;
  }

  Result<void, PqTransportError> remember(int sequence) {
    if (isDuplicate(sequence)) {
      return Result.failure(PqTransportError.replay('sequence $sequence'));
    }
    _seen.add(sequence);
    if (sequence > _max) _max = sequence;
    _seen.removeWhere((s) => s < _max - size);
    return const Result.success(null);
  }
}
