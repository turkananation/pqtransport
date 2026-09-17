import 'dart:async';
import 'package:swissarmyknife/swissarmyknife.dart';

import '../core/errors.dart';
import '../core/lengths.dart';
import '../dns/records.dart';
import '../dns/wire.dart';
import '../socket/pq_transport_socket.dart';

enum MdnsState {
  idle,
  probing,
  announcing,
  registered,
  browsing,
  failed,
  stopped,
}

enum MdnsEvent { startProbe, probeOk, collision, announce, browse, fatal, stop }

final class MdnsServiceEvent {
  const MdnsServiceEvent(this.name, this.record);
  final String name;
  final DnsRecord record;
}

StateMachine<MdnsState, MdnsEvent> mdnsMachine() {
  final m = StateMachine<MdnsState, MdnsEvent>(initialState: MdnsState.idle);
  m.addTransition(MdnsState.idle, MdnsEvent.startProbe, MdnsState.probing);
  m.addTransition(MdnsState.idle, MdnsEvent.browse, MdnsState.browsing);
  m.addTransition(MdnsState.idle, MdnsEvent.stop, MdnsState.stopped);
  m.addTransition(MdnsState.idle, MdnsEvent.fatal, MdnsState.failed);
  m.addTransition(MdnsState.probing, MdnsEvent.probeOk, MdnsState.announcing);
  m.addTransition(MdnsState.probing, MdnsEvent.collision, MdnsState.failed);
  m.addTransition(MdnsState.probing, MdnsEvent.fatal, MdnsState.failed);
  m.addTransition(MdnsState.probing, MdnsEvent.stop, MdnsState.stopped);
  m.addTransition(
    MdnsState.announcing,
    MdnsEvent.announce,
    MdnsState.registered,
  );
  m.addTransition(MdnsState.announcing, MdnsEvent.fatal, MdnsState.failed);
  m.addTransition(MdnsState.announcing, MdnsEvent.stop, MdnsState.stopped);
  m.addTransition(MdnsState.registered, MdnsEvent.stop, MdnsState.stopped);
  m.addTransition(MdnsState.registered, MdnsEvent.fatal, MdnsState.failed);
  m.addTransition(MdnsState.browsing, MdnsEvent.stop, MdnsState.stopped);
  m.addTransition(MdnsState.browsing, MdnsEvent.fatal, MdnsState.failed);
  m.addTransition(MdnsState.failed, MdnsEvent.stop, MdnsState.stopped);
  return m;
}

final class PqMdnsServer {
  PqMdnsServer({
    required this.channel,
    this.local = const PqEndpoint('0.0.0.0', mdnsPort),
  });

  final PqDatagramChannel channel;
  final PqEndpoint local;
  final StateMachine<MdnsState, MdnsEvent> machine = mdnsMachine();
  final Cache<String, DnsRecord> registry = Cache(maxSize: 256);
  var _probes = 0;

  MdnsState get state => machine.currentState;

  Result<void, PqTransportError> beginProbe(String instance) {
    final r = machine.trigger(MdnsEvent.startProbe);
    if (r.isFailure) {
      return Result.failure(
        PqTransportError.unexpectedMessage(r.errorOrNull!.message),
      );
    }
    _probes = 0;
    return const Result.success(null);
  }

  Result<void, PqTransportError> completeProbe({required bool collision}) {
    if (collision) {
      machine.trigger(MdnsEvent.collision);
      return Result.failure(
        PqTransportError.handshakeFailure('mdns collision'),
      );
    }
    _probes++;
    if (_probes >= mdnsProbeCount) {
      machine.trigger(MdnsEvent.probeOk);
    }
    return const Result.success(null);
  }

  Future<Result<void, PqTransportError>> announce(DnsRecord record) async {
    if (!machine.isIn(MdnsState.announcing) &&
        !machine.isIn(MdnsState.registered)) {
      final t = machine.trigger(MdnsEvent.announce);
      if (t.isFailure && !machine.isIn(MdnsState.announcing)) {
        return Result.failure(
          PqTransportError.unexpectedMessage(t.errorOrNull!.message),
        );
      }
    } else {
      machine.trigger(MdnsEvent.announce);
    }
    registry.put(record.name, record);
    final msg = DnsMessage(id: 0, flags: 0x8400, answers: [record]);
    final wire = encodeDnsMessage(msg);
    if (wire.isFailure) return Result.failure(wire.errorOrNull!);
    return channel.send(
      wire.valueOrNull!,
      const PqEndpoint(mdnsIpv4Group, mdnsPort),
    );
  }
}

final class PqMdnsClient {
  PqMdnsClient({required this.channel}) : bus = EventBus();

  final PqDatagramChannel channel;
  final EventBus bus;
  final StateMachine<MdnsState, MdnsEvent> machine = mdnsMachine();
  final Cache<String, DnsRecord> seen = Cache(maxSize: 256);
  StreamSubscription<PqDatagramIn>? _sub;

  Future<Result<void, PqTransportError>> browse() async {
    final t = machine.trigger(MdnsEvent.browse);
    if (t.isFailure) {
      return Result.failure(
        PqTransportError.unexpectedMessage(t.errorOrNull!.message),
      );
    }
    _sub = channel.incoming.listen((d) {
      final msg = decodeDnsMessage(d.data);
      if (msg.isFailure) return;
      for (final rr in msg.valueOrNull!.answers) {
        seen.put(rr.name, rr);
        bus.fire(MdnsServiceEvent(rr.name, rr));
      }
    });
    return const Result.success(null);
  }

  Future<void> stop() async {
    machine.trigger(MdnsEvent.stop);
    await _sub?.cancel();
  }
}
