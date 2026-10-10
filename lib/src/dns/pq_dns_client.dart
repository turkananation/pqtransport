import 'dart:async';
import 'dart:math';
import 'dart:typed_data';

import 'package:swissarmyknife/swissarmyknife.dart';

import '../core/errors.dart';
import '../core/lengths.dart';
import '../socket/pq_transport_socket.dart';
import 'doh_dot.dart';
import 'records.dart';
import 'wire.dart';

enum DnsTransportKind { udp, tcp, doh, dot, system }

final class DnsCacheKey {
  const DnsCacheKey(this.name, this.type);
  final String name;
  final DnsType type;
  @override
  bool operator ==(Object other) =>
      other is DnsCacheKey && other.name == name && other.type == type;
  @override
  int get hashCode => Object.hash(name, type);
}

typedef DnsExchange = Future<Uint8List> Function(Uint8List query);

/// Resolver with TTL cache and circuit breaker around every external hop.
final class PqDnsClient {
  PqDnsClient({
    required this.exchange,
    DateTime Function()? clock,
    this.failureThreshold = 2,
  }) : cache = Cache<DnsCacheKey, DnsMessage>(clock: clock),
       breaker = CircuitBreaker(failureThreshold: failureThreshold);

  final DnsExchange exchange;
  final Cache<DnsCacheKey, DnsMessage> cache;
  final CircuitBreaker breaker;
  final int failureThreshold;
  final _rand = Random();

  Future<Result<DnsMessage, PqTransportError>> lookup(
    String name,
    DnsType type,
  ) async {
    final key = DnsCacheKey(name, type);
    final hit = cache.get(key);
    if (hit != null) return Result.success(hit);
    final id = _rand.nextInt(0x10000);
    final q = DnsMessage(
      id: id,
      questions: [DnsQuestion(name: name, type: type)],
    );
    final encoded = encodeDnsMessage(q);
    if (encoded.isFailure) return Result.failure(encoded.errorOrNull!);
    final exec = await breaker.execute(() => exchange(encoded.valueOrNull!));
    if (exec.isFailure) {
      return Result.failure(
        PqTransportError.circuitOpen(exec.errorOrNull!.toString()),
      );
    }
    final decoded = decodeDnsMessage(exec.valueOrNull!);
    if (decoded.isFailure) return decoded;
    final msg = decoded.valueOrNull!;
    cache.put(key, msg, ttl: msg.minTtl());
    return Result.success(msg);
  }
}

/// Facade that tries DoH → DoT → UDP with independent breakers.
final class PqDnsResolver {
  PqDnsResolver({
    DnsExchange? doh,
    DnsExchange? dot,
    DnsExchange? udp,
    DateTime Function()? clock,
  }) : _doh = doh == null ? null : PqDnsClient(exchange: doh, clock: clock),
       _dot = dot == null ? null : PqDnsClient(exchange: dot, clock: clock),
       _udp = udp == null ? null : PqDnsClient(exchange: udp, clock: clock);

  final PqDnsClient? _doh;
  final PqDnsClient? _dot;
  final PqDnsClient? _udp;

  Future<Result<DnsMessage, PqTransportError>> lookup(
    String name,
    DnsType type,
  ) async {
    for (final c in [_doh, _dot, _udp]) {
      if (c == null) continue;
      final r = await c.lookup(name, type);
      if (r.isSuccess) return r;
    }
    return Result.failure(
      PqTransportError.circuitOpen('all dns transports open or missing'),
    );
  }
}

/// DNS-over-HTTPS POST body hook. Production clients use [DohClient],
/// which builds the RFC 8484 request (media type, URI template, ALPN).
final class DohExchange {
  DohExchange(this.post);
  final Future<Uint8List> Function(Uint8List body) post;
  Future<Uint8List> call(Uint8List query) => post(query);
}

/// Length-prefixed DNS over an already connected byte pipe (RFC 1035 §4.2.2).
/// Production DoT on a completed handshake is [DotClient] (ALPN `dot`).
final class DotExchange {
  DotExchange(this.socket);
  final PqTransportSocket socket;
  final DnsTcpReader _reader = DnsTcpReader();
  StreamSubscription<Uint8List>? _sub;
  final List<Completer<Uint8List>> _waiters = [];

  void _ensureListen() {
    if (_sub != null) return;
    _sub = socket.incoming.listen((chunk) {
      _reader.add(chunk);
      if (_reader.error != null) {
        _fail(_reader.error!);
        return;
      }
      while (true) {
        final msg = _reader.next();
        if (_reader.error != null) {
          _fail(_reader.error!);
          return;
        }
        if (msg == null || _waiters.isEmpty) return;
        _waiters.removeAt(0).complete(msg);
      }
    }, onError: (Object e) => _fail(PqTransportError.closed('$e')));
  }

  Future<void> close() async {
    await _sub?.cancel();
    _sub = null;
    _fail(PqTransportError.closed('dot closed'));
  }

  void _fail(PqTransportError err) {
    final pending = List<Completer<Uint8List>>.of(_waiters);
    _waiters.clear();
    for (final c in pending) {
      if (!c.isCompleted) c.completeError(err);
    }
  }

  Future<Uint8List> call(Uint8List query) async {
    if (query.isEmpty || query.length > dnsMessageMaxBytes) {
      throw PqTransportError.decodeFailure('dot query len');
    }
    _ensureListen();
    final waiter = Completer<Uint8List>();
    _waiters.add(waiter);
    final sent = await socket.send(encodeDnsTcp(query));
    if (sent.isFailure) {
      _waiters.remove(waiter);
      throw sent.errorOrNull!;
    }
    return waiter.future.timeout(const Duration(seconds: 10));
  }
}
