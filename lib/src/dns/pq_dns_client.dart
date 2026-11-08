import 'dart:async';
import 'dart:math';
import 'dart:typed_data';

import 'package:swissarmyknife/swissarmyknife.dart';

import '../core/errors.dart';
import '../core/lengths.dart';
import '../socket/pq_transport_socket.dart';
import 'dnssec.dart';
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
///
/// The query sets the DO bit (RFC 3225) and the CD bit (RFC 4035) so a
/// validator still receives RRSIGs. The response id must match. A truncated
/// response is retried on [tcp] when that exchange is set. BADCOOKIE is
/// retried once with the server cookie (RFC 7873). The AD bit is not
/// validation. [lookup] does not verify an RRSIG and does not follow CNAME.
/// [resolve] follows CNAME. [authenticateDns] checks signatures.
/// The iterative walker is [DnsIterativeResolver] in `resolve.dart`.
final class PqDnsClient {
  PqDnsClient({
    required this.exchange,
    this.tcp,
    DateTime Function()? clock,
    this.failureThreshold = 2,
  }) : cache = Cache<DnsCacheKey, DnsMessage>(clock: clock),
       breaker = CircuitBreaker(failureThreshold: failureThreshold);

  final DnsExchange exchange;
  final DnsExchange? tcp;
  final Cache<DnsCacheKey, DnsMessage> cache;
  final CircuitBreaker breaker;
  final int failureThreshold;
  final _rand = Random();
  Uint8List? _clientCookie;

  Uint8List get clientCookie => _clientCookie ??= Uint8List.fromList(
    List<int>.generate(8, (_) => _rand.nextInt(256)),
  );

  Future<Result<DnsMessage, PqTransportError>> lookup(
    String name,
    DnsType type,
  ) async {
    final canonical = dnsNameKey(name);
    if (canonical == null) {
      return Result.failure(PqTransportError.decodeFailure('dns name'));
    }
    final key = DnsCacheKey(canonical, type);
    final hit = cache.get(key);
    if (hit != null) return Result.success(hit);
    final first = await _query(name, type, clientCookie);
    if (first.isFailure) return Result.failure(first.errorOrNull!);
    final msg = first.valueOrNull!;
    if (msg.rcode != dnsRcodeBadCookie) {
      cache.put(key, msg, ttl: msg.minTtl());
      return Result.success(msg);
    }
    final server = dnsServerCookie(msg, clientCookie);
    if (server == null) {
      return Result.failure(PqTransportError.unexpectedMessage('dns cookie'));
    }
    final cookie = Uint8List(clientCookie.length + server.length)
      ..setRange(0, clientCookie.length, clientCookie)
      ..setRange(
        clientCookie.length,
        clientCookie.length + server.length,
        server,
      );
    final again = await _query(name, type, cookie);
    if (again.isFailure) return Result.failure(again.errorOrNull!);
    if (again.valueOrNull!.rcode == dnsRcodeBadCookie) {
      return Result.failure(PqTransportError.unexpectedMessage('dns cookie'));
    }
    cache.put(key, again.valueOrNull!, ttl: again.valueOrNull!.minTtl());
    return again;
  }

  Future<Result<DnsMessage, PqTransportError>> _query(
    String name,
    DnsType type,
    Uint8List cookie,
  ) async {
    final id = _rand.nextInt(0x10000);
    final q = DnsMessage(
      id: id,
      flags: dnsFlagCd,
      questions: [DnsQuestion(name: name, type: type)],
      additional: [
        DnsOpt(flags: ednsFlagDo, options: {ednsOptionCookie: cookie}),
      ],
    );
    final encoded = encodeDnsMessage(q);
    if (encoded.isFailure) return Result.failure(encoded.errorOrNull!);
    final query = encoded.valueOrNull!;
    final first = await _once(exchange, query, id, name, type);
    if (first.isFailure) return Result.failure(first.errorOrNull!);
    final msg = first.valueOrNull!;
    if ((msg.flags & dnsFlagTc) == 0) return Result.success(msg);
    if (tcp == null) {
      return Result.failure(PqTransportError.unsupported('truncated dns'));
    }
    final again = await _once(tcp!, query, id, name, type);
    if (again.isFailure) return Result.failure(again.errorOrNull!);
    if ((again.valueOrNull!.flags & dnsFlagTc) != 0) {
      return Result.failure(PqTransportError.unsupported('truncated dns'));
    }
    return again;
  }

  /// RFC 1034. Follows CNAME up to [dnsCnameLimit]. Does not validate.
  Future<Result<DnsMessage, PqTransportError>> resolve(
    String name,
    DnsType type,
  ) => followCname(lookup: lookup, name: name, type: type);

  Future<Result<DnsMessage, PqTransportError>> _once(
    DnsExchange via,
    Uint8List query,
    int id,
    String name,
    DnsType type,
  ) async {
    final exec = await breaker.execute(() => via(query));
    if (exec.isFailure) {
      return Result.failure(
        PqTransportError.circuitOpen(exec.errorOrNull!.toString()),
      );
    }
    final decoded = decodeDnsMessage(exec.valueOrNull!);
    if (decoded.isFailure) return Result.failure(decoded.errorOrNull!);
    final msg = decoded.valueOrNull!;
    if (msg.id != id) {
      return Result.failure(PqTransportError.unexpectedMessage('dns id'));
    }
    if (msg.questions.isNotEmpty) {
      final q = msg.questions.first;
      if (q.type != type || !dnsNamesEqual(q.name, name)) {
        return Result.failure(
          PqTransportError.unexpectedMessage('dns question'),
        );
      }
    }
    return Result.success(msg);
  }
}

/// RFC 7873. Bytes after the echoed 8-byte client cookie, or null.
Uint8List? dnsServerCookie(DnsMessage msg, Uint8List client) {
  if (client.length != 8) return null;
  for (final rr in msg.additional) {
    if (rr is! DnsOpt) continue;
    final raw = rr.options[ednsOptionCookie];
    if (raw == null || raw.length < 16 || raw.length > 40) return null;
    for (var i = 0; i < 8; i++) {
      if (raw[i] != client[i]) return null;
    }
    return Uint8List.sublistView(raw, 8);
  }
  return null;
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

  /// CNAME chase across the same failover as [lookup].
  Future<Result<DnsMessage, PqTransportError>> resolve(
    String name,
    DnsType type,
  ) => followCname(lookup: lookup, name: name, type: type);
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

/// RFC 1034 CNAME chase. Stops when the answer is not a CNAME, or when the
/// target records are already in that message.
Future<Result<DnsMessage, PqTransportError>> followCname({
  required Future<Result<DnsMessage, PqTransportError>> Function(
    String name,
    DnsType type,
  )
  lookup,
  required String name,
  required DnsType type,
}) async {
  var current = name;
  final seen = <String>{};
  for (var hop = 0; hop < dnsCnameLimit; hop++) {
    final id = dnsNameKey(current);
    if (id == null || !seen.add(id)) {
      return Result.failure(PqTransportError.unsupported('cname loop'));
    }
    final msg = await lookup(current, type);
    if (msg.isFailure) return msg;
    if (type == DnsType.cname) return msg;
    final links = [
      for (final rr in msg.valueOrNull!.answers)
        if (rr is DnsCname && dnsNamesEqual(rr.name, current)) rr,
    ];
    if (links.isEmpty) return msg;
    final target = links.first.canonical;
    final here = [
      for (final rr in msg.valueOrNull!.answers)
        if (rr is! DnsCname &&
            rr is! DnsRrsig &&
            rr is! DnsOpt &&
            dnsNamesEqual(rr.name, target) &&
            dnsRecordType(rr) == dnsTypeValue(type))
          rr,
    ];
    if (here.isNotEmpty) return msg;
    current = target;
  }
  return Result.failure(PqTransportError.unsupported('cname limit'));
}
