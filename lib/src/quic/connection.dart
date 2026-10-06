import 'dart:async';
import 'dart:typed_data';

import 'package:swissarmyknife/swissarmyknife.dart';

import '../core/bytes.dart';
import '../core/crypto.dart';
import '../core/errors.dart';
import '../core/hybrid.dart';
import '../core/lengths.dart';
import '../tls/pq_tls_server.dart';
import 'initial.dart';
import 'packet.dart';
import 'stream.dart';
import 'tls_in_quic.dart';

/// QUIC endpoint: RFC 9001 TLS-in-QUIC handshake, then 1-RTT STREAM.
final class PqQuicConn {
  PqQuicConn._({
    required this.crypto,
    required this.isClient,
    required this.localCid,
    required this.peerCid,
    required this._tls,
    required this._deliver,
  }) : _streams = QuicStreamMap(isClient: isClient),
       _flow = QuicFlowControl() {
    final secrets = QuicInitialSecrets.derive(
      crypto: crypto,
      destinationConnectionId: isClient ? peerCid : localCid,
    );
    _initialSeal = QuicInitialCodec(
      crypto: crypto,
      keys: isClient ? secrets.client : secrets.server,
    );
    _initialOpen = QuicInitialCodec(
      crypto: crypto,
      keys: isClient ? secrets.server : secrets.client,
    );
  }

  factory PqQuicConn.client({
    PqTransportCrypto? crypto,
    HybridGroup group = HybridGroup.x25519MlKem768,
    List<String>? alpnProtocols,
    Uint8List? localCid,
    Uint8List? peerCid,
    Future<Result<void, PqTransportError>> Function(Uint8List)? deliver,
  }) {
    final c = crypto ?? const PqTransportCrypto();
    return PqQuicConn._(
      crypto: c,
      isClient: true,
      localCid: localCid ?? c.randomBytes(quicShortDcidBytes),
      peerCid: peerCid ?? c.randomBytes(quicShortDcidBytes),
      tls: QuicTlsHandshake.client(
        crypto: c,
        group: group,
        alpnProtocols: alpnProtocols,
      ),
      deliver: deliver,
    );
  }

  factory PqQuicConn.server({
    PqTransportCrypto? crypto,
    HybridGroup group = HybridGroup.x25519MlKem768,
    PqTlsServerIdentity? identity,
    List<String>? alpnProtocols,
    Uint8List? localCid,
    Uint8List? peerCid,
    Future<Result<void, PqTransportError>> Function(Uint8List)? deliver,
  }) {
    final c = crypto ?? const PqTransportCrypto();
    return PqQuicConn._(
      crypto: c,
      isClient: false,
      localCid: localCid ?? c.randomBytes(quicShortDcidBytes),
      peerCid: peerCid ?? c.randomBytes(quicShortDcidBytes),
      tls: QuicTlsHandshake.server(
        crypto: c,
        group: group,
        identity: identity,
        alpnProtocols: alpnProtocols,
      ),
      deliver: deliver,
    );
  }

  /// Linked in-memory pair. Datagrams are delivered as futures.
  static (PqQuicConn, PqQuicConn) pair({
    PqTransportCrypto? crypto,
    HybridGroup group = HybridGroup.x25519MlKem768,
    PqTlsServerIdentity? identity,
    List<String>? alpnProtocols,
  }) {
    final c = crypto ?? const PqTransportCrypto();
    final id = identity ?? PqTlsServerIdentity.generate(c);
    final clientCid = c.randomBytes(quicShortDcidBytes);
    final serverCid = c.randomBytes(quicShortDcidBytes);
    late final PqQuicConn client;
    late final PqQuicConn server;
    client = PqQuicConn.client(
      crypto: c,
      group: group,
      alpnProtocols: alpnProtocols,
      localCid: clientCid,
      peerCid: serverCid,
      deliver: (p) => server.ingestDatagram(p),
    );
    server = PqQuicConn.server(
      crypto: c,
      group: group,
      identity: id,
      alpnProtocols: alpnProtocols,
      localCid: serverCid,
      peerCid: clientCid,
      deliver: (p) => client.ingestDatagram(p),
    );
    return (client, server);
  }

  final PqTransportCrypto crypto;
  final bool isClient;
  final Uint8List localCid;
  final Uint8List peerCid;
  final QuicTlsHandshake _tls;
  final Future<Result<void, PqTransportError>> Function(Uint8List)? _deliver;
  final QuicStreamMap _streams;
  final QuicFlowControl _flow;
  final List<Uint8List> outgoing = [];
  late final QuicInitialCodec _initialSeal;
  late final QuicInitialCodec _initialOpen;
  QuicPacketCodec? _appSeal;
  QuicPacketCodec? _appOpen;
  Future<void> _inFlight = Future<void>.value();
  var _initialPn = 0;
  var _appPn = 0;
  Completer<void>? _waiter;
  PqTransportError? _error;

  bool get isComplete => _tls.isComplete;
  String? get alpn => _tls.alpn;
  QuicStreamMap get streams => _streams;

  Future<Result<void, PqTransportError>> handshake({
    Duration timeout = const Duration(seconds: 20),
  }) async {
    if (isClient) {
      final started = await start();
      if (started.isFailure) return started;
    }
    final deadline = DateTime.now().add(timeout);
    while (!isComplete) {
      if (DateTime.now().isAfter(deadline)) {
        return Result.failure(
          PqTransportError.handshakeFailure('quic handshake timeout'),
        );
      }
      if (_error != null) return Result.failure(_error!);
      await _waitTick(timeout);
    }
    _ensureAppKeys();
    return const Result.success(null);
  }

  Future<Result<void, PqTransportError>> start() async {
    if (!isClient) {
      return Result.failure(
        PqTransportError.unexpectedMessage('server does not start'),
      );
    }
    final frames = await _tls.start();
    if (frames.isFailure) return Result.failure(frames.errorOrNull!);
    return _sendInitial(frames.valueOrNull!, pad: true);
  }

  Future<Result<void, PqTransportError>> ingestDatagram(Uint8List wire) {
    final done = Completer<Result<void, PqTransportError>>();
    _inFlight = _inFlight.then((_) async {
      try {
        final r = await _ingest(wire);
        if (r.isFailure) _error = r.errorOrNull;
        done.complete(r);
        _wake();
      } on Object catch (e) {
        final err = PqTransportError.internalError('quic ingest $e');
        _error = err;
        done.complete(Result.failure(err));
        _wake();
      }
    });
    return done.future;
  }

  Future<Result<void, PqTransportError>> writeStream(
    int id,
    Uint8List data, {
    bool fin = false,
  }) async {
    if (!isComplete) {
      return Result.failure(
        PqTransportError.handshakeFailure('quic not complete'),
      );
    }
    _ensureAppKeys();
    final flow = _flow.consume(id, data.length);
    if (flow.isFailure) return flow;
    _streams.streams.putIfAbsent(id, () => QuicStreamReassembler(id));
    final sent = _sendOffsets[id] ?? 0;
    final f = QuicStreamFrame(id: id, offset: sent, data: data, fin: fin);
    _sendOffsets[id] = sent + data.length;
    return _sendApp(f.encode());
  }

  final Map<int, int> _sendOffsets = {};

  int openBidi() => _streams.openBidi();
  int openUni() => _streams.openUni();

  Uint8List readStream(int id) {
    final s = _streams.streams[id];
    if (s == null) return Uint8List(0);
    return s.takeAvailable();
  }

  bool streamFin(int id) => _streams.streams[id]?.isFin ?? false;

  bool streamHasData(int id) => _streams.streams[id]?.hasBuffered ?? false;

  Future<Result<void, PqTransportError>> _ingest(Uint8List wire) async {
    if (wire.isEmpty) {
      return Result.failure(PqTransportError.decodeFailure('empty quic'));
    }
    if ((wire[0] & 0x80) != 0 || _appOpen == null) {
      final opened = _initialOpen.open(wire);
      if (opened.isFailure) {
        if (_appOpen != null) {
          return _ingestApp(wire);
        }
        return Result.failure(opened.errorOrNull!);
      }
      final parsed = decodeQuicPayload(opened.valueOrNull!.payload);
      if (parsed.isFailure) return Result.failure(parsed.errorOrNull!);
      for (final c in parsed.valueOrNull!.crypto) {
        final reply = await _tls.ingest(c);
        if (reply.isFailure) return Result.failure(reply.errorOrNull!);
        if (reply.valueOrNull!.isNotEmpty) {
          final sent = await _sendInitial(reply.valueOrNull!, pad: isClient);
          if (sent.isFailure) return sent;
        }
      }
      if (_tls.isComplete) _ensureAppKeys();
      return const Result.success(null);
    }
    return _ingestApp(wire);
  }

  Future<Result<void, PqTransportError>> _ingestApp(Uint8List wire) async {
    final codec = _appOpen;
    if (codec == null) {
      return Result.failure(PqTransportError.decodeFailure('no 1-rtt keys'));
    }
    final opened = codec.open(wire);
    if (opened.isFailure) return Result.failure(opened.errorOrNull!);
    final parsed = decodeQuicPayload(opened.valueOrNull!.payload);
    if (parsed.isFailure) return Result.failure(parsed.errorOrNull!);
    for (final s in parsed.valueOrNull!.streams) {
      final r = _streams.ingest(s);
      if (r.isFailure) return Result.failure(r.errorOrNull!);
    }
    _wake();
    return const Result.success(null);
  }

  Future<Result<void, PqTransportError>> _sendInitial(
    List<QuicCryptoFrame> frames, {
    required bool pad,
  }) async {
    final payload = BytesBuilder(copy: false);
    for (final f in frames) {
      payload.add(f.encode());
    }
    var body = payload.takeBytes();
    if (pad && body.length < quicMinClientInitialUdpBytes) {
      body = concatBytes([
        body,
        Uint8List(quicMinClientInitialUdpBytes - body.length),
      ]);
    }
    final pkt = _initialSeal.protect(
      dcid: peerCid,
      scid: localCid,
      packetNumber: _initialPn++,
      payload: body,
    );
    if (pkt.isFailure) return Result.failure(pkt.errorOrNull!);
    return _emit(pkt.valueOrNull!);
  }

  Future<Result<void, PqTransportError>> _sendApp(Uint8List payload) async {
    final codec = _appSeal;
    if (codec == null) {
      return Result.failure(PqTransportError.decodeFailure('no 1-rtt keys'));
    }
    final pkt = codec.protect(
      dcid: peerCid,
      packetNumber: _appPn++,
      payload: payload,
    );
    if (pkt.isFailure) return Result.failure(pkt.errorOrNull!);
    return _emit(pkt.valueOrNull!);
  }

  Future<Result<void, PqTransportError>> _emit(Uint8List packet) async {
    final deliver = _deliver;
    if (deliver != null) {
      unawaited(Future<void>(() => deliver(packet)));
      return const Result.success(null);
    }
    outgoing.add(packet);
    return const Result.success(null);
  }

  void _ensureAppKeys() {
    if (_appSeal != null || !_tls.isComplete) return;
    final sendSecret = isClient
        ? _tls.schedule.clientApplicationTraffic
        : _tls.schedule.serverApplicationTraffic;
    final recvSecret = isClient
        ? _tls.schedule.serverApplicationTraffic
        : _tls.schedule.clientApplicationTraffic;
    _appSeal = QuicPacketCodec.fromKeys(
      crypto,
      quicKeysFromTls(schedule: _tls.schedule, trafficSecret: sendSecret),
    );
    _appOpen = QuicPacketCodec.fromKeys(
      crypto,
      quicKeysFromTls(schedule: _tls.schedule, trafficSecret: recvSecret),
    );
  }

  Future<void> _waitTick(Duration timeout) async {
    if (isComplete || _error != null) return;
    final c = Completer<void>();
    _waiter = c;
    if (isComplete || _error != null) {
      _wake();
      return;
    }
    try {
      await c.future.timeout(timeout);
    } on TimeoutException {
      return;
    }
  }

  void _wake() {
    final w = _waiter;
    _waiter = null;
    if (w != null && !w.isCompleted) w.complete();
  }
}
