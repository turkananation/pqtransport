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
import 'recovery.dart';
import 'stream.dart';
import 'tls_in_quic.dart';

/// QUIC endpoint: RFC 9001 TLS-in-QUIC, then 1-RTT STREAM, with RFC 9002
/// loss detection and NewReno.
///
/// Lost CRYPTO and STREAM bytes are sealed again under a new packet number
/// (RFC 9000 §13.3). The congestion window is [QuicNewReno]. A client
/// Initial is padded so the UDP datagram is at least 1200 bytes
/// (RFC 9000 §14.1); the frame payload is not padded to 1200 and then
/// wrapped. This object does
/// not start a [Timer] by itself: call [driveLossRecovery] when
/// [QuicLossRecovery.lossDetectionDeadline] is due, or [bindLossTimer] to arm
/// a wall-clock timer. A [QuicManualClock] does not move that timer; tests
/// advance the clock and call [driveLossRecovery].
///
/// Handshake packet-protection keys are not minted here. Initial and
/// Application Data are tracked. The Handshake space exists on
/// [lossRecovery] for a caller that has those keys.
final class PqQuicConn {
  PqQuicConn._({
    required this.crypto,
    required this.isClient,
    required this.localCid,
    required this.peerCid,
    required this._tls,
    required this._deliver,
    QuicClock? clock,
    int maxDatagramSize = quicMinClientInitialUdpBytes,
    int maxData = quicMaxDataDefault,
    int maxStreamData = quicMaxStreamDataDefault,
    int? sendMaxData,
    int? sendMaxStreamData,
    int? recvMaxData,
    int? recvMaxStreamData,
    this.flowWindow = 0,
    this.idleTimeout,
  }) : lossRecovery = QuicLossRecovery(
         clock: clock ?? const QuicSystemClock(),
         isServer: !isClient,
         maxDatagramSize: maxDatagramSize,
       ),
       _streams = QuicStreamMap(isClient: isClient),
       _flow = QuicFlowControl(
         maxData: maxData,
         maxStreamData: maxStreamData,
         sendMaxData: sendMaxData,
         sendMaxStreamData: sendMaxStreamData,
         recvMaxData: recvMaxData,
         recvMaxStreamData: recvMaxStreamData,
       ),
       _connMachine = quicConnMachine() {
    _connMachine.trigger(QuicConnectionEvent.start);
    _lastActivity = lossRecovery.clock.now();
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
    QuicClock? clock,
    int maxDatagramSize = quicMinClientInitialUdpBytes,
    int maxData = quicMaxDataDefault,
    int maxStreamData = quicMaxStreamDataDefault,
    int? sendMaxData,
    int? sendMaxStreamData,
    int? recvMaxData,
    int? recvMaxStreamData,
    int flowWindow = 0,
    Duration? idleTimeout,
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
      clock: clock,
      maxDatagramSize: maxDatagramSize,
      maxData: maxData,
      maxStreamData: maxStreamData,
      sendMaxData: sendMaxData,
      sendMaxStreamData: sendMaxStreamData,
      recvMaxData: recvMaxData,
      recvMaxStreamData: recvMaxStreamData,
      flowWindow: flowWindow,
      idleTimeout: idleTimeout,
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
    QuicClock? clock,
    int maxDatagramSize = quicMinClientInitialUdpBytes,
    int maxData = quicMaxDataDefault,
    int maxStreamData = quicMaxStreamDataDefault,
    int? sendMaxData,
    int? sendMaxStreamData,
    int? recvMaxData,
    int? recvMaxStreamData,
    int flowWindow = 0,
    Duration? idleTimeout,
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
      clock: clock,
      maxDatagramSize: maxDatagramSize,
      maxData: maxData,
      maxStreamData: maxStreamData,
      sendMaxData: sendMaxData,
      sendMaxStreamData: sendMaxStreamData,
      recvMaxData: recvMaxData,
      recvMaxStreamData: recvMaxStreamData,
      flowWindow: flowWindow,
      idleTimeout: idleTimeout,
    );
  }

  /// Linked in-memory pair. Datagrams are delivered as futures.
  static (PqQuicConn, PqQuicConn) pair({
    PqTransportCrypto? crypto,
    HybridGroup group = HybridGroup.x25519MlKem768,
    PqTlsServerIdentity? identity,
    List<String>? alpnProtocols,
    QuicClock? clock,
    int maxDatagramSize = quicMinClientInitialUdpBytes,
    int maxData = quicMaxDataDefault,
    int maxStreamData = quicMaxStreamDataDefault,
    int flowWindow = 0,
    Duration? idleTimeout,
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
      clock: clock,
      maxDatagramSize: maxDatagramSize,
      maxData: maxData,
      maxStreamData: maxStreamData,
      flowWindow: flowWindow,
      idleTimeout: idleTimeout,
    );
    server = PqQuicConn.server(
      crypto: c,
      group: group,
      identity: id,
      alpnProtocols: alpnProtocols,
      localCid: serverCid,
      peerCid: clientCid,
      deliver: (p) => client.ingestDatagram(p),
      clock: clock,
      maxDatagramSize: maxDatagramSize,
      maxData: maxData,
      maxStreamData: maxStreamData,
      flowWindow: flowWindow,
      idleTimeout: idleTimeout,
    );
    return (client, server);
  }

  final PqTransportCrypto crypto;
  final bool isClient;
  final Uint8List localCid;
  final Uint8List peerCid;

  /// RFC 9002 loss detection and the NewReno window for this endpoint.
  final QuicLossRecovery lossRecovery;

  final QuicTlsHandshake _tls;
  final Future<Result<void, PqTransportError>> Function(Uint8List)? _deliver;
  final QuicStreamMap _streams;
  final QuicFlowControl _flow;
  final int flowWindow;
  final Duration? idleTimeout;
  final StateMachine<QuicConnectionState, QuicConnectionEvent> _connMachine;
  final List<_QuicStalledSend> _stalled = [];
  late DateTime _lastActivity;
  DateTime? _drainUntil;
  final List<Uint8List> outgoing = [];
  final List<QuicRetransmittable> _pending = [];
  final Map<QuicPacketNumberSpace, QuicAckProcessor> _received = {
    for (final space in QuicPacketNumberSpace.values) space: QuicAckProcessor(),
  };
  final Map<QuicPacketNumberSpace, bool> _wantAck = {
    for (final space in QuicPacketNumberSpace.values) space: false,
  };
  final List<QuicLossSubscription> _lossTimers = [];
  final Map<int, int> _sendOffsets = {};
  late final QuicInitialCodec _initialSeal;
  late final QuicInitialCodec _initialOpen;
  QuicPacketCodec? _appSeal;
  QuicPacketCodec? _appOpen;
  Future<void> _inFlight = Future<void>.value();
  Completer<void>? _waiter;
  PqTransportError? _error;
  var _markedConfirmed = false;
  var _initialDiscarded = false;

  bool get isComplete => _tls.isComplete;
  String? get alpn => _tls.alpn;
  QuicStreamMap get streams => _streams;
  QuicConnectionState get connectionState => _connMachine.currentState;
  bool get isDraining => connectionState == QuicConnectionState.draining;
  bool get isClosed =>
      connectionState == QuicConnectionState.closed ||
      connectionState == QuicConnectionState.failed;
  bool get _terminal => isDraining || isClosed;

  /// Application error code from a received or local RESET_STREAM.
  int? streamResetCode(int id) => _streams.streams[id]?.resetCode;

  /// STREAM bytes accepted by [writeStream] and not yet sealed into a packet.
  int get pendingApplicationBytes {
    var total = 0;
    for (final frame in _pending) {
      if (frame is QuicRetransmitStream) total += frame.data.length;
    }
    return total;
  }

  /// Arm a wall-clock timer for [driveLossRecovery]. Cancel the returned
  /// subscription when the endpoint is finished. No-op for a
  /// [QuicManualClock]; advance that clock and call [driveLossRecovery].
  QuicLossSubscription bindLossTimer() {
    final sub = QuicLossSubscription._(this);
    _lossTimers.add(sub);
    _armBoundTimers();
    return sub;
  }

  /// Run RFC 9002 Appendix A.9 if the loss-detection deadline has passed.
  Future<Result<void, PqTransportError>> driveLossRecovery() {
    final done = Completer<Result<void, PqTransportError>>();
    _inFlight = _inFlight.then((_) async {
      try {
        final driven = await _driveLossRecovery();
        if (driven.isFailure) _error = driven.errorOrNull;
        done.complete(driven);
        _wake();
      } on Object catch (e) {
        final err = PqTransportError.internalError('quic recovery $e');
        _error = err;
        done.complete(Result.failure(err));
        _wake();
      }
    });
    return done.future;
  }

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
    _syncHandshake();
    return const Result.success(null);
  }

  Future<Result<void, PqTransportError>> start() {
    final done = Completer<Result<void, PqTransportError>>();
    _inFlight = _inFlight.then((_) async {
      try {
        final started = await _start();
        if (started.isFailure) _error = started.errorOrNull;
        done.complete(started);
        _wake();
      } on Object catch (e) {
        final err = PqTransportError.internalError('quic start $e');
        _error = err;
        done.complete(Result.failure(err));
        _wake();
      }
    });
    return done.future;
  }

  Future<Result<void, PqTransportError>> _start() async {
    if (!isClient) {
      return Result.failure(
        PqTransportError.unexpectedMessage('server does not start'),
      );
    }
    final frames = await _tls.start();
    if (frames.isFailure) return Result.failure(frames.errorOrNull!);
    for (final frame in frames.valueOrNull!) {
      _pending.add(
        QuicRetransmitCrypto(
          space: QuicPacketNumberSpace.initial,
          offset: frame.offset,
          data: frame.data,
        ),
      );
    }
    return _flush();
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
  }) {
    final done = Completer<Result<void, PqTransportError>>();
    _inFlight = _inFlight.then((_) async {
      try {
        final wrote = await _writeStream(id, data, fin: fin);
        done.complete(wrote);
        _wake();
      } on Object catch (e) {
        final err = PqTransportError.internalError('quic write $e');
        _error = err;
        done.complete(Result.failure(err));
        _wake();
      }
    });
    return done.future;
  }

  Future<Result<void, PqTransportError>> _writeStream(
    int id,
    Uint8List data, {
    required bool fin,
  }) async {
    if (!isComplete) {
      return Result.failure(
        PqTransportError.handshakeFailure('quic not complete'),
      );
    }
    if (_terminal) {
      return Result.failure(PqTransportError.closed('quic closed'));
    }
    if (_error != null) return Result.failure(_error!);
    final idle = _checkIdle();
    if (idle != null) return Result.failure(idle);
    _syncHandshake();
    final existing = _streams.streams[id];
    if (existing != null && existing.isReset) {
      return Result.failure(PqTransportError.closed('stream reset'));
    }
    _streams.streams.putIfAbsent(id, () => QuicStreamReassembler(id));
    final queued = _enqueueSend(id, data, fin: fin);
    if (queued.isFailure) return queued;
    return _flush();
  }

  Result<void, PqTransportError> _enqueueSend(
    int id,
    Uint8List data, {
    required bool fin,
  }) {
    final room = lossRecovery.maxDatagramPayload;
    if (room < 1) {
      return Result.failure(
        PqTransportError.internalError('quic datagram payload'),
      );
    }
    final base = _sendOffsets[id] ?? 0;
    if (data.isEmpty) {
      _pending.add(
        QuicRetransmitStream(
          streamId: id,
          offset: base,
          data: Uint8List(0),
          fin: fin,
        ),
      );
      return const Result.success(null);
    }
    final budget = _flow.budget(
      streamId: id,
      offset: base,
      length: data.length,
    );
    if (budget.allowed > 0) {
      final take = Uint8List.sublistView(data, 0, budget.allowed);
      var off = 0;
      while (off < take.length) {
        final rest = take.length - off;
        final n = rest < room ? rest : room;
        _pending.add(
          QuicRetransmitStream(
            streamId: id,
            offset: base + off,
            data: Uint8List.fromList(take.sublist(off, off + n)),
            fin: fin && budget.allowed == data.length && off + n == take.length,
          ),
        );
        off += n;
      }
      _flow.commitSend(id, base + budget.allowed);
      _sendOffsets[id] = base + budget.allowed;
    }
    if (budget.allowed < data.length) {
      _stalled.add(
        _QuicStalledSend(id, Uint8List.sublistView(data, budget.allowed), fin),
      );
      _queueBlocked(id, budget);
    }
    return const Result.success(null);
  }

  void _queueBlocked(int id, QuicSendBudget budget) {
    if (budget.connectionBlocked) {
      final limit = _flow.peerMaxData;
      _queueControl('db:$limit', QuicDataBlockedFrame(limit).encode());
    }
    if (budget.streamBlocked) {
      final limit = _flow.peerStreamMax(id);
      _queueControl(
        'sb:$id:$limit',
        QuicStreamDataBlockedFrame(id, limit).encode(),
      );
    }
  }

  void _queueControl(String token, Uint8List bytes) {
    if (_pending.any((frame) => frame.token == token)) return;
    _pending.add(
      QuicRetransmitFrame(
        space: QuicPacketNumberSpace.application,
        token: token,
        bytes: bytes,
      ),
    );
  }

  void _releaseStalled() {
    if (_stalled.isEmpty || _terminal) return;
    final waiting = List<_QuicStalledSend>.of(_stalled);
    _stalled.clear();
    for (final item in waiting) {
      _enqueueSend(item.id, item.data, fin: item.fin);
    }
  }

  int openBidi() => _streams.openBidi();
  int openUni() => _streams.openUni();

  Uint8List readStream(int id) {
    final s = _streams.streams[id];
    if (s == null) return Uint8List(0);
    final bytes = s.takeAvailable();
    if (bytes.isNotEmpty && !_terminal) {
      for (final frame in _flow.onConsumed(
        streamId: id,
        bytes: bytes.length,
        window: flowWindow,
      )) {
        _queueControl('ad:$id:${frame[0]}:${frame.length}', frame);
      }
    }
    return bytes;
  }

  /// Seal MAX_DATA / MAX_STREAM_DATA queued by [readStream].
  Future<Result<void, PqTransportError>> flushControl() {
    final done = Completer<Result<void, PqTransportError>>();
    _inFlight = _inFlight.then((_) async {
      try {
        if (_terminal) {
          done.complete(Result.failure(PqTransportError.closed('quic closed')));
        } else {
          done.complete(await _flush());
        }
        _wake();
      } on Object catch (e) {
        final err = PqTransportError.internalError('quic flush $e');
        _error = err;
        done.complete(Result.failure(err));
        _wake();
      }
    });
    return done.future;
  }

  /// RFC 9000 §19.4. [errorCode] is an application error.
  Future<Result<void, PqTransportError>> resetStream(int id, int errorCode) {
    final done = Completer<Result<void, PqTransportError>>();
    _inFlight = _inFlight.then((_) async {
      try {
        final reset = await _resetStream(id, errorCode);
        done.complete(reset);
        _wake();
      } on Object catch (e) {
        final err = PqTransportError.internalError('quic reset $e');
        _error = err;
        done.complete(Result.failure(err));
        _wake();
      }
    });
    return done.future;
  }

  Future<Result<void, PqTransportError>> _resetStream(
    int id,
    int errorCode,
  ) async {
    if (!isComplete) {
      return Result.failure(
        PqTransportError.handshakeFailure('quic not complete'),
      );
    }
    if (_terminal) {
      return Result.failure(PqTransportError.closed('quic closed'));
    }
    final stream = _streams.streams.putIfAbsent(
      id,
      () => QuicStreamReassembler(id),
    );
    final marked = stream.reset(errorCode);
    if (marked.isFailure) return marked;
    _stalled.removeWhere((item) => item.id == id);
    final finalSize = _sendOffsets[id] ?? 0;
    _queueControl(
      'rst:$id:$errorCode:$finalSize',
      QuicResetStreamFrame(
        id: id,
        errorCode: errorCode,
        finalSize: finalSize,
      ).encode(),
    );
    return _flush();
  }

  /// RFC 9000 §10.2. Sends CONNECTION_CLOSE, then discards inbound
  /// packets until three times the current PTO have passed.
  Future<Result<void, PqTransportError>> close({
    int errorCode = quicErrorNoError,
    bool application = true,
  }) {
    final done = Completer<Result<void, PqTransportError>>();
    _inFlight = _inFlight.then((_) async {
      try {
        done.complete(
          await _close(errorCode: errorCode, application: application),
        );
        _wake();
      } on Object catch (e) {
        final err = PqTransportError.internalError('quic close $e');
        _error = err;
        done.complete(Result.failure(err));
        _wake();
      }
    });
    return done.future;
  }

  Future<Result<void, PqTransportError>> _close({
    required int errorCode,
    required bool application,
  }) async {
    if (isClosed) {
      return Result.failure(
        PqTransportError.unexpectedMessage('quic already closed'),
      );
    }
    if (isDraining) {
      return Result.failure(
        PqTransportError.unexpectedMessage('quic already draining'),
      );
    }
    _syncHandshake();
    final frame = QuicConnectionCloseFrame(
      application: application,
      errorCode: errorCode,
    ).encode();
    _pending
      ..clear()
      ..add(
        QuicRetransmitFrame(
          space: isComplete
              ? QuicPacketNumberSpace.application
              : QuicPacketNumberSpace.initial,
          token: 'close:$errorCode',
          bytes: frame,
        ),
      );
    _stalled.clear();
    final sent = await _flush(ignoreWindowPackets: 1);
    _enterDrain();
    return sent;
  }

  bool streamFin(int id) => _streams.streams[id]?.isFin ?? false;

  bool streamHasData(int id) => _streams.streams[id]?.hasBuffered ?? false;

  Future<Result<void, PqTransportError>> _driveLossRecovery() async {
    final idle = _checkIdle();
    if (idle != null) return Result.failure(idle);
    final drained = _checkDrain();
    if (drained != null) return Result.failure(drained);
    if (_error != null) return Result.failure(_error!);
    final event = lossRecovery.onLossDetectionTimeout();
    if (event.isFailure) return Result.failure(event.errorOrNull!);
    final applied = await _apply(event.valueOrNull!);
    _armBoundTimers();
    return applied;
  }

  Future<Result<void, PqTransportError>> _ingest(Uint8List wire) async {
    if (_terminal) {
      final drained = _checkDrain();
      if (drained != null) return Result.failure(drained);
      return const Result.success(null);
    }
    final idle = _checkIdle();
    if (idle != null) return Result.failure(idle);
    if (wire.isEmpty) {
      return Result.failure(PqTransportError.decodeFailure('empty quic'));
    }
    if ((wire[0] & 0x80) != 0 || _appOpen == null) {
      final opened = _initialOpen.open(wire);
      if (opened.isFailure) {
        if (_appOpen != null) return _ingestApp(wire);
        return Result.failure(opened.errorOrNull!);
      }
      final packet = opened.valueOrNull!;
      return _accept(
        space: QuicPacketNumberSpace.initial,
        packetNumber: packet.packetNumber,
        payload: packet.payload,
      );
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
    final packet = opened.valueOrNull!;
    return _accept(
      space: QuicPacketNumberSpace.application,
      packetNumber: packet.packetNumber,
      payload: packet.payload,
    );
  }

  Future<Result<void, PqTransportError>> _accept({
    required QuicPacketNumberSpace space,
    required int packetNumber,
    required Uint8List payload,
  }) async {
    final parsed = decodeQuicPayload(payload);
    if (parsed.isFailure) return Result.failure(parsed.errorOrNull!);
    final body = parsed.valueOrNull!;
    final recv = _received[space]!;
    final duplicate = recv.received.contains(packetNumber);
    recv.onReceived(packetNumber);
    if (body.ackEliciting) _wantAck[space] = true;
    if (!duplicate) {
      if (body.closes.isNotEmpty) {
        _enterDrain();
        return const Result.success(null);
      }
      for (final frame in body.crypto) {
        final reply = await _tls.ingest(frame);
        if (reply.isFailure) return Result.failure(reply.errorOrNull!);
        for (final cryptoFrame in reply.valueOrNull!) {
          _pending.add(
            QuicRetransmitCrypto(
              space: QuicPacketNumberSpace.initial,
              offset: cryptoFrame.offset,
              data: cryptoFrame.data,
            ),
          );
        }
      }
      for (final frame in body.streams) {
        if (frame.data.isNotEmpty) {
          final limited = _flow.receive(
            frame.id,
            frame.offset + frame.data.length,
          );
          if (limited.isFailure) {
            await _close(errorCode: quicErrorFlowControl, application: false);
            return limited;
          }
        }
        final ingested = _streams.ingest(frame);
        if (ingested.isFailure) return Result.failure(ingested.errorOrNull!);
      }
      for (final frame in body.maxData) {
        _flow.onMaxData(frame.maximum);
      }
      for (final frame in body.maxStreamData) {
        _flow.onMaxStreamData(frame.id, frame.maximum);
      }
      for (final frame in body.resets) {
        final stream = _streams.streams.putIfAbsent(
          frame.id,
          () => QuicStreamReassembler(frame.id),
        );
        final marked = stream.reset(frame.errorCode);
        if (marked.isFailure) return marked;
      }
      _releaseStalled();
      for (final ack in body.acks) {
        final event = lossRecovery.onAck(space, ack);
        if (event.isFailure) return Result.failure(event.errorOrNull!);
        final applied = await _apply(event.valueOrNull!);
        if (applied.isFailure) return applied;
      }
    }
    _syncHandshake();
    _noteActivity();
    _wake();
    return _flush();
  }

  Future<Result<void, PqTransportError>> _apply(QuicRecoveryEvent event) async {
    for (final frame in event.retransmit) {
      if (!lossRecovery.shouldSend(frame)) continue;
      if (_pending.any((queued) => queued.token == frame.token)) continue;
      _pending.add(frame);
    }
    // §7.3.2 allows one packet when entering recovery. §6.2.4 allows up
    // to two ack-eliciting probes on PTO. Both ignore the window.
    var ignoreWindowPackets = event.congestionProbe ? 1 : 0;
    final probe = event.probeSpace;
    if (probe != null) {
      var queued = 0;
      for (final frame in _pending) {
        if (frame.space == probe && lossRecovery.shouldSend(frame)) queued++;
      }
      if (queued < quicPtoProbePackets) {
        var at = 0;
        for (final frame in lossRecovery.oldestInFlightData(probe)) {
          if (queued >= quicPtoProbePackets) break;
          if (_pending.any((queuedFrame) => queuedFrame.token == frame.token)) {
            continue;
          }
          _pending.insert(at, frame);
          at++;
          queued++;
        }
      }
      if (queued == 0) {
        _pending.insert(0, QuicRetransmitPing(probe));
        queued = 1;
      }
      final probes = queued < quicPtoProbePackets
          ? queued
          : quicPtoProbePackets;
      if (probes > ignoreWindowPackets) ignoreWindowPackets = probes;
    }
    return _flush(ignoreWindowPackets: ignoreWindowPackets);
  }

  Future<Result<void, PqTransportError>> _flush({
    int ignoreWindowPackets = 0,
  }) async {
    var bypassLeft = ignoreWindowPackets;
    while (true) {
      _pending.removeWhere((frame) => !lossRecovery.shouldSend(frame));
      if (_pending.isEmpty) break;
      final space = _pending.first.space;
      final batch = _batchFor(space);
      if (batch.isEmpty) break;
      final sent = await _sendPacket(
        space: space,
        frames: batch,
        ignoreWindow: bypassLeft > 0,
      );
      if (sent.isFailure) return Result.failure(sent.errorOrNull!);
      if (sent.valueOrNull != true) break;
      final tokens = batch.map((frame) => frame.token).toSet();
      _pending.removeWhere((frame) => tokens.contains(frame.token));
      if (bypassLeft > 0) bypassLeft--;
    }
    for (final space in QuicPacketNumberSpace.values) {
      if (_wantAck[space] != true) continue;
      final sent = await _sendPacket(
        space: space,
        frames: const [],
        ignoreWindow: false,
      );
      if (sent.isFailure) return Result.failure(sent.errorOrNull!);
    }
    _syncHandshake();
    _armBoundTimers();
    return const Result.success(null);
  }

  List<QuicRetransmittable> _batchFor(QuicPacketNumberSpace space) {
    final batch = <QuicRetransmittable>[];
    var bytes = 0;
    for (final frame in _pending) {
      if (frame.space != space) continue;
      final size = frame.encode().length;
      final cap = space == QuicPacketNumberSpace.application;
      if (cap &&
          batch.isNotEmpty &&
          bytes + size > lossRecovery.maxDatagramPayload) {
        break;
      }
      batch.add(frame);
      bytes += size;
    }
    return batch;
  }

  Future<Result<bool, PqTransportError>> _sendPacket({
    required QuicPacketNumberSpace space,
    required List<QuicRetransmittable> frames,
    required bool ignoreWindow,
  }) async {
    if (space == QuicPacketNumberSpace.handshake) {
      return Result.failure(
        PqTransportError.unsupported(
          'Handshake packet protection keys are not minted',
        ),
      );
    }
    if (frames.isEmpty && _wantAck[space] != true) {
      return const Result.success(true);
    }
    final pad = space == QuicPacketNumberSpace.initial && isClient;
    final eliciting = frames.isNotEmpty;
    final inFlight = eliciting || pad;
    final builder = BytesBuilder(copy: false);
    final includeAck = _wantAck[space] == true;
    if (includeAck) {
      final ack = _received[space]!.pendingAck();
      if (ack.isSuccess) builder.add(ack.valueOrNull!.encode());
    }
    for (final frame in frames) {
      builder.add(frame.encode());
    }
    var body = builder.takeBytes();
    if (body.isEmpty) {
      _wantAck[space] = false;
      return const Result.success(true);
    }
    if (pad) {
      final target = quicClientInitialPayloadBytes(
        dcidLength: peerCid.length,
        scidLength: localCid.length,
        payloadLength: body.length,
      );
      if (body.length < target) {
        body = concatBytes([body, Uint8List(target - body.length)]);
      }
    }
    if (space == QuicPacketNumberSpace.application) {
      _ensureAppKeys();
      if (_appSeal == null) {
        return Result.failure(PqTransportError.decodeFailure('no 1-rtt keys'));
      }
    }
    final pn = lossRecovery.peekPacketNumber(space);
    final Result<Uint8List, PqTransportError> sealed;
    if (space == QuicPacketNumberSpace.initial) {
      sealed = _initialSeal.protect(
        dcid: peerCid,
        scid: localCid,
        packetNumber: pn,
        payload: body,
      );
    } else {
      final codec = _appSeal;
      if (codec == null) {
        return Result.failure(PqTransportError.decodeFailure('no 1-rtt keys'));
      }
      sealed = codec.protect(dcid: peerCid, packetNumber: pn, payload: body);
    }
    if (sealed.isFailure) return Result.failure(sealed.errorOrNull!);
    final packet = sealed.valueOrNull!;
    if (!lossRecovery.canSend(
      packet.length,
      probe: ignoreWindow,
      inFlight: inFlight,
    )) {
      return const Result.success(false);
    }
    final committed = lossRecovery.allocatePacketNumber(space);
    if (committed != pn) {
      return Result.failure(
        PqTransportError.internalError('packet number changed'),
      );
    }
    final inFlightBefore = lossRecovery.bytesInFlight;
    final more = _pending.length > frames.length;
    final recorded = lossRecovery.onPacketSent(
      space: space,
      packetNumber: pn,
      sentBytes: packet.length,
      ackEliciting: eliciting,
      inFlight: inFlight,
      frames: frames,
      probe: ignoreWindow,
      appLimited:
          !ignoreWindow &&
          inFlight &&
          !more &&
          inFlightBefore + packet.length < lossRecovery.congestionWindow,
    );
    if (recorded.isFailure) {
      if (recorded.errorOrNull!.code == PqTransportErrorCode.throttled) {
        return const Result.success(false);
      }
      return Result.failure(recorded.errorOrNull!);
    }
    if (includeAck) _wantAck[space] = false;
    final emitted = await _emit(packet);
    if (emitted.isFailure) return Result.failure(emitted.errorOrNull!);
    _noteActivity();
    return const Result.success(true);
  }

  Future<Result<void, PqTransportError>> _emit(Uint8List packet) async {
    final deliver = _deliver;
    if (deliver != null) {
      unawaited(deliver(packet));
      return const Result.success(null);
    }
    outgoing.add(packet);
    return const Result.success(null);
  }

  void _syncHandshake() {
    if (!_tls.isComplete) return;
    _ensureAppKeys();
    if (!_markedConfirmed) {
      _markedConfirmed = true;
      lossRecovery.markHandshakeConfirmed();
      if (_connMachine.currentState == QuicConnectionState.handshake) {
        _connMachine.trigger(QuicConnectionEvent.handshakeDone);
      }
    }
    if (_initialDiscarded) return;
    if (_pending.any((frame) => frame.space == QuicPacketNumberSpace.initial)) {
      return;
    }
    if (lossRecovery.hasInFlight(QuicPacketNumberSpace.initial)) return;
    _initialDiscarded = true;
    lossRecovery.onPacketNumberSpaceDiscarded(QuicPacketNumberSpace.initial);
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
      aead: _tls.schedule.aead,
    );
    _appOpen = QuicPacketCodec.fromKeys(
      crypto,
      quicKeysFromTls(schedule: _tls.schedule, trafficSecret: recvSecret),
      aead: _tls.schedule.aead,
    );
  }

  void _noteActivity() {
    _lastActivity = lossRecovery.clock.now();
  }

  PqTransportError? _checkIdle() {
    final limit = idleTimeout;
    if (limit == null || _terminal) return null;
    if (lossRecovery.clock.now().difference(_lastActivity) < limit) {
      return null;
    }
    _silentClose();
    return PqTransportError.closed('idle timeout');
  }

  void _silentClose() {
    _pending.clear();
    _stalled.clear();
    final state = _connMachine.currentState;
    if (state == QuicConnectionState.ready ||
        state == QuicConnectionState.handshake ||
        state == QuicConnectionState.idle) {
      _connMachine.trigger(QuicConnectionEvent.close);
    }
    _error = PqTransportError.closed('idle timeout');
  }

  PqTransportError? _checkDrain() {
    final until = _drainUntil;
    if (until == null) return null;
    if (lossRecovery.clock.now().isBefore(until)) return null;
    if (connectionState == QuicConnectionState.draining) {
      _connMachine.trigger(QuicConnectionEvent.close);
    }
    _error = PqTransportError.closed('drained');
    return _error;
  }

  void _enterDrain() {
    _pending.clear();
    _stalled.clear();
    final state = _connMachine.currentState;
    if (state == QuicConnectionState.ready) {
      _connMachine.trigger(QuicConnectionEvent.drain);
    } else if (state == QuicConnectionState.handshake ||
        state == QuicConnectionState.idle) {
      _connMachine.trigger(QuicConnectionEvent.close);
      _error = PqTransportError.closed('quic closed');
      return;
    }
    final micros = lossRecovery.ptoMicros * quicDrainPtoMultiplier;
    _drainUntil = lossRecovery.clock.now().add(Duration(microseconds: micros));
    _error = PqTransportError.closed('quic draining');
  }

  void _armBoundTimers() {
    if (_lossTimers.isEmpty) return;
    if (lossRecovery.clock is! QuicSystemClock) return;
    final deadline = lossRecovery.lossDetectionDeadline;
    for (final sub in _lossTimers) {
      sub._arm(deadline);
    }
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

/// Wall-clock subscription from [PqQuicConn.bindLossTimer].
final class QuicLossSubscription {
  QuicLossSubscription._(this._conn);

  final PqQuicConn _conn;
  Timer? _timer;
  var _cancelled = false;

  void cancel() {
    _cancelled = true;
    _timer?.cancel();
    _timer = null;
    _conn._lossTimers.remove(this);
  }

  void _arm(DateTime? deadline) {
    _timer?.cancel();
    _timer = null;
    if (_cancelled || deadline == null) return;
    var delay = deadline.difference(DateTime.now());
    if (delay.isNegative) delay = Duration.zero;
    _timer = Timer(delay, () {
      if (_cancelled) return;
      unawaited(_conn.driveLossRecovery());
    });
  }
}

final class _QuicStalledSend {
  _QuicStalledSend(this.id, this.data, this.fin);

  final int id;
  final Uint8List data;
  final bool fin;
}
