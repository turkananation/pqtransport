import 'dart:async';
import 'dart:typed_data';

import 'package:swissarmyknife/swissarmyknife.dart';

import '../core/bytes.dart';
import '../core/crypto.dart';
import '../core/errors.dart';
import '../core/hybrid.dart';
import '../core/lengths.dart';
import '../tls/handshake.dart';
import '../tls/pq_tls_server.dart';
import '../tls/resumption.dart';
import 'datagram.dart';
import 'initial.dart';
import 'packet.dart';
import 'recovery.dart';
import 'stream.dart';
import 'tls_in_quic.dart';
import 'transport_params.dart';
import 'zero_rtt.dart';

/// QUIC endpoint: RFC 9001 TLS-in-QUIC, 0-RTT, then 1-RTT STREAM, with
/// RFC 9002 loss detection and NewReno.
///
/// 0-RTT is a long header in the Application Data packet number space.
/// Call [writeEarly] before [start]. Those bytes are replayable until
/// the handshake accepts them. A replayed ticket completes and carries
/// no early data.
///
/// Lost CRYPTO and STREAM bytes are sealed again under a new packet number
/// (RFC 9000 §13.3). The congestion window is [QuicNewReno]. A UDP datagram
/// stays within [QuicLossRecovery.maxDatagramSize] (1200 until the path is
/// measured, RFC 9000 §14). A datagram that carries a client Initial is
/// padded to 1200 bytes. The server answers with at most three times the
/// bytes it has received until a Handshake packet validates the address
/// (RFC 9000 §8.1). Handshake packets use the TLS handshake traffic
/// secrets (RFC 9001 §5.3). 1-RTT follows. This object does
/// not start a [Timer] by itself: call [driveLossRecovery] when
/// [QuicLossRecovery.lossDetectionDeadline] is due, or [bindLossTimer] to arm
/// a wall-clock timer. A [QuicManualClock] does not move that timer; tests
/// advance the clock and call [driveLossRecovery].
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
    this._resumption,
    this._statelessResetToken,
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
       _connMachine = quicConnMachine(),
       _originalDcid = Uint8List.fromList(peerCid),
       _dcid = Uint8List.fromList(peerCid),
       _peerInitialSource = Uint8List.fromList(peerCid) {
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
    QuicResumptionTicket? ticket,
    List<TlsCertificateType>? certificateTypes,
    List<Uint8List> trustAnchors = const [],
    String? serverName,
    List<int>? signatureSchemes,
  }) {
    final c = crypto ?? const PqTransportCrypto();
    final local = localCid ?? c.randomBytes(quicShortDcidBytes);
    final peer = peerCid ?? c.randomBytes(quicShortDcidBytes);
    return PqQuicConn._(
      crypto: c,
      isClient: true,
      localCid: local,
      peerCid: peer,
      tls: QuicTlsHandshake.client(
        crypto: c,
        group: group,
        alpnProtocols: alpnProtocols,
        ticket: ticket,
        transportParameters: quicEndpointParameters(
          server: false,
          localCid: local,
          maxData: recvMaxData ?? maxData,
          maxStreamData: recvMaxStreamData ?? maxStreamData,
          maxIdleTimeoutMs: idleTimeout?.inMilliseconds ?? 0,
        ),
        certificateTypes: certificateTypes,
        trustAnchors: trustAnchors,
        serverName: serverName,
        signatureSchemes: signatureSchemes,
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
      resumption: ticket,
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
    QuicEarlyDataStore? earlyData,
  }) {
    final c = crypto ?? const PqTransportCrypto();
    final local = localCid ?? c.randomBytes(quicShortDcidBytes);
    final peer = peerCid ?? c.randomBytes(quicShortDcidBytes);
    final reset = c.randomBytes(quicStatelessResetTokenBytes);
    return PqQuicConn._(
      crypto: c,
      isClient: false,
      localCid: local,
      peerCid: peer,
      tls: QuicTlsHandshake.server(
        crypto: c,
        group: group,
        identity: identity,
        alpnProtocols: alpnProtocols,
        earlyData: earlyData,
        transportParameters: quicEndpointParameters(
          server: true,
          localCid: local,
          maxData: recvMaxData ?? maxData,
          maxStreamData: recvMaxStreamData ?? maxStreamData,
          statelessResetToken: reset,
          maxIdleTimeoutMs: idleTimeout?.inMilliseconds ?? 0,
        ),
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
      statelessResetToken: reset,
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
    QuicResumptionTicket? ticket,
    QuicEarlyDataStore? earlyData,
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
      ticket: ticket,
    );
    server = PqQuicConn.server(
      crypto: c,
      group: group,
      identity: id,
      earlyData: earlyData,
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
  Uint8List _dcid;

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
  late QuicInitialCodec _initialSeal;
  late QuicInitialCodec _initialOpen;
  QuicPacketCodec? _appSeal;
  QuicPacketCodec? _appOpen;
  QuicZeroRttCodec? _zeroSeal;
  QuicZeroRttCodec? _zeroOpen;
  QuicZeroRttCodec? _hsSeal;
  QuicZeroRttCodec? _hsOpen;
  Uint8List? _earlyPayload;
  var _earlyStreamId = 0;
  final List<({int streamId, Uint8List data})> earlyData = [];
  QuicResumptionTicket? receivedTicket;
  final QuicResumptionTicket? _resumption;
  final Uint8List? _statelessResetToken;
  Uint8List? _peerResetToken;
  Uint8List? _appSendSecret;
  Uint8List? _appRecvSecret;
  var _sendKeyPhase = false;
  var _recvKeyPhase = false;
  var _keyUpdateUnconfirmed = false;
  int? _keyUpdateAt;
  final Map<QuicPacketNumberSpace, QuicCryptoStream> _inCrypto = {
    QuicPacketNumberSpace.initial: QuicCryptoStream(),
    QuicPacketNumberSpace.handshake: QuicCryptoStream(),
  };
  final Map<QuicPacketNumberSpace, int> _outCrypto = {};
  var _tlsOffset = 0;
  var _bytesReceived = 0;
  var _bytesSent = 0;
  var _addressValidated = false;
  var _paramsApplied = false;
  var _sawHandshakeDone = false;
  var _handshakeDoneSent = false;
  var _handshakeDiscarded = false;
  var _earlyAbandoned = false;
  var _streamsConfirmed = false;
  var _peerMaxBidi = 0;
  var _peerMaxUni = 0;
  final int _localMaxBidi = quicInitialMaxStreams;
  final int _localMaxUni = quicInitialMaxStreams;
  var _peerActiveCidLimit = quicActiveConnectionIdLimitDefault;
  final Map<int, Uint8List> _peerCids = {};
  final Map<int, Uint8List> _localCids = {};
  var _nextLocalCid = 1;
  final Map<int, int> _stopped = {};
  Uint8List? _pathChallenge;
  var pathResponseMatched = false;
  List<Uint8List>? _coalesce;
  var _openedBidi = 0;
  var _openedUni = 0;
  Uint8List? _retryToken;
  Uint8List? _retrySourceCid;
  var _retryAccepted = false;
  var _sawServerInitial = false;
  Uint8List? _clientInitialCrypto;
  final QuicCryptoStream _postHandshake = QuicCryptoStream();
  Uint8List _postPartial = Uint8List(0);
  Uint8List _originalDcid;
  Uint8List _peerInitialSource;
  var _learnedPeerScid = false;
  Future<void> _inFlight = Future<void>.value();
  Completer<void>? _waiter;
  PqTransportError? _error;
  var _markedConfirmed = false;
  var _initialDiscarded = false;

  bool get isComplete => _tls.isComplete;
  bool get earlyDataAccepted => _tls.earlyDataAccepted;
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
      _queueCrypto(frame.data);
    }
    _installEarlyKeys();
    final flushed = await _flush();
    if (flushed.isFailure) return flushed;
    return _sendQueuedEarly();
  }

  /// RFC 9000 0-RTT STREAM. Replayable. Call before [start].
  Result<void, PqTransportError> writeEarly(
    Uint8List data, {
    int streamId = 0,
  }) {
    if (!isClient) {
      return Result.failure(
        PqTransportError.unexpectedMessage('server does not send 0-rtt'),
      );
    }
    if (data.isEmpty || isComplete || _earlyPayload != null) {
      return Result.failure(
        PqTransportError.illegalParameter(
          PqLengthLabel.tlsExtension,
          data.length,
          1,
        ),
      );
    }
    final remembered = _resumption;
    if (remembered != null &&
        (data.length > remembered.maxEarlyData ||
            data.length > remembered.maxEarlyStreamData)) {
      return Result.failure(PqTransportError.flowControl('0-rtt limit'));
    }
    _earlyPayload = Uint8List.fromList(data);
    _earlyStreamId = streamId;
    return const Result.success(null);
  }

  /// RFC 8446 NewSessionTicket in a 1-RTT CRYPTO frame.
  Future<Result<QuicResumptionTicket, PqTransportError>> sendNewSessionTicket(
    QuicEarlyDataStore store,
  ) {
    final done = Completer<Result<QuicResumptionTicket, PqTransportError>>();
    _inFlight = _inFlight.then((_) async {
      try {
        if (isClient || !isComplete) {
          done.complete(
            Result.failure(
              PqTransportError.unexpectedMessage('ticket before handshake'),
            ),
          );
        } else {
          final ticket = store.issue(
            schedule: _tls.schedule,
            crypto: crypto,
            cipherSuite: _tls.schedule.suite.codepoint,
            now: lossRecovery.clock.now(),
            maxEarlyData: _flow.localMaxData,
            maxEarlyStreamData: _flow.localStreamMax(0),
          );
          _pending.add(
            QuicRetransmitCrypto(
              space: QuicPacketNumberSpace.application,
              offset: 0,
              data: encodeNewSessionTicket(ticket),
            ),
          );
          final sent = await _flush();
          done.complete(
            sent.isFailure
                ? Result.failure(sent.errorOrNull!)
                : Result.success(ticket),
          );
        }
        _wake();
      } on Object catch (e) {
        done.complete(
          Result.failure(PqTransportError.internalError('quic ticket $e')),
        );
        _wake();
      }
    });
    return done.future;
  }

  Future<Result<void, PqTransportError>> _sendQueuedEarly() async {
    final data = _earlyPayload;
    final codec = _zeroSeal;
    if (data == null || codec == null) return const Result.success(null);
    _earlyPayload = null;
    final room =
        lossRecovery.maxDatagramSize - _longHeaderOverhead(initial: false);
    if (room < 1) {
      return Result.failure(
        PqTransportError.internalError('quic datagram payload'),
      );
    }
    var offset = 0;
    while (offset < data.length) {
      final n = _fitPayload(
        fixed: 1 + quicVarintLength(_earlyStreamId) + quicVarintLength(offset),
        available: data.length - offset,
        room: room,
      );
      if (n == null || n < 1) {
        return Result.failure(
          PqTransportError.internalError('quic early data does not fit'),
        );
      }
      final chunk = slice(data, offset, offset + n);
      final frame = QuicRetransmitFrame(
        space: QuicPacketNumberSpace.application,
        token: '0rtt:$_earlyStreamId:$offset:${chunk.length}',
        bytes: QuicStreamFrame(
          id: _earlyStreamId,
          offset: offset,
          data: chunk,
        ).encode(),
      );
      final pn = lossRecovery.peekPacketNumber(
        QuicPacketNumberSpace.application,
      );
      final sealed = codec.protect(
        dcid: _dcid,
        scid: localCid,
        packetNumber: pn,
        payload: frame.encode(),
      );
      if (sealed.isFailure) return Result.failure(sealed.errorOrNull!);
      final packet = sealed.valueOrNull!;
      if (packet.length > lossRecovery.maxDatagramSize) {
        return Result.failure(
          PqTransportError.internalError('quic datagram exceeds path maximum'),
        );
      }
      final committed = lossRecovery.allocatePacketNumber(
        QuicPacketNumberSpace.application,
      );
      if (committed != pn) {
        return Result.failure(
          PqTransportError.internalError('packet number changed'),
        );
      }
      final recorded = lossRecovery.onPacketSent(
        space: QuicPacketNumberSpace.application,
        packetNumber: pn,
        sentBytes: packet.length,
        ackEliciting: true,
        inFlight: true,
        frames: [frame],
        appLimited: true,
      );
      if (recorded.isFailure) return Result.failure(recorded.errorOrNull!);
      if (_connMachine.currentState == QuicConnectionState.handshake) {
        _connMachine.trigger(QuicConnectionEvent.early);
      }
      _bytesSent += packet.length;
      final emitted = await _emit(packet);
      if (emitted.isFailure) return emitted;
      offset += n;
    }
    return const Result.success(null);
  }

  Result<QuicResumptionTicket, PqTransportError> _ticketFrom(
    Uint8List handshake,
  ) {
    final parsed = decodeNewSessionTicket(handshake);
    if (parsed.isFailure) return Result.failure(parsed.errorOrNull!);
    final parts = parsed.valueOrNull!;
    return Result.success(
      QuicResumptionTicket(
        identity: parts.identity,
        nonce: parts.nonce,
        psk: _tls.schedule.ticketPsk(parts.nonce),
        ageAdd: parts.ageAdd,
        cipherSuite: _tls.schedule.suite.codepoint,
        issuedAt: lossRecovery.clock.now(),
        lifetimeSeconds: parts.lifetimeSeconds,
      ),
    );
  }

  void _installEarlyKeys() {
    final secret = _tls.earlyTrafficSecret;
    if (secret == null) return;
    final codec = QuicZeroRttCodec(
      crypto: crypto,
      keys: quicKeysFromTls(schedule: _tls.schedule, trafficSecret: secret),
      aead: _tls.schedule.aead,
    );
    if (isClient) {
      _zeroSeal ??= codec;
    } else {
      _zeroOpen ??= codec;
    }
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
    if (_stopped.containsKey(id)) {
      return Result.failure(PqTransportError.closed('stop sending'));
    }
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

  int openBidi() {
    if (_paramsApplied && _openedBidi >= _peerMaxBidi) {
      _queueControl(
        'msb:$_peerMaxBidi',
        QuicStreamsBlockedFrame(
          bidirectional: true,
          maximum: _peerMaxBidi,
        ).encode(),
      );
      return -1;
    }
    _openedBidi++;
    return _streams.openBidi();
  }

  int openUni() {
    if (_paramsApplied && _openedUni >= _peerMaxUni) {
      _queueControl(
        'msu:$_peerMaxUni',
        QuicStreamsBlockedFrame(
          bidirectional: false,
          maximum: _peerMaxUni,
        ).encode(),
      );
      return -1;
    }
    _openedUni++;
    return _streams.openUni();
  }

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
    String reason = '',
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
      reason: reason.codeUnits,
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
    final reset = _peerResetToken;
    if (reset != null && quicStatelessResetMatches(wire, reset)) {
      _silentClose();
      return Result.failure(PqTransportError.closed('stateless reset'));
    }
    if ((wire[0] & 0x80) != 0 && wire.length >= 5) {
      final version = readUint32(wire, 1);
      if (version == 0) {
        final listed = readQuicVersionNegotiation(wire);
        if (listed.isFailure) return Result.failure(listed.errorOrNull!);
        if (!listed.valueOrNull!.contains(quicVersion1)) {
          return Result.failure(
            PqTransportError.decodeFailure('version negotiation'),
          );
        }
        return const Result.success(null);
      }
      if (version != quicVersion1) {
        await _emit(
          quicVersionNegotiation(
            destinationConnectionId: _readCid(wire, source: false),
            sourceConnectionId: localCid,
          ),
        );
        return Result.failure(
          PqTransportError.decodeFailure('unsupported version'),
        );
      }
    }
    if (!isClient &&
        wire.length < quicMinClientInitialUdpBytes &&
        (wire[0] & 0xF0) == 0xC0 &&
        (wire.length < 5 || readUint32(wire, 1) == quicVersion1)) {
      // RFC 9000 §14.1. A server discards an Initial carried in a UDP
      // datagram smaller than 1200 bytes. The bytes still count toward
      // anti-amplification (RFC 9000 §8.1).
      _bytesReceived += wire.length;
      return const Result.success(null);
    }
    final split = splitQuicDatagram(wire);
    if (split.isFailure) return Result.failure(split.errorOrNull!);
    _bytesReceived += wire.length;
    if (!isClient) {
      for (final packet in split.valueOrNull!) {
        if ((packet[0] & 0xF0) == 0xE0) _addressValidated = true;
      }
    }
    for (final packet in split.valueOrNull!) {
      final one = await _ingestOne(packet);
      if (one.isFailure) return one;
    }
    return const Result.success(null);
  }

  Uint8List _readCid(Uint8List packet, {required bool source}) {
    if (packet.length < 7 || (packet[0] & 0x80) == 0) return Uint8List(0);
    var off = 5;
    final dcidLen = packet[off++];
    if (packet.length < off + dcidLen) return Uint8List(0);
    final dcid = slice(packet, off, off + dcidLen);
    if (!source) return dcid;
    off += dcidLen;
    if (packet.length < off + 1) return Uint8List(0);
    final scidLen = packet[off++];
    if (packet.length < off + scidLen) return Uint8List(0);
    return slice(packet, off, off + scidLen);
  }

  Future<Result<void, PqTransportError>> _ingestOne(Uint8List wire) async {
    final type = wire[0] & 0xF0;
    if (type == 0xC0 || type == 0xD0 || type == 0xE0) {
      _learnPeerCid(wire);
    }
    if (type == 0xF0) return _ingestRetry(wire);
    if (type == 0xD0) {
      _installEarlyKeys();
      final codec = _zeroOpen;
      if (codec == null) return const Result.success(null);
      final opened = codec.open(wire);
      if (opened.isFailure) return const Result.success(null);
      final packet = opened.valueOrNull!;
      return _accept(
        space: QuicPacketNumberSpace.application,
        packetNumber: packet.packetNumber,
        payload: packet.payload,
        early: true,
      );
    }
    if (type == 0xE0) {
      _installHandshakeKeys();
      final codec = _hsOpen;
      if (codec == null) return const Result.success(null);
      final opened = codec.open(wire);
      if (opened.isFailure) return Result.failure(opened.errorOrNull!);
      final packet = opened.valueOrNull!;
      return _accept(
        space: QuicPacketNumberSpace.handshake,
        packetNumber: packet.packetNumber,
        payload: packet.payload,
      );
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

  Future<Result<void, PqTransportError>> _ingestRetry(Uint8List wire) async {
    if (!isClient || _tls.isComplete) {
      return Result.failure(PqTransportError.decodeFailure('unexpected retry'));
    }
    // RFC 9000 §17.2.5.3. One Retry, and none after a server Initial.
    if (_retryAccepted || _sawServerInitial) {
      return const Result.success(null);
    }
    if (!quicRetryTagValid(
      crypto: crypto,
      originalDestinationConnectionId: _originalDcid,
      packet: wire,
    )) {
      return Result.failure(PqTransportError.decryptError('retry tag'));
    }
    final parsed = _parseRetry(wire);
    if (parsed == null) {
      return Result.failure(PqTransportError.decodeFailure('retry'));
    }
    // A zero-length Retry Source Connection ID is discarded, not fatal.
    if (parsed.sourceConnectionId.isEmpty) {
      return const Result.success(null);
    }
    final hello = _clientInitialCrypto;
    if (hello == null) {
      return Result.failure(
        PqTransportError.unexpectedMessage('retry before client hello'),
      );
    }
    _retryAccepted = true;
    _retryToken = parsed.token;
    _retrySourceCid = Uint8List.fromList(parsed.sourceConnectionId);
    _dcid = Uint8List.fromList(parsed.sourceConnectionId);
    _rebindInitial(_dcid);
    _earlyAbandoned = true;
    lossRecovery.abandonFrames((token) => token.startsWith('0rtt:'));
    _pending.removeWhere((frame) => frame.token.startsWith('0rtt:'));
    _pending.removeWhere(
      (frame) => frame.space == QuicPacketNumberSpace.initial,
    );
    lossRecovery.resetAfterRetry();
    final received = _received[QuicPacketNumberSpace.initial]!;
    received.received.clear();
    received.inFlight.clear();
    _wantAck[QuicPacketNumberSpace.initial] = false;
    _inCrypto[QuicPacketNumberSpace.initial] = QuicCryptoStream();
    _outCrypto.remove(QuicPacketNumberSpace.initial);
    // Same ClientHello. A second startHandshake is not a Retry.
    _queueCrypto(hello, rememberInitial: false);
    return _flush();
  }

  ({Uint8List sourceConnectionId, Uint8List token})? _parseRetry(
    Uint8List packet,
  ) {
    if (packet.length < 7 + quicRetryIntegrityTagBytes) return null;
    final end = packet.length - quicRetryIntegrityTagBytes;
    var off = 5;
    final dcidLen = packet[off++];
    if (end < off + dcidLen + 1) return null;
    off += dcidLen;
    final scidLen = packet[off++];
    if (scidLen > quicMaxConnectionIdBytes || end < off + scidLen) return null;
    final scid = slice(packet, off, off + scidLen);
    off += scidLen;
    return (sourceConnectionId: scid, token: slice(packet, off, end));
  }

  void _rebindInitial(Uint8List destination) {
    final secrets = QuicInitialSecrets.derive(
      crypto: crypto,
      destinationConnectionId: destination,
    );
    _initialSeal = QuicInitialCodec(crypto: crypto, keys: secrets.client);
    _initialOpen = QuicInitialCodec(crypto: crypto, keys: secrets.server);
  }

  /// RFC 9000 §7.2. The first long header from the peer carries the CID
  /// that later packets use. A server also derives Initial secrets from
  /// the DCID the client actually chose.
  void _learnPeerCid(Uint8List packet) {
    if (_learnedPeerScid) return;
    final scid = _headerCid(packet, source: true);
    final dcid = _headerCid(packet, source: false);
    if (scid == null || dcid == null) return;
    _learnedPeerScid = true;
    _peerInitialSource = Uint8List.fromList(scid);
    _dcid = Uint8List.fromList(scid);
    if (isClient) return;
    _originalDcid = Uint8List.fromList(dcid);
    final secrets = QuicInitialSecrets.derive(
      crypto: crypto,
      destinationConnectionId: dcid,
    );
    _initialSeal = QuicInitialCodec(crypto: crypto, keys: secrets.server);
    _initialOpen = QuicInitialCodec(crypto: crypto, keys: secrets.client);
    _tls.setTransportParameters(
      QuicTransportParameters(
        originalDestinationConnectionId: _originalDcid,
        statelessResetToken: _statelessResetToken,
        maxIdleTimeout: idleTimeout?.inMilliseconds ?? 0,
        initialMaxData: _flow.localMaxData,
        initialMaxStreamDataBidiLocal: _flow.localStreamMax(0),
        initialMaxStreamDataBidiRemote: _flow.localStreamMax(0),
        initialMaxStreamDataUni: _flow.localStreamMax(0),
        initialMaxStreamsBidi: _localMaxBidi,
        initialMaxStreamsUni: _localMaxUni,
        activeConnectionIdLimit: 4,
        initialSourceConnectionId: localCid,
      ).encode(),
    );
  }

  Uint8List? _headerCid(Uint8List packet, {required bool source}) {
    if (packet.length < 7 || (packet[0] & 0x80) == 0) return null;
    if (readUint32(packet, 1) != quicVersion1) return null;
    var off = 5;
    if (packet.length < off + 1) return null;
    final dcidLen = packet[off];
    off++;
    if (dcidLen > quicMaxConnectionIdBytes || packet.length < off + dcidLen) {
      return null;
    }
    if (!source) return slice(packet, off, off + dcidLen);
    off += dcidLen;
    if (packet.length < off + 1) return null;
    final scidLen = packet[off];
    off++;
    if (scidLen > quicMaxConnectionIdBytes || packet.length < off + scidLen) {
      return null;
    }
    return slice(packet, off, off + scidLen);
  }

  Future<Result<void, PqTransportError>> _ingestApp(Uint8List wire) async {
    final codec = _appOpen;
    if (codec == null) {
      return Result.failure(PqTransportError.decodeFailure('no 1-rtt keys'));
    }
    var opened = codec.open(wire);
    if (opened.isFailure) {
      final rotated = _openWithNextKeys(wire);
      if (rotated == null) return Result.failure(opened.errorOrNull!);
      opened = Result.success(rotated);
    }
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
    bool early = false,
  }) async {
    if (isClient && space == QuicPacketNumberSpace.initial) {
      _sawServerInitial = true;
    }
    final parsed = decodeQuicPayload(payload);
    if (parsed.isFailure) return Result.failure(parsed.errorOrNull!);
    final body = parsed.valueOrNull!;
    final recv = _received[space]!;
    final duplicate = recv.received.contains(packetNumber);
    recv.onReceived(packetNumber);
    if (body.ackEliciting) _wantAck[space] = true;
    if (!duplicate) {
      if (body.closes.isNotEmpty) {
        final frame = body.closes.first;
        _enterDrain();
        _error = PqTransportError.closed(
          'peer close ${frame.errorCode} ${String.fromCharCodes(frame.reason)}',
        );
        return Result.failure(_error!);
      }
      for (final frame in body.crypto) {
        if (isComplete && space == QuicPacketNumberSpace.application) {
          final added = _postHandshake.add(frame);
          if (added.isFailure) return Result.failure(added.errorOrNull!);
          final available = _postHandshake.takeAvailable();
          if (available.isNotEmpty) {
            _postPartial = concatBytes([_postPartial, available]);
          }
          while (_postPartial.length >= tlsHandshakeHeaderBytes) {
            final wire = tlsHandshakeHeaderBytes + readUint24(_postPartial, 1);
            if (wire < tlsHandshakeHeaderBytes || _postPartial.length < wire) {
              break;
            }
            final message = slice(_postPartial, 0, wire);
            _postPartial = slice(_postPartial, wire, _postPartial.length);
            if (message[0] != tlsHsNewSessionTicket) {
              return Result.failure(
                PqTransportError.unexpectedMessage(
                  'post-handshake ${message[0]}',
                ),
              );
            }
            final ticket = _ticketFrom(message);
            if (ticket.isFailure) return Result.failure(ticket.errorOrNull!);
            receivedTicket = ticket.valueOrNull;
          }
          continue;
        }
        final inbound = _inCrypto[space];
        if (inbound == null) {
          return Result.failure(PqTransportError.decodeFailure('crypto space'));
        }
        final added = inbound.add(frame);
        if (added.isFailure) return Result.failure(added.errorOrNull!);
        final available = inbound.takeAvailable();
        if (available.isEmpty) continue;
        final reply = await _tls.ingest(
          QuicCryptoFrame(offset: _tlsOffset, data: available),
        );
        _tlsOffset += available.length;
        if (reply.isFailure) return Result.failure(reply.errorOrNull!);
        _installHandshakeKeys();
        for (final cryptoFrame in reply.valueOrNull!) {
          _queueCrypto(cryptoFrame.data);
        }
        final params = _applyPeerParams();
        if (params != null) {
          await _close(
            errorCode: quicErrorTransportParameter,
            application: false,
            reason: '${params.errorOrNull}',
          );
          return params;
        }
      }
      for (final frame in body.streams) {
        if (_streamIdPastLimit(frame.id)) {
          await _close(errorCode: quicErrorStreamLimit, application: false);
          return Result.failure(PqTransportError.decodeFailure('stream limit'));
        }
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
        final ingested = early
            ? _streams.ingestEarly(frame)
            : _streams.ingest(frame);
        if (ingested.isFailure) return Result.failure(ingested.errorOrNull!);
        if (early) {
          earlyData.add((streamId: frame.id, data: frame.data));
          if (isComplete) {
            _streams.confirmEarly();
          } else if (_connMachine.currentState ==
              QuicConnectionState.handshake) {
            _connMachine.trigger(QuicConnectionEvent.early);
          }
        }
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
      for (final frame in body.stopSending) {
        _stopped[frame.id] = frame.errorCode;
        final stream = _streams.streams.putIfAbsent(
          frame.id,
          () => QuicStreamReassembler(frame.id),
        );
        final marked = stream.reset(frame.errorCode);
        if (marked.isFailure) return marked;
      }
      for (final frame in body.maxStreams) {
        if (frame.bidirectional) {
          if (frame.maximum > _peerMaxBidi) _peerMaxBidi = frame.maximum;
        } else if (frame.maximum > _peerMaxUni) {
          _peerMaxUni = frame.maximum;
        }
      }
      for (final frame in body.newConnectionIds) {
        final accepted = _acceptNewConnectionId(frame);
        if (accepted != null) return accepted;
      }
      for (final frame in body.retireConnectionIds) {
        _localCids.remove(frame.sequence);
      }
      for (final frame in body.pathChallenges) {
        _queueControl(
          'pr:${frame.data.join(',')}',
          QuicPathResponseFrame(frame.data).encode(),
        );
      }
      for (final frame in body.pathResponses) {
        final challenge = _pathChallenge;
        if (challenge != null && _sameBytes(challenge, frame.data)) {
          pathResponseMatched = true;
        }
      }
      if (body.handshakeDone) {
        if (!isClient) {
          await _close(
            errorCode: quicErrorProtocolViolation,
            application: false,
          );
          return Result.failure(
            PqTransportError.decodeFailure('handshake_done'),
          );
        }
        _sawHandshakeDone = true;
      }
      _releaseStalled();
      for (final ack in body.acks) {
        if (_keyUpdateAt != null &&
            ack.packetNumbers().contains(_keyUpdateAt)) {
          _keyUpdateUnconfirmed = false;
          _keyUpdateAt = null;
        }
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
    final root = _coalesce == null;
    _coalesce ??= <Uint8List>[];
    Result<void, PqTransportError>? failed;
    var bypassLeft = ignoreWindowPackets;
    var again = true;
    while (again && failed == null) {
      again = false;
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
        if (sent.isFailure) {
          failed = Result.failure(sent.errorOrNull!);
          break;
        }
        if (sent.valueOrNull != true) break;
        final tokens = batch.map((frame) => frame.token).toSet();
        _pending.removeWhere((frame) => tokens.contains(frame.token));
        if (bypassLeft > 0) bypassLeft--;
      }
      if (failed != null) break;
      for (final space in QuicPacketNumberSpace.values) {
        if (_wantAck[space] != true) continue;
        final sent = await _sendPacket(
          space: space,
          frames: const [],
          ignoreWindow: false,
        );
        if (sent.isFailure) {
          failed = Result.failure(sent.errorOrNull!);
          break;
        }
      }
      final doneBefore = _handshakeDoneSent;
      _syncHandshake();
      if (!doneBefore && _handshakeDoneSent) again = true;
    }
    _armBoundTimers();
    if (root) {
      final released = await _releaseCoalesce();
      if (failed != null) return failed;
      if (released.isFailure) return released;
    }
    return failed ?? const Result.success(null);
  }

  List<QuicRetransmittable> _batchFor(QuicPacketNumberSpace space) {
    final budget = _payloadBudget(space);
    if (budget <= 0) return const [];
    final batch = <QuicRetransmittable>[];
    var used = 0;
    for (var i = 0; i < _pending.length; i++) {
      final frame = _pending[i];
      if (frame.space != space) continue;
      final size = frame.encode().length;
      if (used + size <= budget) {
        batch.add(frame);
        used += size;
        continue;
      }
      final split = _splitToFit(frame, budget - used);
      if (split == null || split.rest == null) break;
      _pending[i] = split.head;
      _pending.insert(i + 1, split.rest!);
      batch.add(split.head);
      break;
    }
    return batch;
  }

  Future<Result<bool, PqTransportError>> _sendPacket({
    required QuicPacketNumberSpace space,
    required List<QuicRetransmittable> frames,
    required bool ignoreWindow,
  }) async {
    if (frames.isEmpty && _wantAck[space] != true) {
      return const Result.success(true);
    }
    if (space == QuicPacketNumberSpace.handshake) {
      _installHandshakeKeys();
      if (_hsSeal == null) return const Result.success(false);
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
        dcidLength: _dcid.length,
        scidLength: localCid.length,
        payloadLength: body.length,
        tokenLength: _retryToken?.length ?? 0,
      );
      if (body.length < target) {
        body = concatBytes([body, Uint8List(target - body.length)]);
      }
    }
    if (space == QuicPacketNumberSpace.application) {
      _ensureAppKeys();
      // 0-RTT is acknowledged in a 1-RTT packet. Until those keys exist,
      // leave the ACK (and any other Application Data) queued.
      if (_appSeal == null) return const Result.success(false);
    }
    final pn = lossRecovery.peekPacketNumber(space);
    final Result<Uint8List, PqTransportError> sealed;
    if (space == QuicPacketNumberSpace.initial) {
      sealed = _initialSeal.protect(
        dcid: _dcid,
        scid: localCid,
        packetNumber: pn,
        payload: body,
        token: _retryToken,
      );
    } else if (space == QuicPacketNumberSpace.handshake) {
      final codec = _hsSeal;
      if (codec == null) return const Result.success(false);
      sealed = codec.protect(
        dcid: _dcid,
        scid: localCid,
        packetNumber: pn,
        payload: body,
      );
    } else {
      final codec = _appSeal;
      if (codec == null) {
        return Result.failure(PqTransportError.decodeFailure('no 1-rtt keys'));
      }
      sealed = codec.protect(dcid: _dcid, packetNumber: pn, payload: body);
    }
    if (sealed.isFailure) return Result.failure(sealed.errorOrNull!);
    final packet = sealed.valueOrNull!;
    if (packet.length > lossRecovery.maxDatagramSize) {
      return Result.failure(
        PqTransportError.internalError('quic datagram exceeds path maximum'),
      );
    }
    if (!lossRecovery.canSend(
      packet.length,
      probe: ignoreWindow,
      inFlight: inFlight,
    )) {
      return const Result.success(false);
    }
    if (!isClient && !_addressValidated) {
      final room = _bytesReceived * 3 - _bytesSent;
      if (packet.length > room) return const Result.success(false);
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
    if (space == QuicPacketNumberSpace.application &&
        _keyUpdateUnconfirmed &&
        _keyUpdateAt == null) {
      _keyUpdateAt = pn;
    }
    _bytesSent += packet.length;
    final emitted = await _emit(packet);
    if (emitted.isFailure) return Result.failure(emitted.errorOrNull!);
    _noteActivity();
    return const Result.success(true);
  }

  Future<Result<void, PqTransportError>> _emit(Uint8List packet) async {
    final buffer = _coalesce;
    if (buffer != null) {
      buffer.add(packet);
      return const Result.success(null);
    }
    return _deliverDatagram(packet);
  }

  Future<Result<void, PqTransportError>> _releaseCoalesce() async {
    final parts = _coalesce;
    _coalesce = null;
    if (parts == null || parts.isEmpty) return const Result.success(null);
    parts.sort((a, b) => _packetRank(a).compareTo(_packetRank(b)));
    final limit = lossRecovery.maxDatagramSize;
    final datagram = <Uint8List>[];
    var used = 0;
    for (final packet in parts) {
      // A client Initial is already padded to 1200. Nothing else may
      // share that datagram (RFC 9000 §14).
      final initialFull =
          datagram.isNotEmpty &&
          (datagram.first[0] & 0xF0) == 0xC0 &&
          used >= quicMinClientInitialUdpBytes;
      if (datagram.isNotEmpty &&
          (used + packet.length > limit || initialFull)) {
        final sent = await _deliverDatagram(concatBytes(datagram));
        if (sent.isFailure) return sent;
        datagram.clear();
        used = 0;
      }
      datagram.add(packet);
      used += packet.length;
    }
    if (datagram.isEmpty) return const Result.success(null);
    return _deliverDatagram(concatBytes(datagram));
  }

  int _payloadBudget(QuicPacketNumberSpace space) {
    var room = lossRecovery.maxDatagramSize - _headerOverhead(space);
    if (_wantAck[space] == true) {
      final ack = _received[space]!.pendingAck();
      if (ack.isSuccess) room -= ack.valueOrNull!.encode().length;
    }
    return room > 0 ? room : 0;
  }

  int _headerOverhead(QuicPacketNumberSpace space) {
    if (space == QuicPacketNumberSpace.application) {
      return _shortHeaderOverhead();
    }
    return _longHeaderOverhead(initial: space == QuicPacketNumberSpace.initial);
  }

  int _shortHeaderOverhead() =>
      1 + _dcid.length + quicPacketNumberMaxBytes + aeadTagBytes;

  /// Long-header overhead for a packet that fills [maxDatagramSize].
  /// The length field is 2 bytes: a full payload is far past 63.
  int _longHeaderOverhead({required bool initial}) {
    final tokenLen = initial ? (_retryToken?.length ?? 0) : 0;
    final tokenField = initial ? quicVarintLength(tokenLen) + tokenLen : 0;
    return 1 +
        4 +
        1 +
        _dcid.length +
        1 +
        localCid.length +
        tokenField +
        2 +
        quicPacketNumberMaxBytes +
        aeadTagBytes;
  }

  ({QuicRetransmittable head, QuicRetransmittable? rest})? _splitToFit(
    QuicRetransmittable frame,
    int room,
  ) {
    if (room <= 0) return null;
    if (frame is QuicRetransmitCrypto) {
      if (frame.data.isEmpty) return null;
      final n = _fitPayload(
        fixed: 1 + quicVarintLength(frame.offset),
        available: frame.data.length,
        room: room,
      );
      if (n == null) return null;
      if (n >= frame.data.length) return (head: frame, rest: null);
      return (
        head: QuicRetransmitCrypto(
          space: frame.space,
          offset: frame.offset,
          data: slice(frame.data, 0, n),
        ),
        rest: QuicRetransmitCrypto(
          space: frame.space,
          offset: frame.offset + n,
          data: slice(frame.data, n, frame.data.length),
        ),
      );
    }
    if (frame is QuicRetransmitStream) {
      if (frame.data.isEmpty) return null;
      final n = _fitPayload(
        fixed:
            1 +
            quicVarintLength(frame.streamId) +
            quicVarintLength(frame.offset),
        available: frame.data.length,
        room: room,
      );
      if (n == null) return null;
      if (n >= frame.data.length) return (head: frame, rest: null);
      return (
        head: QuicRetransmitStream(
          streamId: frame.streamId,
          offset: frame.offset,
          data: slice(frame.data, 0, n),
          fin: false,
        ),
        rest: QuicRetransmitStream(
          streamId: frame.streamId,
          offset: frame.offset + n,
          data: slice(frame.data, n, frame.data.length),
          fin: frame.fin,
        ),
      );
    }
    return null;
  }

  int? _fitPayload({
    required int fixed,
    required int available,
    required int room,
  }) {
    var n = available > room ? room : available;
    while (n > 0) {
      final size = fixed + quicVarintLength(n) + n;
      if (size <= room) return n;
      final over = size - room;
      n -= over > 0 ? over : 1;
    }
    return null;
  }

  int _packetRank(Uint8List packet) {
    if ((packet[0] & 0x80) == 0) return 4;
    return (packet[0] >> 4) & 0x3;
  }

  Future<Result<void, PqTransportError>> _deliverDatagram(
    Uint8List packet,
  ) async {
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
    if (_tls.peerTransportParameters == null && _error == null) {
      _error = PqTransportError.decodeFailure('missing transport parameters');
    }
    if (isClient && !_tls.earlyDataAccepted && !_earlyAbandoned) {
      _earlyAbandoned = true;
      lossRecovery.abandonFrames((token) => token.startsWith('0rtt:'));
    }
    final state = _connMachine.currentState;
    if (state == QuicConnectionState.handshake ||
        state == QuicConnectionState.zeroRtt) {
      _connMachine.trigger(QuicConnectionEvent.handshakeDone);
    }
    if (!_streamsConfirmed) {
      _streamsConfirmed = true;
      _streams.confirmEarly();
    }
    final clientReady = !isClient || _sawHandshakeDone;
    if (clientReady && !_markedConfirmed) {
      _markedConfirmed = true;
      lossRecovery.markHandshakeConfirmed();
    }
    if (!isClient && !_handshakeDoneSent) {
      _queueControl('hsdone', Uint8List.fromList([quicFrameHandshakeDone]));
      _handshakeDoneSent = true;
    }
    _discardSpace(QuicPacketNumberSpace.initial);
    if (_markedConfirmed) _discardSpace(QuicPacketNumberSpace.handshake);
  }

  void _discardSpace(QuicPacketNumberSpace space) {
    final discarded = space == QuicPacketNumberSpace.initial
        ? _initialDiscarded
        : _handshakeDiscarded;
    if (discarded) return;
    if (_pending.any((frame) => frame.space == space)) return;
    if (lossRecovery.hasInFlight(space)) return;
    if (space == QuicPacketNumberSpace.initial) {
      _initialDiscarded = true;
    } else {
      _handshakeDiscarded = true;
      _hsSeal = null;
      _hsOpen = null;
    }
    lossRecovery.onPacketNumberSpaceDiscarded(space);
  }

  void _ensureAppKeys() {
    if (_appSeal != null || !_tls.isComplete) return;
    final schedule = _tls.schedule;
    _appSendSecret = isClient
        ? schedule.clientApplicationTraffic
        : schedule.serverApplicationTraffic;
    _appRecvSecret = isClient
        ? schedule.serverApplicationTraffic
        : schedule.clientApplicationTraffic;
    _appSeal = QuicPacketCodec.fromKeys(
      crypto,
      quicKeysFromTls(schedule: schedule, trafficSecret: _appSendSecret!),
      aead: schedule.aead,
      keyPhase: _sendKeyPhase,
    );
    _appOpen = QuicPacketCodec.fromKeys(
      crypto,
      quicKeysFromTls(schedule: schedule, trafficSecret: _appRecvSecret!),
      aead: schedule.aead,
      keyPhase: _recvKeyPhase,
      dcidLength: localCid.length,
    );
  }

  void _queueCrypto(Uint8List data, {bool rememberInitial = true}) {
    if (data.isEmpty) return;
    final space = _cryptoSpace(data);
    if (rememberInitial && isClient && space == QuicPacketNumberSpace.initial) {
      final prior = _clientInitialCrypto;
      final copy = Uint8List.fromList(data);
      _clientInitialCrypto = prior == null ? copy : concatBytes([prior, copy]);
    }
    final offset = _outCrypto[space] ?? 0;
    _outCrypto[space] = offset + data.length;
    _pending.add(
      QuicRetransmitCrypto(space: space, offset: offset, data: data),
    );
  }

  QuicPacketNumberSpace _cryptoSpace(Uint8List data) {
    switch (data[0]) {
      case tlsHsClientHello:
      case tlsHsServerHello:
        return QuicPacketNumberSpace.initial;
      case tlsHsNewSessionTicket:
        return QuicPacketNumberSpace.application;
      default:
        return QuicPacketNumberSpace.handshake;
    }
  }

  void _installHandshakeKeys() {
    if (_hsSeal != null || !_tls.handshakeSecretsReady) return;
    final schedule = _tls.schedule;
    final aead = schedule.aead;
    final send = isClient
        ? schedule.clientHandshakeTraffic
        : schedule.serverHandshakeTraffic;
    final recv = isClient
        ? schedule.serverHandshakeTraffic
        : schedule.clientHandshakeTraffic;
    _hsSeal = QuicZeroRttCodec(
      crypto: crypto,
      keys: quicKeysFromTls(schedule: schedule, trafficSecret: send),
      aead: aead,
      longType: 0xE0,
    );
    _hsOpen = QuicZeroRttCodec(
      crypto: crypto,
      keys: quicKeysFromTls(schedule: schedule, trafficSecret: recv),
      aead: aead,
      longType: 0xE0,
    );
    lossRecovery.markHandshakeKeysAvailable();
  }

  Result<void, PqTransportError>? _applyPeerParams() {
    if (_paramsApplied) return null;
    final raw = _tls.peerTransportParameters;
    if (raw == null) return null;
    final decoded = QuicTransportParameters.decode(raw);
    if (decoded.isFailure) return Result.failure(decoded.errorOrNull!);
    final params = decoded.valueOrNull!;
    final checked = params.check(
      peerIsServer: isClient,
      expectedInitialSource: _peerInitialSource,
      expectedOriginalDestination: isClient ? _originalDcid : null,
      expectedRetrySource: isClient ? _retrySourceCid : null,
    );
    if (checked.isFailure) return checked;
    _flow.adoptPeerInitial(
      maxData: params.initialMaxData,
      maxStreamData: params.streamDataLimit,
    );
    _peerMaxBidi = params.initialMaxStreamsBidi;
    _peerMaxUni = params.initialMaxStreamsUni;
    _peerActiveCidLimit = params.activeConnectionIdLimit;
    _peerResetToken = params.statelessResetToken;
    _paramsApplied = true;
    return null;
  }

  bool _streamIdPastLimit(int id) {
    if (!_paramsApplied) return false;
    final n = (id >> 2) + 1;
    if ((id & 0x02) == 0) return n > _localMaxBidi;
    return n > _localMaxUni;
  }

  Result<void, PqTransportError>? _acceptNewConnectionId(
    QuicNewConnectionIdFrame frame,
  ) {
    if (frame.connectionId.isEmpty) {
      return Result.failure(PqTransportError.decodeFailure('connection id'));
    }
    _peerCids.removeWhere((sequence, _) => sequence < frame.retirePriorTo);
    if (_peerCids.length >= _peerActiveCidLimit &&
        !_peerCids.containsKey(frame.sequence)) {
      return Result.failure(
        PqTransportError.decodeFailure('connection id limit'),
      );
    }
    _peerCids[frame.sequence] = frame.connectionId;
    _peerResetToken = frame.statelessResetToken;
    if (frame.retirePriorTo > 0) {
      _queueControl(
        'retire:${frame.retirePriorTo - 1}',
        QuicRetireConnectionIdFrame(frame.retirePriorTo - 1).encode(),
      );
    }
    return null;
  }

  ({int packetNumber, Uint8List payload, bool keyPhase})? _openWithNextKeys(
    Uint8List wire,
  ) {
    final current = _appRecvSecret;
    if (current == null || !_tls.isComplete) return null;
    final schedule = _tls.schedule;
    final nextSecret = schedule.quicNextSecret(current);
    final codec = QuicPacketCodec.fromKeys(
      crypto,
      quicKeysFromTls(schedule: schedule, trafficSecret: nextSecret),
      aead: schedule.aead,
      keyPhase: !_recvKeyPhase,
      dcidLength: localCid.length,
    );
    final opened = codec.open(wire);
    if (opened.isFailure) return null;
    final packet = opened.valueOrNull!;
    if (packet.keyPhase == _recvKeyPhase) return null;
    _appRecvSecret = nextSecret;
    _recvKeyPhase = packet.keyPhase;
    _appOpen = codec;
    return packet;
  }

  bool get handshakeConfirmed => _markedConfirmed;

  Uint8List? get statelessResetToken => _statelessResetToken;

  Future<Result<void, PqTransportError>> updateKeys() {
    final done = Completer<Result<void, PqTransportError>>();
    _inFlight = _inFlight.then((_) async {
      try {
        if (_appSendSecret == null || _keyUpdateUnconfirmed) {
          done.complete(
            Result.failure(PqTransportError.unexpectedMessage('key update')),
          );
        } else {
          final schedule = _tls.schedule;
          _appSendSecret = schedule.quicNextSecret(_appSendSecret!);
          _sendKeyPhase = !_sendKeyPhase;
          _keyUpdateUnconfirmed = true;
          _keyUpdateAt = null;
          _appSeal = QuicPacketCodec.fromKeys(
            crypto,
            quicKeysFromTls(schedule: schedule, trafficSecret: _appSendSecret!),
            aead: schedule.aead,
            keyPhase: _sendKeyPhase,
          );
          done.complete(const Result.success(null));
        }
        _wake();
      } on Object catch (e) {
        done.complete(
          Result.failure(PqTransportError.internalError('key update $e')),
        );
        _wake();
      }
    });
    return done.future;
  }

  Future<Result<void, PqTransportError>> sendPathChallenge() {
    final done = Completer<Result<void, PqTransportError>>();
    _inFlight = _inFlight.then((_) async {
      try {
        if (!isComplete) {
          done.complete(
            Result.failure(
              PqTransportError.handshakeFailure('path before handshake'),
            ),
          );
        } else {
          final data = crypto.randomBytes(quicPathChallengeBytes);
          _pathChallenge = data;
          pathResponseMatched = false;
          _queueControl('pc', QuicPathChallengeFrame(data).encode());
          done.complete(await _flush());
        }
        _wake();
      } on Object catch (e) {
        done.complete(
          Result.failure(PqTransportError.internalError('path $e')),
        );
        _wake();
      }
    });
    return done.future;
  }

  Future<Result<Uint8List, PqTransportError>> issueConnectionId() {
    final done = Completer<Result<Uint8List, PqTransportError>>();
    _inFlight = _inFlight.then((_) async {
      try {
        if (!isComplete) {
          done.complete(
            Result.failure(
              PqTransportError.handshakeFailure('cid before handshake'),
            ),
          );
        } else if (_nextLocalCid >= _peerActiveCidLimit) {
          done.complete(
            Result.failure(
              PqTransportError.decodeFailure('connection id limit'),
            ),
          );
        } else {
          final cid = crypto.randomBytes(quicShortDcidBytes);
          final token = crypto.randomBytes(quicStatelessResetTokenBytes);
          final sequence = _nextLocalCid++;
          _localCids[sequence] = cid;
          _queueControl(
            'ncid:$sequence',
            QuicNewConnectionIdFrame(
              sequence: sequence,
              retirePriorTo: 0,
              connectionId: cid,
              statelessResetToken: token,
            ).encode(),
          );
          final sent = await _flush();
          done.complete(
            sent.isFailure
                ? Result.failure(sent.errorOrNull!)
                : Result.success(cid),
          );
        }
        _wake();
      } on Object catch (e) {
        done.complete(Result.failure(PqTransportError.internalError('cid $e')));
        _wake();
      }
    });
    return done.future;
  }

  static bool _sameBytes(Uint8List a, Uint8List b) {
    if (a.length != b.length) return false;
    var diff = 0;
    for (var i = 0; i < a.length; i++) {
      diff |= a[i] ^ b[i];
    }
    return diff == 0;
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
        state == QuicConnectionState.zeroRtt ||
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
        state == QuicConnectionState.zeroRtt ||
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
