import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'package:pqforge/pqforge.dart' hide requireLength;
import 'package:swissarmyknife/swissarmyknife.dart';

import '../core/bytes.dart';
import '../core/crypto.dart';
import '../core/errors.dart';
import '../core/hybrid.dart';
import '../core/lengths.dart';
import '../core/transcript.dart';
import '../core/zeroize.dart';
import '../socket/pq_transport_socket.dart';
import '../tls/key_schedule.dart';
import '../quic/initial.dart';
import '../quic/packet.dart';
import '../quic/recovery.dart';
import 'pq_datagram.dart';
import 'reliable_window.dart';

/// Raw datagram socket over a [PqDatagramChannel] (IO or memory).
final class PqUdpSocket {
  PqUdpSocket({required this.channel, this.local, Duration? throttleWindow})
    : _throttler = Throttler(throttleWindow ?? const Duration(milliseconds: 1));

  final PqDatagramChannel channel;
  final PqEndpoint? local;
  final Throttler _throttler;
  var _throttled = false;

  Stream<PqDatagramIn> get incoming => channel.incoming;

  Future<Result<void, PqTransportError>> send(
    Uint8List data,
    PqEndpoint peer,
  ) async {
    if (channel.isClosed) {
      return Result.failure(PqTransportError.closed('udp send'));
    }
    if (_throttler.duration > Duration.zero && _throttler.isActive) {
      _throttled = true;
      return Result.failure(PqTransportError.throttled('udp send'));
    }
    var sent = false;
    _throttler.run(() => sent = true);
    if (!sent) {
      return Result.failure(PqTransportError.throttled('udp send'));
    }
    return channel.send(data, peer);
  }

  bool get wasThrottled => _throttled;

  Future<void> close() => channel.close();
}

/// ML-KEM + classical ECDH session, then AEAD datagrams.
///
/// Live key agreement is implemented for all three RFC 10024 groups.
/// [HybridGroup.secP384r1MlKem1024] requires `PqForgeProfile.maximum`.
///
/// After the session is up, every datagram is a QUIC packet.
///
/// The handshake is a RFC 9000 Initial long header. The client datagram
/// is padded to 1200 bytes. Initial keys are RFC 9001 §5.2, derived from
/// the destination connection ID, so a peer opens that packet with
/// [QuicInitialCodec] and no session key. Application data is a RFC 9000
/// §17.3 short header with RFC 9001 protection from [quicKeysFromTls].
/// The peer opens it with [QuicPacketCodec], the same opener [PqQuicConn]
/// uses. Loss recovery is RFC 9002. The HKDF extra is unchanged. Not ECN.
/// Not `curl --http3`.
final class PqEncryptedUdpSocket {
  PqEncryptedUdpSocket({
    required this.raw,
    required this.crypto,
    this.group = HybridGroup.x25519MlKem768,
    QuicClock? clock,
  }) : _recovery = QuicLossRecovery(clock: clock);

  final PqUdpSocket raw;
  final PqTransportCrypto crypto;
  final HybridGroup group;
  final QuicLossRecovery _recovery;

  QuicPacketCodec? _sealCodec;
  QuicPacketCodec? _openCodec;
  Uint8List? _localCid;
  Uint8List? _peerCid;
  var _isClient = true;
  final ReplayWindow _replay = ReplayWindow();
  final QuicAckProcessor _received = QuicAckProcessor();
  final Set<int> _deliveredOffsets = <int>{};
  int _sendOffset = 0;
  PqEndpoint? _peer;
  final StreamController<PqDatagram> _plain =
      StreamController<PqDatagram>.broadcast();
  StreamSubscription<PqDatagramIn>? _sub;
  Uint8List? _sessionKey;
  Timer? _lossTimer;
  Future<void> _tail = Future<void>.value();

  /// RFC 9002 recovery for this session. Tests advance [QuicLossRecovery.clock]
  /// and then call [driveLossDetection].
  QuicLossRecovery get lossRecovery => _recovery;

  Stream<PqDatagram> get incoming => _plain.stream;

  bool get isEstablished => _sealCodec != null;

  /// 32-byte application session key length after HKDF. Test seam only.
  int? get sessionKeyLength => _sessionKey?.length;

  /// Initiator: encapsulate to [peerKemPublicKey], emit handshake bytes.
  ///
  /// HKDF extra is identical on both roles (`ct || initiatorX || responderX`
  /// plus info `"pqtransport udp-session v1|udp"`). A role string must not be
  /// mixed in — that would desynchronise the session key.
  Future<Result<Uint8List, PqTransportError>> initiate({
    required Uint8List peerKemPublicKey,
    required Uint8List deploymentSalt,
  }) async {
    _isClient = true;
    final compatible = crypto.requireGroup(group);
    if (compatible.isFailure) return Result.failure(compatible.errorOrNull!);
    final sized = requireLength(
      peerKemPublicKey,
      group.kemPublicKeyBytes,
      group.kemPublicLabel,
    );
    if (sized.isFailure) return Result.failure(sized.errorOrNull!);
    if (!crypto.checkEncapsulationKey(peerKemPublicKey)) {
      return Result.failure(
        PqTransportError.illegalKemKey(group.kemPublicLabel),
      );
    }
    final classical = await crypto.classicalKeyGen(group);
    try {
      final enc = crypto.encapsulate(peerKemPublicKey);
      _pendingInitiate = _PendingInitiate(
        classicalSecret: classical.secretKey,
        classicalPublic: classical.publicKey,
        ciphertext: enc.ciphertext,
        ssKem: enc.sharedSecret,
        salt: deploymentSalt,
      );
      _localCid = crypto.randomBytes(quicShortDcidBytes);
      _peerCid = crypto.randomBytes(quicShortDcidBytes);
      final flight = Uint8List.fromList([
        ...classical.publicKey,
        ...enc.ciphertext,
      ]);
      return _protectInitial(
        crypto,
        dcid: _peerCid!,
        scid: _localCid!,
        keyDcid: _peerCid!,
        cryptoData: flight,
        fromClient: true,
        padToMinimum: true,
      );
    } on Object catch (e) {
      zeroize(classical.secretKey);
      return Result.failure(
        PqTransportError.handshakeFailure('udp initiate: ${e.runtimeType}'),
      );
    }
  }

  _PendingInitiate? _pendingInitiate;

  Future<Result<void, PqTransportError>> completeInitiate({
    required Uint8List responderClassicalPublic,
  }) async {
    final p = _pendingInitiate;
    if (p == null) {
      return Result.failure(
        PqTransportError.handshakeFailure('no pending initiate'),
      );
    }
    Uint8List? ssClassical;
    try {
      final opened = _openInitial(
        crypto,
        responderClassicalPublic,
        fromClient: false,
        keyDcid: _peerCid!,
      );
      if (opened.isFailure) return Result.failure(opened.errorOrNull!);
      final responderKey = opened.valueOrNull!.crypto;
      ssClassical = await crypto.classicalAgree(
        group,
        secretKey: p.classicalSecret,
        remotePublicKey: responderKey,
      );
      final combined = combineSharedSecret(
        group: group,
        kemSharedSecret: p.ssKem,
        classicalSharedSecret: ssClassical,
      );
      if (combined.isFailure) return Result.failure(combined.errorOrNull!);
      _installSession(
        combined.valueOrNull!,
        salt: p.salt,
        extra: Uint8List.fromList([
          ...p.ciphertext,
          ...p.classicalPublic,
          ...responderKey,
        ]),
      );
      _pendingInitiate = null;
      await _listen();
      return const Result.success(null);
    } on Object catch (e) {
      return Result.failure(
        PqTransportError.handshakeFailure('udp complete: ${e.runtimeType}'),
      );
    } finally {
      zeroize(p.classicalSecret);
      zeroize(p.ssKem);
      zeroize(ssClassical);
    }
  }

  /// Responder: own ML-KEM secret, receive initiator flight.
  Future<Result<Uint8List, PqTransportError>> accept({
    required Uint8List kemSecretKey,
    required Uint8List initiatorFlight,
    required Uint8List deploymentSalt,
  }) async {
    _isClient = false;
    final compatible = crypto.requireGroup(group);
    if (compatible.isFailure) return Result.failure(compatible.errorOrNull!);
    if (initiatorFlight.length < quicMinClientInitialUdpBytes ||
        (initiatorFlight[0] & 0x80) == 0) {
      return Result.failure(
        PqTransportError.illegalParameter(
          PqLengthLabel.datagram,
          initiatorFlight.length,
          quicMinClientInitialUdpBytes,
        ),
      );
    }
    final opened = _openInitial(crypto, initiatorFlight, fromClient: true);
    if (opened.isFailure) return Result.failure(opened.errorOrNull!);
    final flight = opened.valueOrNull!.crypto;
    final need = group.classicalShareBytes + group.kemCiphertextBytes;
    if (flight.length != need) {
      return Result.failure(
        PqTransportError.illegalParameter(
          PqLengthLabel.datagram,
          flight.length,
          need,
        ),
      );
    }
    _localCid = opened.valueOrNull!.dcid;
    _peerCid = opened.valueOrNull!.scid;
    final peerClassical = flight.sublist(0, group.classicalShareBytes);
    final ct = flight.sublist(group.classicalShareBytes);
    final classical = await crypto.classicalKeyGen(group);
    Uint8List? ssKem;
    Uint8List? ssClassical;
    try {
      ssKem = crypto.decapsulate(kemSecretKey, ct);
      ssClassical = await crypto.classicalAgree(
        group,
        secretKey: classical.secretKey,
        remotePublicKey: peerClassical,
      );
      final combined = combineSharedSecret(
        group: group,
        kemSharedSecret: ssKem,
        classicalSharedSecret: ssClassical,
      );
      if (combined.isFailure) return Result.failure(combined.errorOrNull!);
      _installSession(
        combined.valueOrNull!,
        salt: deploymentSalt,
        extra: Uint8List.fromList([
          ...ct,
          ...peerClassical,
          ...classical.publicKey,
        ]),
      );
      await _listen();
      return _protectInitial(
        crypto,
        dcid: _peerCid!,
        scid: _localCid!,
        keyDcid: _localCid!,
        cryptoData: classical.publicKey,
        fromClient: false,
        padToMinimum: false,
      );
    } on Object catch (e) {
      return Result.failure(
        PqTransportError.handshakeFailure('udp accept: ${e.runtimeType}'),
      );
    } finally {
      zeroize(classical.secretKey);
      zeroize(ssKem);
      zeroize(ssClassical);
    }
  }

  /// Directly install a 32-byte session key (tests / out-of-band).
  /// Does not start [incoming]. The handshake paths do.
  void installSessionKey(Uint8List key, {bool client = true}) {
    _isClient = client;
    _sessionKey = Uint8List.fromList(key);
    _installQuic(_sessionKey!);
    _recovery.markHandshakeConfirmed();
    _recovery.markPeerAddressValidated();
  }

  void _installSession(
    Uint8List hybridSs, {
    required Uint8List salt,
    required Uint8List extra,
  }) {
    final transcript = PqBytes.sha256(extra);
    final key = crypto.hkdf(
      ikm: hybridSs,
      salt: concatSalt(salt, transcript),
      info: udpSessionInfo('udp'),
    );
    zeroize(hybridSs);
    _sessionKey = key;
    _installQuic(key);
    _recovery.markHandshakeConfirmed();
    _recovery.markPeerAddressValidated();
  }

  void _installQuic(Uint8List sessionKey) {
    final schedule = TlsKeySchedule(crypto);
    final base = crypto.hkdfExtractSha384(
      Uint8List(schedule.hashLen),
      sessionKey,
    );
    final clientSecret = schedule.expandLabel(
      base,
      quicLabelClientIn,
      Uint8List(0),
      schedule.hashLen,
    );
    final serverSecret = schedule.expandLabel(
      base,
      quicLabelServerIn,
      Uint8List(0),
      schedule.hashLen,
    );
    final clientKeys = quicKeysFromTls(
      schedule: schedule,
      trafficSecret: clientSecret,
    );
    final serverKeys = quicKeysFromTls(
      schedule: schedule,
      trafficSecret: serverSecret,
    );
    _localCid ??= _connectionId(sessionKey, client: _isClient);
    _peerCid ??= _connectionId(sessionKey, client: !_isClient);
    _sealCodec = QuicPacketCodec.fromKeys(
      crypto,
      _isClient ? clientKeys : serverKeys,
    );
    _openCodec = QuicPacketCodec.fromKeys(
      crypto,
      _isClient ? serverKeys : clientKeys,
    );
  }

  Uint8List _connectionId(Uint8List sessionKey, {required bool client}) {
    return crypto.hkdf(
      ikm: sessionKey,
      salt: Uint8List(0),
      info: Uint8List.fromList(
        utf8.encode(
          client ? 'pqtransport udp cid client' : 'pqtransport udp cid server',
        ),
      ),
      length: quicShortDcidBytes,
    );
  }

  /// Opens one 1-RTT packet with this socket's receive keys.
  /// A long header is rejected. This is the opener [PqQuicConn] uses.
  Result<({int packetNumber, Uint8List payload}), PqTransportError> openPacket(
    Uint8List wire,
  ) {
    final codec = _openCodec;
    final local = _localCid;
    if (codec == null || local == null) {
      return Result.failure(PqTransportError.handshakeFailure('no session'));
    }
    if (wire.length < 1 + quicShortDcidBytes || (wire[0] & 0x80) != 0) {
      return Result.failure(PqTransportError.decodeFailure('not short header'));
    }
    for (var i = 0; i < local.length; i++) {
      if (wire[1 + i] != local[i]) {
        return Result.failure(PqTransportError.decodeFailure('dcid'));
      }
    }
    return codec.open(wire);
  }

  Future<void> _listen() async {
    await _sub?.cancel();
    _sub = raw.incoming.listen((d) {
      _serialized(() => _onDatagram(d));
    });
  }

  Future<void> _onDatagram(PqDatagramIn d) async {
    final opened = openPacket(d.data);
    if (opened.isFailure || _plain.isClosed) return;
    final pn = opened.valueOrNull!.packetNumber;
    if (_replay.isDuplicate(pn)) return;
    if (_replay.remember(pn).isFailure) return;
    final frames = decodeQuicPayload(opened.valueOrNull!.payload);
    if (frames.isFailure) return;
    final payload = frames.valueOrNull!;
    _peer = d.peer;
    for (final ack in payload.acks) {
      final event = _recovery.onAck(QuicPacketNumberSpace.application, ack);
      if (event.isFailure) return;
      await _applyRecovery(event.valueOrNull!);
    }
    for (final stream in payload.streams) {
      if (stream.id != 0) continue;
      if (!_deliveredOffsets.add(stream.offset)) continue;
      if (!_plain.isClosed) {
        _plain.add(PqDatagram(sequence: pn, payload: stream.data));
      }
    }
    if (!payload.ackEliciting) return;
    _received.onReceived(pn);
    await _seal(
      peer: d.peer,
      frames: const [],
      ackEliciting: false,
      inFlight: false,
    );
  }

  /// Runs RFC 9002 loss detection if [QuicLossRecovery.lossDetectionDeadline]
  /// is due on the caller-supplied clock. A deadline still in the future
  /// does nothing.
  Future<Result<void, PqTransportError>> driveLossDetection() {
    return _serialized(() async {
      final event = _recovery.onLossDetectionTimeout();
      if (event.isFailure) return Result.failure(event.errorOrNull!);
      await _applyRecovery(event.valueOrNull!);
      _armLossTimer();
      return const Result.success(null);
    });
  }

  Future<void> _applyRecovery(QuicRecoveryEvent event) async {
    final frames = <QuicRetransmittable>[
      for (final frame in event.retransmit)
        if (_recovery.shouldSend(frame)) frame,
    ];
    final probe = event.probeSpace;
    if (probe == QuicPacketNumberSpace.application) {
      const space = QuicPacketNumberSpace.application;
      final oldest = _recovery.oldestInFlightData(space);
      if (oldest.isEmpty) {
        frames.add(QuicRetransmitPing(space));
      } else {
        for (final frame in oldest) {
          if (_recovery.shouldSend(frame)) frames.add(frame);
        }
      }
    }
    final peer = _peer;
    if (frames.isEmpty || peer == null) return;
    await _seal(
      peer: peer,
      frames: frames,
      ackEliciting: true,
      inFlight: true,
      probe: probe != null || event.congestionProbe,
    );
  }

  Future<Result<void, PqTransportError>> send(
    Uint8List payload,
    PqEndpoint peer,
  ) {
    final frame = QuicRetransmitStream(
      streamId: 0,
      offset: _sendOffset,
      data: Uint8List.fromList(payload),
    );
    _sendOffset += payload.isEmpty ? 1 : payload.length;
    _peer = peer;
    return _serialized(
      () => _seal(
        peer: peer,
        frames: [frame],
        ackEliciting: true,
        inFlight: true,
      ),
    );
  }

  Future<Result<void, PqTransportError>> _seal({
    required PqEndpoint peer,
    required List<QuicRetransmittable> frames,
    required bool ackEliciting,
    required bool inFlight,
    bool probe = false,
  }) async {
    final codec = _sealCodec;
    final dcid = _peerCid;
    if (codec == null || dcid == null) {
      return Result.failure(PqTransportError.handshakeFailure('no session'));
    }
    const space = QuicPacketNumberSpace.application;
    final pn = _recovery.peekPacketNumber(space);
    final body = BytesBuilder(copy: false);
    if (_received.received.isNotEmpty) {
      final ack = _received.pendingAck();
      if (ack.isSuccess) body.add(ack.valueOrNull!.encode());
    }
    for (final frame in frames) {
      body.add(frame.encode());
    }
    if (body.isEmpty) return const Result.success(null);
    final sealed = codec.protect(
      dcid: dcid,
      packetNumber: pn,
      payload: body.takeBytes(),
    );
    if (sealed.isFailure) return Result.failure(sealed.errorOrNull!);
    final wire = sealed.valueOrNull!;
    if (!_recovery.canSend(wire.length, probe: probe, inFlight: inFlight)) {
      return Result.failure(PqTransportError.throttled('congestion window'));
    }
    final sent = await raw.send(wire, peer);
    if (sent.isFailure) return Result.failure(sent.errorOrNull!);
    _recovery.allocatePacketNumber(space);
    if (!ackEliciting && !inFlight) {
      _armLossTimer();
      return const Result.success(null);
    }
    final recorded = _recovery.onPacketSent(
      space: space,
      packetNumber: pn,
      sentBytes: wire.length,
      ackEliciting: ackEliciting,
      inFlight: inFlight,
      frames: frames,
      probe: probe,
    );
    _armLossTimer();
    return recorded;
  }

  void _armLossTimer() {
    _lossTimer?.cancel();
    if (_recovery.clock is! QuicSystemClock) return;
    final deadline = _recovery.lossDetectionDeadline;
    if (deadline == null || _plain.isClosed) return;
    final delay = deadline.difference(DateTime.now());
    _lossTimer = Timer(delay.isNegative ? Duration.zero : delay, () {
      unawaited(driveLossDetection());
    });
  }

  Future<T> _serialized<T>(Future<T> Function() job) {
    final result = _tail.then((_) => job());
    _tail = result.then<void>((_) {}, onError: (_) {});
    return result;
  }

  Future<void> close() async {
    _lossTimer?.cancel();
    await _sub?.cancel();
    await _plain.close();
    await raw.close();
    zeroize(_sessionKey);
  }
}

final class _PendingInitiate {
  _PendingInitiate({
    required this.classicalSecret,
    required this.classicalPublic,
    required this.ciphertext,
    required this.ssKem,
    required this.salt,
  });

  final Uint8List classicalSecret;
  final Uint8List classicalPublic;
  final Uint8List ciphertext;
  final Uint8List ssKem;
  final Uint8List salt;
}

Uint8List concatSalt(Uint8List salt, Uint8List transcript) =>
    Uint8List.fromList([...salt, ...transcript]);

Result<Uint8List, PqTransportError> _protectInitial(
  PqTransportCrypto crypto, {
  required Uint8List dcid,
  required Uint8List scid,
  required Uint8List keyDcid,
  required Uint8List cryptoData,
  required bool fromClient,
  required bool padToMinimum,
}) {
  final secrets = QuicInitialSecrets.derive(
    crypto: crypto,
    destinationConnectionId: keyDcid,
  );
  final codec = QuicInitialCodec(
    crypto: crypto,
    keys: fromClient ? secrets.client : secrets.server,
  );
  var payload = QuicCryptoFrame(offset: 0, data: cryptoData).encode();
  Result<Uint8List, PqTransportError>? sealed;
  for (var n = 0; n < 4; n++) {
    sealed = codec.protect(
      dcid: dcid,
      scid: scid,
      packetNumber: 0,
      payload: payload,
    );
    if (sealed.isFailure) return sealed;
    final wire = sealed.valueOrNull!;
    if (!padToMinimum || wire.length >= quicMinClientInitialUdpBytes) {
      return sealed;
    }
    final deficit = quicMinClientInitialUdpBytes - wire.length;
    payload = Uint8List(payload.length + deficit)..setAll(0, payload);
  }
  return sealed!;
}

Result<({Uint8List dcid, Uint8List scid, Uint8List crypto}), PqTransportError>
_openInitial(
  PqTransportCrypto crypto,
  Uint8List wire, {
  required bool fromClient,
  Uint8List? keyDcid,
}) {
  if (wire.length < 7 || (wire[0] & 0xf0) != 0xc0) {
    return Result.failure(PqTransportError.decodeFailure('not initial'));
  }
  final dcidLen = wire[5];
  if (wire.length < 6 + dcidLen + 1) {
    return Result.failure(PqTransportError.decodeFailure('short dcid'));
  }
  final dcid = Uint8List.sublistView(wire, 6, 6 + dcidLen);
  final scidLen = wire[6 + dcidLen];
  final scidAt = 7 + dcidLen;
  if (wire.length < scidAt + scidLen) {
    return Result.failure(PqTransportError.decodeFailure('short scid'));
  }
  final scid = Uint8List.sublistView(wire, scidAt, scidAt + scidLen);
  final secrets = QuicInitialSecrets.derive(
    crypto: crypto,
    destinationConnectionId: keyDcid ?? dcid,
  );
  final opened = QuicInitialCodec(
    crypto: crypto,
    keys: fromClient ? secrets.client : secrets.server,
  ).open(wire);
  if (opened.isFailure) return Result.failure(opened.errorOrNull!);
  final frames = decodeQuicPayload(opened.valueOrNull!.payload);
  if (frames.isFailure) return Result.failure(frames.errorOrNull!);
  final cryptoFrames = frames.valueOrNull!.crypto;
  if (cryptoFrames.isEmpty) {
    return Result.failure(PqTransportError.decodeFailure('no CRYPTO'));
  }
  return Result.success((
    dcid: Uint8List.fromList(dcid),
    scid: Uint8List.fromList(scid),
    crypto: cryptoFrames.single.data,
  ));
}
