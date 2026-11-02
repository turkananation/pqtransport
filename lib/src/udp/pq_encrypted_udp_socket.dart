import 'dart:async';
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
/// After the session is up, loss recovery is [QuicLossRecovery]: RFC 9002
/// packet threshold, time threshold, and PTO. A lost payload is a RFC 9000
/// STREAM frame sent again under a new packet number. The receiver's ACK
/// is a RFC 9000 ACK frame. The replay window drops a repeated packet
/// number before AEAD open, and a repeated stream offset is delivered once.
///
/// The outer bytes stay `version || header || nonce || ciphertext`. They
/// are not a QUIC long or short header. A QUIC peer will not accept them.
/// [clock] is the caller-supplied clock. [driveLossDetection] runs when
/// its deadline is due. A [QuicSystemClock] also arms a timer.
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

  PqDatagramCodec? _codec;
  final ReplayWindow _replay = ReplayWindow();
  final QuicAckProcessor _received = QuicAckProcessor();
  final Set<int> _deliveredOffsets = <int>{};
  int _nonceCounter = 0;
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

  bool get isEstablished => _codec != null;

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
      return Result.success(
        Uint8List.fromList([...classical.publicKey, ...enc.ciphertext]),
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
      ssClassical = await crypto.classicalAgree(
        group,
        secretKey: p.classicalSecret,
        remotePublicKey: responderClassicalPublic,
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
          ...responderClassicalPublic,
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
    final compatible = crypto.requireGroup(group);
    if (compatible.isFailure) return Result.failure(compatible.errorOrNull!);
    final need = group.classicalShareBytes + group.kemCiphertextBytes;
    if (initiatorFlight.length != need) {
      return Result.failure(
        PqTransportError.illegalParameter(
          PqLengthLabel.datagram,
          initiatorFlight.length,
          need,
        ),
      );
    }
    final peerClassical = initiatorFlight.sublist(0, group.classicalShareBytes);
    final ct = initiatorFlight.sublist(group.classicalShareBytes);
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
      return Result.success(classical.publicKey);
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
  void installSessionKey(Uint8List key) {
    _sessionKey = Uint8List.fromList(key);
    _codec = PqDatagramCodec(key: Uint8List.fromList(key), crypto: crypto);
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
    _codec = PqDatagramCodec(key: key, crypto: crypto);
    _recovery.markHandshakeConfirmed();
    _recovery.markPeerAddressValidated();
  }

  Future<void> _listen() async {
    await _sub?.cancel();
    _sub = raw.incoming.listen((d) {
      _serialized(() => _onDatagram(d));
    });
  }

  Future<void> _onDatagram(PqDatagramIn d) async {
    final codec = _codec;
    if (codec == null || _plain.isClosed) return;
    final seq = peekDatagramSequence(d.data);
    if (seq.isFailure) return;
    if (_replay.isDuplicate(seq.valueOrNull!)) return;
    final opened = codec.open(d.data);
    if (opened.isFailure) return;
    final pkt = opened.valueOrNull!;
    if (_replay.remember(pkt.sequence).isFailure) return;
    final frames = decodeQuicPayload(pkt.payload);
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
        _plain.add(PqDatagram(sequence: pkt.sequence, payload: stream.data));
      }
    }
    if (!payload.ackEliciting) return;
    _received.onReceived(pkt.sequence);
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
    final codec = _codec;
    if (codec == null) {
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
    if (body.length == 0) return const Result.success(null);
    final nonce = _nextNonce();
    final sealed = codec.seal(
      PqDatagram(sequence: pn, payload: body.takeBytes()),
      nonce: nonce,
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

  Uint8List _nextNonce() {
    final n = Uint8List(aeadNonceBytes);
    var v = _nonceCounter++;
    for (var i = aeadNonceBytes - 1; i >= 0 && v > 0; i--) {
      n[i] = v & 0xff;
      v >>= 8;
    }
    return n;
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
