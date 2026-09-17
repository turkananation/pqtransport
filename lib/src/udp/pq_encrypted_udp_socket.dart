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

/// ML-KEM + classical ECDH session then AEAD datagrams.
///
/// Live key agreement is implemented for all three RFC 10024 groups.
/// [HybridGroup.secP384r1MlKem1024] requires `PqForgeProfile.maximum`.
final class PqEncryptedUdpSocket {
  PqEncryptedUdpSocket({
    required this.raw,
    required this.crypto,
    this.group = HybridGroup.x25519MlKem768,
  });

  final PqUdpSocket raw;
  final PqTransportCrypto crypto;
  final HybridGroup group;

  PqDatagramCodec? _codec;
  final ReplayWindow _replay = ReplayWindow();
  int _nextSequence = 0;
  int _nonceCounter = 0;
  final StreamController<PqDatagram> _plain =
      StreamController<PqDatagram>.broadcast();
  StreamSubscription<PqDatagramIn>? _sub;
  Uint8List? _sessionKey;

  Stream<PqDatagram> get incoming => _plain.stream;

  bool get isEstablished => _codec != null;

  /// 32-byte application session key length after HKDF. Test seam only.
  int? get sessionKeyLength => _sessionKey?.length;

  /// Initiator: encapsulate to [peerKemPublicKey], emit handshake bytes.
  ///
  /// [role] is accepted for API compatibility and is **not** mixed into HKDF
  /// extra — initiator and responder must derive the same session key.
  Future<Result<Uint8List, PqTransportError>> initiate({
    required Uint8List peerKemPublicKey,
    required Uint8List deploymentSalt,
    String role = 'initiator',
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
    String role = 'responder',
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
  void installSessionKey(Uint8List key) {
    _sessionKey = Uint8List.fromList(key);
    _codec = PqDatagramCodec(key: Uint8List.fromList(key), crypto: crypto);
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
  }

  Future<void> _listen() async {
    await _sub?.cancel();
    _sub = raw.incoming.listen((d) {
      final codec = _codec;
      if (codec == null) return;
      final seq = peekDatagramSequence(d.data);
      if (seq.isFailure) return;
      if (_replay.isDuplicate(seq.valueOrNull!)) return;
      final opened = codec.open(d.data);
      if (opened.isFailure) return;
      final pkt = opened.valueOrNull!;
      if (_replay.remember(pkt.sequence).isFailure) return;
      _plain.add(pkt);
    });
  }

  Future<Result<void, PqTransportError>> send(
    Uint8List payload,
    PqEndpoint peer,
  ) async {
    final codec = _codec;
    if (codec == null) {
      return Result.failure(PqTransportError.handshakeFailure('no session'));
    }
    final seq = _nextSequence++;
    final nonce = _nextNonce();
    final sealed = codec.seal(
      PqDatagram(sequence: seq, payload: payload),
      nonce: nonce,
    );
    if (sealed.isFailure) return Result.failure(sealed.errorOrNull!);
    return raw.send(sealed.valueOrNull!, peer);
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
