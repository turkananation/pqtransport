import 'dart:typed_data';

import 'package:pqforge/pqforge.dart';
import 'package:swissarmyknife/swissarmyknife.dart';

import '../core/bytes.dart';
import '../core/crypto.dart';
import '../core/errors.dart';
import '../core/hybrid.dart';
import '../core/lengths.dart';
import '../core/transcript.dart';
import '../core/zeroize.dart';
import 'handshake.dart';
import 'key_schedule.dart';
import 'machines.dart';
import 'record.dart';
import 'tls_state.dart';

final class PqTlsServerIdentity {
  PqTlsServerIdentity({required this.publicKey, required this.secretKey});

  final Uint8List publicKey;
  final Uint8List secretKey;

  factory PqTlsServerIdentity.generate(PqTransportCrypto crypto) {
    final kp = crypto.mlDsaKeyGen();
    return PqTlsServerIdentity(
      publicKey: kp.publicKey,
      secretKey: kp.secretKey,
    );
  }
}

/// TLS 1.3 server with RFC 10024 X25519MLKEM768.
final class PqTlsServer {
  PqTlsServer({
    PqTransportCrypto? crypto,
    this.group = HybridGroup.x25519MlKem768,
    PqTlsServerIdentity? identity,
  }) : crypto = crypto ?? const PqTransportCrypto(),
       identity =
           identity ??
           PqTlsServerIdentity.generate(crypto ?? const PqTransportCrypto());

  final PqTransportCrypto crypto;
  final HybridGroup group;
  final PqTlsServerIdentity identity;

  final StateMachine<TlsState, TlsEvent> machine = tlsServerMachine();
  final Transcript transcript = Transcript();
  late final TlsKeySchedule schedule = TlsKeySchedule(crypto);
  TlsRecordLayer? records;
  Uint8List? _hybridSs;

  TlsState get state => machine.currentState;
  bool get isComplete => machine.isIn(TlsState.handshakeCompleted);

  Future<Result<List<Uint8List>, PqTransportError>> ingest(
    Uint8List recordBytes,
  ) async {
    if (state == TlsState.waitClientHello) {
      return _onClientHello(recordBytes);
    }
    if (state == TlsState.serverHelloSent) {
      return _onClientFinished(recordBytes);
    }
    driveTls(machine, TlsEvent.fatal);
    return Result.failure(
      PqTransportError.unexpectedMessage('ingest in $state'),
    );
  }

  Future<Result<List<Uint8List>, PqTransportError>> _onClientHello(
    Uint8List recordBytes,
  ) async {
    if (group != HybridGroup.x25519MlKem768) {
      return Result.failure(
        PqTransportError.unsupported(
          '${group.name} live handshake needs classical ECDH from pqforge',
        ),
      );
    }
    final rec = decodePlainRecord(recordBytes);
    if (rec.isFailure) return Result.failure(rec.errorOrNull!);
    if (rec.valueOrNull!.type != tlsContentHandshake) {
      return _fail('expected handshake');
    }
    final ch = ClientHello.decode(rec.valueOrNull!.payload);
    if (ch.isFailure) return Result.failure(ch.errorOrNull!);
    if (ch.valueOrNull!.group != group) return _fail('group mismatch');
    final driven = driveTls(machine, TlsEvent.receiveClientHello);
    if (driven.isFailure) return Result.failure(driven.errorOrNull!);
    transcript.add(rec.valueOrNull!.payload);
    final decoded = decodeClientShare(group, ch.valueOrNull!.share);
    if (decoded.isFailure) return Result.failure(decoded.errorOrNull!);
    final clientShare = decoded.valueOrNull!;
    final x = await crypto.x25519KeyGen();
    Uint8List? ssKem;
    Uint8List? ssX;
    try {
      final enc = crypto.encapsulate(clientShare.kemEncapsulationKey);
      ssKem = enc.sharedSecret;
      ssX = await crypto.x25519Agree(
        secretKey: x.secretKey,
        remotePublicKey: clientShare.classicalShare,
      );
      if (isAllZeros(ssX)) return _fail('x25519 all-zero');
      final combined = combineSharedSecret(
        group: group,
        kemSharedSecret: ssKem,
        classicalSharedSecret: ssX,
      );
      if (combined.isFailure) return Result.failure(combined.errorOrNull!);
      _hybridSs = combined.valueOrNull!;
      final serverShare = encodeServerShare(
        HybridServerShare(
          group: group,
          kemCiphertext: enc.ciphertext,
          classicalShare: x.publicKey,
        ),
      );
      if (serverShare.isFailure) {
        return Result.failure(serverShare.errorOrNull!);
      }
      final sh = ServerHello(
        random: crypto.randomBytes(handshakeRandomBytes),
        group: group,
        share: serverShare.valueOrNull!,
      );
      final shBytes = sh.encode();
      transcript.add(shBytes);
      schedule.deriveHandshake(
        hybridSharedSecret: _hybridSs!,
        handshakeTranscriptHash: transcript.snapshot(),
      );
      records = TlsRecordLayer(crypto, schedule);
      final ee = encodeEncryptedExtensions();
      transcript.add(ee);
      final cert = encodeCertificate(identity.publicKey);
      transcript.add(cert);
      final toSign = transcript.snapshot();
      final sig = crypto.mlDsaSign(
        secretKey: identity.secretKey,
        message: toSign,
      );
      final cv = encodeCertVerify(sig);
      transcript.add(cv);
      final fin = encodeFinished(
        crypto.hmac(schedule.serverFinishedKey, transcript.snapshot()),
      );
      transcript.add(fin);
      final protected = records!.protectWith(
        trafficSecret: schedule.serverHandshakeTraffic,
        iv: schedule.serverHandshakeIv,
        inner: TlsRecord(
          type: tlsContentHandshake,
          payload: concatBytes([ee, cert, cv, fin]),
        ),
        epoch: TlsRecordEpoch.handshake,
      );
      return Result.success([
        encodePlainRecord(
          TlsRecord(type: tlsContentHandshake, payload: shBytes),
        ),
        protected,
      ]);
    } on Object catch (e) {
      return _fail('kex ${e.runtimeType}');
    } finally {
      zeroize(x.secretKey);
      zeroize(ssKem);
      zeroize(ssX);
    }
  }

  Future<Result<List<Uint8List>, PqTransportError>> _onClientFinished(
    Uint8List recordBytes,
  ) async {
    final layer = records;
    if (layer == null) return _fail('no records');
    final inner = layer.openWith(
      trafficSecret: schedule.clientHandshakeTraffic,
      iv: schedule.clientHandshakeIv,
      wire: recordBytes,
      epoch: TlsRecordEpoch.handshake,
    );
    if (inner.isFailure) return Result.failure(inner.errorOrNull!);
    final fin = decodeFinished(inner.valueOrNull!.payload);
    if (fin.isFailure) return Result.failure(fin.errorOrNull!);
    final expected = crypto.hmac(
      schedule.clientFinishedKey,
      transcript.snapshot(),
    );
    if (!PqBytes.constantTimeEquals(expected, fin.valueOrNull!)) {
      return _fail('client finished mac');
    }
    transcript.add(inner.valueOrNull!.payload);
    final driven = driveTls(machine, TlsEvent.receiveFinished);
    if (driven.isFailure) return Result.failure(driven.errorOrNull!);
    schedule.deriveApplication(
      hybridSharedSecret: _hybridSs!,
      applicationTranscriptHash: transcript.snapshot(),
    );
    return const Result.success([]);
  }

  Result<List<Uint8List>, PqTransportError> _fail(String why) {
    driveTls(machine, TlsEvent.fatal);
    return Result.failure(PqTransportError.handshakeFailure(why));
  }

  Uint8List exporter(String label, Uint8List context, int length) =>
      schedule.exporter(label, context, length);

  Future<void> close() async {
    driveTls(machine, TlsEvent.close);
    zeroize(_hybridSs);
  }
}
