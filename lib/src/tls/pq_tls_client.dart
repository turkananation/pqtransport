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

/// TLS 1.3 client with RFC 10024 hybrid key exchange.
final class PqTlsClient {
  PqTlsClient({
    PqTransportCrypto? crypto,
    this.group = HybridGroup.x25519MlKem768,
    this.allowUnauthenticated = false,
  }) : crypto = crypto ?? const PqTransportCrypto();

  final PqTransportCrypto crypto;
  final HybridGroup group;
  final bool allowUnauthenticated;

  final StateMachine<TlsState, TlsEvent> machine = tlsClientMachine();
  final Transcript transcript = Transcript();
  late final TlsKeySchedule schedule = TlsKeySchedule(crypto);
  TlsRecordLayer? records;

  Uint8List? _classicalSecret;
  Uint8List? _kemSecret;
  Uint8List? _hybridSs;
  var helloRetryCount = 0;

  TlsState get state => machine.currentState;
  bool get isComplete => machine.isIn(TlsState.handshakeCompleted);

  Future<Result<Uint8List, PqTransportError>> startHandshake() async {
    final compatible = crypto.requireGroup(group);
    if (compatible.isFailure) return Result.failure(compatible.errorOrNull!);
    final driven = driveTls(machine, TlsEvent.startHandshake);
    if (driven.isFailure) return Result.failure(driven.errorOrNull!);
    final kem = crypto.kemKeyGen();
    final classical = await crypto.classicalKeyGen(group);
    _kemSecret = kem.secretKey;
    _classicalSecret = classical.secretKey;
    final share = encodeClientShare(
      HybridClientShare(
        group: group,
        kemEncapsulationKey: kem.publicKey,
        classicalShare: classical.publicKey,
      ),
    );
    if (share.isFailure) return Result.failure(share.errorOrNull!);
    final hello = ClientHello(
      random: crypto.randomBytes(handshakeRandomBytes),
      group: group,
      share: share.valueOrNull!,
    );
    final encoded = hello.encode();
    transcript.add(encoded);
    return Result.success(
      encodePlainRecord(TlsRecord(type: tlsContentHandshake, payload: encoded)),
    );
  }

  Future<Result<List<Uint8List>, PqTransportError>> ingest(
    Uint8List recordBytes,
  ) async {
    if (state == TlsState.clientHelloSent) {
      return _ingestServerHello(recordBytes);
    }
    if (state == TlsState.serverHelloProcessed ||
        state == TlsState.waitCertificate ||
        state == TlsState.waitCertVerify ||
        state == TlsState.waitFinished) {
      return _ingestEncrypted(recordBytes);
    }
    driveTls(machine, TlsEvent.fatal);
    return Result.failure(
      PqTransportError.unexpectedMessage('ingest in $state'),
    );
  }

  Result<List<Uint8List>, PqTransportError> noteHelloRetry() {
    if (helloRetryCount >= tlsMaxHelloRetry) {
      driveTls(machine, TlsEvent.fatal);
      return Result.failure(
        PqTransportError.handshakeFailure('second hello retry'),
      );
    }
    helloRetryCount++;
    final driven = driveTls(machine, TlsEvent.receiveHelloRetry);
    if (driven.isFailure) return Result.failure(driven.errorOrNull!);
    return const Result.success([]);
  }

  Future<Result<List<Uint8List>, PqTransportError>> _ingestServerHello(
    Uint8List recordBytes,
  ) async {
    final rec = decodePlainRecord(recordBytes);
    if (rec.isFailure) return Result.failure(rec.errorOrNull!);
    if (rec.valueOrNull!.type != tlsContentHandshake) {
      return _fail('expected handshake');
    }
    final sh = ServerHello.decode(rec.valueOrNull!.payload);
    if (sh.isFailure) return Result.failure(sh.errorOrNull!);
    if (sh.valueOrNull!.group != group) return _fail('group mismatch');
    final driven = driveTls(machine, TlsEvent.receiveServerHello);
    if (driven.isFailure) return Result.failure(driven.errorOrNull!);
    transcript.add(rec.valueOrNull!.payload);
    final decoded = decodeServerShare(group, sh.valueOrNull!.share);
    if (decoded.isFailure) return Result.failure(decoded.errorOrNull!);
    final share = decoded.valueOrNull!;
    Uint8List? ssKem;
    Uint8List? ssClassical;
    try {
      ssKem = crypto.decapsulate(_kemSecret!, share.kemCiphertext);
      ssClassical = await crypto.classicalAgree(
        group,
        secretKey: _classicalSecret!,
        remotePublicKey: share.classicalShare,
      );
      if (isAllZeros(ssClassical)) return _fail('classical all-zero');
      final combined = combineSharedSecret(
        group: group,
        kemSharedSecret: ssKem,
        classicalSharedSecret: ssClassical,
      );
      if (combined.isFailure) return Result.failure(combined.errorOrNull!);
      _hybridSs = combined.valueOrNull!;
      schedule.deriveHandshake(
        hybridSharedSecret: _hybridSs!,
        handshakeTranscriptHash: transcript.snapshot(),
      );
      records = TlsRecordLayer(crypto, schedule);
      return const Result.success([]);
    } on Object catch (e) {
      return _fail('kex ${e.runtimeType}');
    } finally {
      zeroize(_kemSecret);
      zeroize(_classicalSecret);
      zeroize(ssKem);
      zeroize(ssClassical);
    }
  }

  Future<Result<List<Uint8List>, PqTransportError>> _ingestEncrypted(
    Uint8List recordBytes,
  ) async {
    final layer = records;
    if (layer == null) return _fail('no records');
    final inner = layer.openWith(
      trafficSecret: schedule.serverHandshakeTraffic,
      iv: schedule.serverHandshakeIv,
      wire: recordBytes,
      epoch: TlsRecordEpoch.handshake,
    );
    if (inner.isFailure) return Result.failure(inner.errorOrNull!);
    final payload = inner.valueOrNull!.payload;
    var offset = 0;
    Uint8List? certPk;
    Uint8List? finishedRecord;
    while (offset < payload.length) {
      if (payload.length - offset < tlsHandshakeHeaderBytes) {
        return _fail('truncated hs');
      }
      final len = readUint24(payload, offset + 1);
      final end = offset + tlsHandshakeHeaderBytes + len;
      if (end > payload.length) return _fail('hs overflow');
      final msg = slice(payload, offset, end);
      final type = msg[0];
      if (type == tlsHsEncryptedExtensions) {
        final ee = decodeEncryptedExtensions(msg);
        if (ee.isFailure) return Result.failure(ee.errorOrNull!);
        final d = driveTls(machine, TlsEvent.receiveEncryptedExtensions);
        if (d.isFailure) return Result.failure(d.errorOrNull!);
        transcript.add(msg);
      } else if (type == tlsHsCertificate) {
        final d = driveTls(machine, TlsEvent.receiveCertificate);
        if (d.isFailure) return Result.failure(d.errorOrNull!);
        final cert = decodeCertificate(msg);
        if (cert.isFailure) return Result.failure(cert.errorOrNull!);
        certPk = cert.valueOrNull;
        transcript.add(msg);
      } else if (type == tlsHsCertificateVerify) {
        final toSign = transcript.snapshot();
        final d = driveTls(machine, TlsEvent.receiveCertVerify);
        if (d.isFailure) return Result.failure(d.errorOrNull!);
        final sig = decodeCertVerify(msg);
        if (sig.isFailure) return Result.failure(sig.errorOrNull!);
        if (!allowUnauthenticated) {
          if (certPk == null) return _fail('cv without cert');
          final ok = crypto.mlDsaVerify(
            publicKey: certPk,
            message: toSign,
            signatureBytes: sig.valueOrNull!,
          );
          if (!ok) return _fail('ml-dsa verify failed');
        }
        transcript.add(msg);
      } else if (type == tlsHsFinished) {
        final toMac = transcript.snapshot();
        final d = driveTls(machine, TlsEvent.receiveFinished);
        if (d.isFailure) return Result.failure(d.errorOrNull!);
        final fin = decodeFinished(msg);
        if (fin.isFailure) return Result.failure(fin.errorOrNull!);
        final expected = crypto.hmac(schedule.serverFinishedKey, toMac);
        if (!PqBytes.constantTimeEquals(expected, fin.valueOrNull!)) {
          return _fail('finished mac');
        }
        transcript.add(msg);
        final clientFin = encodeFinished(
          crypto.hmac(schedule.clientFinishedKey, transcript.snapshot()),
        );
        transcript.add(clientFin);
        finishedRecord = layer.protectWith(
          trafficSecret: schedule.clientHandshakeTraffic,
          iv: schedule.clientHandshakeIv,
          inner: TlsRecord(type: tlsContentHandshake, payload: clientFin),
          epoch: TlsRecordEpoch.handshake,
        );
        schedule.deriveApplication(
          hybridSharedSecret: _hybridSs!,
          applicationTranscriptHash: transcript.snapshot(),
        );
      } else {
        return _fail('hs type $type');
      }
      offset = end;
    }
    return Result.success(
      finishedRecord == null ? const <Uint8List>[] : [finishedRecord],
    );
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
