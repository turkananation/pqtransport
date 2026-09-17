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
import 'cipher_suite.dart';

/// TLS 1.3 client with RFC 10024 hybrid key exchange.
final class PqTlsClient {
  PqTlsClient({
    PqTransportCrypto? crypto,
    this.group = HybridGroup.x25519MlKem768,
    List<HybridGroup>? offeredGroups,
    List<int>? offeredCipherSuites,
    this.allowUnauthenticated = false,
  }) : crypto = crypto ?? const PqTransportCrypto(),
       offeredGroups = offeredGroups ?? [group],
       offeredCipherSuites =
           offeredCipherSuites ?? tlsDefaultOfferedCipherSuites;

  final PqTransportCrypto crypto;
  final HybridGroup group;
  final List<HybridGroup> offeredGroups;
  final List<int> offeredCipherSuites;
  final bool allowUnauthenticated;

  final StateMachine<TlsState, TlsEvent> machine = tlsClientMachine();
  final Transcript transcript = Transcript();
  late final TlsKeySchedule schedule = TlsKeySchedule(crypto);
  TlsRecordLayer? records;

  Uint8List? _classicalSecret;
  Uint8List? _kemSecret;
  Uint8List? _hybridSs;
  Uint8List? _clientRandom;
  late HybridGroup _activeGroup;
  TlsCipherSuite _suite = TlsCipherSuite.aes256GcmSha384;
  var helloRetryCount = 0;

  TlsState get state => machine.currentState;
  bool get isComplete => machine.isIn(TlsState.handshakeCompleted);
  TlsCipherSuite get cipherSuite => _suite;

  Future<Result<Uint8List, PqTransportError>> startHandshake() async {
    final compatible = crypto.requireGroup(group);
    if (compatible.isFailure) return Result.failure(compatible.errorOrNull!);
    final driven = driveTls(machine, TlsEvent.startHandshake);
    if (driven.isFailure) return Result.failure(driven.errorOrNull!);
    _activeGroup = group;
    _clientRandom = crypto.randomBytes(handshakeRandomBytes);
    final share = await _newClientShare(_activeGroup);
    if (share.isFailure) return Result.failure(share.errorOrNull!);
    final hello = _clientHello(share.valueOrNull!);
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
    if (sh.valueOrNull!.isHelloRetryRequest) {
      return _ingestHelloRetry(sh.valueOrNull!, rec.valueOrNull!.payload);
    }
    final bound = _bindSuite(sh.valueOrNull!.cipherSuite);
    if (bound.isFailure) return Result.failure(bound.errorOrNull!);
    if (sh.valueOrNull!.group != _activeGroup) return _fail('group mismatch');
    final driven = driveTls(machine, TlsEvent.receiveServerHello);
    if (driven.isFailure) return Result.failure(driven.errorOrNull!);
    transcript.add(rec.valueOrNull!.payload);
    final decoded = decodeServerShare(_activeGroup, sh.valueOrNull!.share);
    if (decoded.isFailure) return Result.failure(decoded.errorOrNull!);
    final share = decoded.valueOrNull!;
    Uint8List? ssKem;
    Uint8List? ssClassical;
    try {
      ssKem = crypto.decapsulate(_kemSecret!, share.kemCiphertext);
      ssClassical = await crypto.classicalAgree(
        _activeGroup,
        secretKey: _classicalSecret!,
        remotePublicKey: share.classicalShare,
      );
      if (isAllZeros(ssClassical)) return _fail('classical all-zero');
      final combined = combineSharedSecret(
        group: _activeGroup,
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
    } on PqTransportError catch (e) {
      driveTls(machine, TlsEvent.fatal);
      return Result.failure(e);
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
        final fin = decodeFinished(msg, verifyDataLength: schedule.hashLen);
        if (fin.isFailure) return Result.failure(fin.errorOrNull!);
        final expected = schedule.finishedMac(
          schedule.serverFinishedKey,
          toMac,
        );
        if (!PqBytes.constantTimeEquals(expected, fin.valueOrNull!)) {
          return _fail('finished mac');
        }
        transcript.add(msg);
        final clientFin = encodeFinished(
          schedule.finishedMac(
            schedule.clientFinishedKey,
            transcript.snapshot(),
          ),
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

  Future<Result<List<Uint8List>, PqTransportError>> _ingestHelloRetry(
    ServerHello hrr,
    Uint8List hrrBytes,
  ) async {
    final noted = noteHelloRetry();
    if (noted.isFailure) return Result.failure(noted.errorOrNull!);
    if (!_offersGroup(hrr.group)) {
      return _fail('hrr group not offered');
    }
    final bound = _bindSuite(hrr.cipherSuite);
    if (bound.isFailure) return Result.failure(bound.errorOrNull!);
    final compatible = crypto.requireGroup(hrr.group);
    if (compatible.isFailure) return Result.failure(compatible.errorOrNull!);
    final cookie = hrr.cookie;
    if (cookie == null) return _fail('hrr missing cookie');
    final ch1 = transcript.bytes;
    rewriteTranscriptForHelloRetry(
      transcript: transcript,
      clientHello1: ch1,
      helloRetryRequest: hrrBytes,
      hash: schedule.transcriptHash,
    );
    zeroize(_kemSecret);
    zeroize(_classicalSecret);
    _kemSecret = null;
    _classicalSecret = null;
    _activeGroup = hrr.group;
    final share = await _newClientShare(_activeGroup);
    if (share.isFailure) return Result.failure(share.errorOrNull!);
    final hello = _clientHello(share.valueOrNull!, cookie: cookie);
    final encoded = hello.encode();
    transcript.add(encoded);
    return Result.success([
      encodePlainRecord(TlsRecord(type: tlsContentHandshake, payload: encoded)),
    ]);
  }

  ClientHello _clientHello(Uint8List share, {Uint8List? cookie}) => ClientHello(
    random: _clientRandom!,
    group: _activeGroup,
    share: share,
    cipherSuites: offeredCipherSuites,
    supportedGroups: [for (final g in offeredGroups) g.codepoint],
    cookie: cookie,
  );

  Future<Result<Uint8List, PqTransportError>> _newClientShare(
    HybridGroup shareGroup,
  ) async {
    final kem = crypto.kemKeyGen();
    final classical = await crypto.classicalKeyGen(shareGroup);
    _kemSecret = kem.secretKey;
    _classicalSecret = classical.secretKey;
    return encodeClientShare(
      HybridClientShare(
        group: shareGroup,
        kemEncapsulationKey: kem.publicKey,
        classicalShare: classical.publicKey,
      ),
    );
  }

  bool _offersGroup(HybridGroup g) {
    if (offeredGroups.contains(g)) return true;
    return g == group;
  }

  Result<void, PqTransportError> _bindSuite(int codepoint) {
    final selected = TlsCipherSuite.byCodepoint(codepoint);
    if (selected == null) {
      return Result.failure(
        PqTransportError.handshakeFailure('unexpected cipher suite'),
      );
    }
    if (!offeredCipherSuites.contains(selected.codepoint)) {
      return Result.failure(
        PqTransportError.handshakeFailure('cipher not offered'),
      );
    }
    _suite = selected;
    schedule.suite = selected;
    transcript.hashKind = selected.usesSha384
        ? TranscriptHashKind.sha384
        : TranscriptHashKind.sha256;
    return const Result.success(null);
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
