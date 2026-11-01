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
import 'certificate_policy.dart';

/// TLS 1.3 client with RFC 10024 hybrid key exchange.
final class PqTlsClient {
  PqTlsClient({
    PqTransportCrypto? crypto,
    this.group = HybridGroup.x25519MlKem768,
    List<HybridGroup>? offeredGroups,
    List<int>? offeredCipherSuites,
    List<String>? alpnProtocols,

    /// Skip identity checks. This is not authentication.
    ///
    /// Production callers leave this false. True lets the handshake finish
    /// without checking the peer signature. Finished is still checked.
    /// [peerAuthenticated] stays false for the life of the session, so the
    /// skip cannot be forgotten. A raw public key, an X.509 certificate,
    /// or a caller verify hook is a substitute. This flag is not.
    this.allowUnauthenticated = false,
    this.certificateTypes = const [TlsCertificateType.rawPublicKey],
    this.trustAnchors = const [],
    this.trustedSpki,
    this.verifyPeer,
    this.now,
    this.serverName,
    this.signatureSchemes,
    this.quic = false,
  }) : crypto = crypto ?? const PqTransportCrypto(),
       offeredGroups = offeredGroups ?? [group],
       offeredCipherSuites =
           offeredCipherSuites ?? tlsDefaultOfferedCipherSuites,
       alpnProtocols = alpnProtocols ?? const [httpAlpnH1];

  final PqTransportCrypto crypto;
  final HybridGroup group;
  final List<HybridGroup> offeredGroups;
  final List<int> offeredCipherSuites;
  final List<String> alpnProtocols;

  /// Skip identity checks. This is not authentication.
  ///
  /// See the constructor parameter. [peerAuthenticated] stays false when
  /// this is true.
  final bool allowUnauthenticated;

  /// Default is raw public key only. `[x509]` is the OpenSSL, curl, and
  /// browser shape: the ClientHello omits `server_certificate_type`.
  final List<TlsCertificateType> certificateTypes;

  /// DER trust anchors. Empty means the pin path, or fail closed.
  final List<Uint8List> trustAnchors;

  /// SubjectPublicKeyInfo of a self-signed leaf. Not a trust store.
  final Uint8List? trustedSpki;

  final PqCertificateHook? verifyPeer;

  /// Clock for the certificate path. Tests pass this. Null is `now.toUtc()`.
  final DateTime Function()? now;

  /// SAN check. Null skips it, so an extension-less certificate can be pinned.
  final String? serverName;

  /// Overrides the ClientHello signature list. Null keeps the default:
  /// ML-DSA only for a raw offer, and the schemes pqforge can verify when
  /// X.509 is offered.
  final List<int>? signatureSchemes;

  /// RFC 9001: handshake messages without the TLS record layer.
  final bool quic;

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
  String? selectedAlpn;
  var _peerAuthenticated = false;
  Uint8List? _peerPublicKey;
  int? _certificateType;
  List<Uint8List>? _certificateEntries;

  /// Handshake bytes that did not finish a message. RFC 8446 permits a
  /// handshake message to span records. OpenSSL sends one message per record.
  Uint8List _pendingHandshake = Uint8List(0);

  TlsState get state => machine.currentState;
  bool get isComplete => machine.isIn(TlsState.handshakeCompleted);
  TlsCipherSuite get cipherSuite => _suite;

  /// True only when this client checked CertificateVerify and the
  /// handshake then completed.
  ///
  /// False before completion, false after a fatal alert, and false when
  /// [allowUnauthenticated] skipped the check. Finished is not this bit.
  bool get peerAuthenticated => _peerAuthenticated && isComplete;

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
    return Result.success(wrapHandshake(encoded, quic: quic));
  }

  Future<Result<List<Uint8List>, PqTransportError>> ingest(
    Uint8List recordBytes,
  ) async {
    if (!quic &&
        recordBytes.isNotEmpty &&
        recordBytes[0] == tlsContentChangeCipherSpec) {
      return const Result.success([]);
    }
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
    final rec = unwrapHandshake(recordBytes, quic: quic);
    if (rec.isFailure) return Result.failure(rec.errorOrNull!);
    var shBytes = rec.valueOrNull!;
    var leftover = Uint8List(0);
    if (quic) {
      final n = handshakeWireLength(shBytes);
      if (n < 0 || n > shBytes.length) return _fail('truncated sh');
      leftover = n < shBytes.length
          ? slice(shBytes, n, shBytes.length)
          : Uint8List(0);
      shBytes = slice(shBytes, 0, n);
    }
    final sh = ServerHello.decode(shBytes);
    if (sh.isFailure) return Result.failure(sh.errorOrNull!);
    if (sh.valueOrNull!.isHelloRetryRequest) {
      if (leftover.isNotEmpty) return _fail('trailing after hrr');
      return _ingestHelloRetry(sh.valueOrNull!, shBytes);
    }
    final bound = _bindSuite(sh.valueOrNull!.cipherSuite);
    if (bound.isFailure) return Result.failure(bound.errorOrNull!);
    if (sh.valueOrNull!.group != _activeGroup) return _fail('group mismatch');
    final driven = driveTls(machine, TlsEvent.receiveServerHello);
    if (driven.isFailure) return Result.failure(driven.errorOrNull!);
    transcript.add(shBytes);
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
      if (quic && leftover.isNotEmpty) {
        return await _ingestEncrypted(leftover);
      }
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
    Uint8List payload;
    if (quic) {
      payload = recordBytes;
    } else {
      final layer = records;
      if (layer == null) return _fail('no records');
      final inner = layer.openWith(
        trafficSecret: schedule.serverHandshakeTraffic,
        iv: schedule.serverHandshakeIv,
        wire: recordBytes,
        epoch: TlsRecordEpoch.handshake,
      );
      if (inner.isFailure) return Result.failure(inner.errorOrNull!);
      payload = inner.valueOrNull!.payload;
    }
    if (_pendingHandshake.isEmpty) {
      _pendingHandshake = payload;
    } else {
      _pendingHandshake = concatBytes([_pendingHandshake, payload]);
    }
    if (_pendingHandshake.length > tlsHandshakeReassemblyMaxBytes) {
      return _fail('handshake too large');
    }
    var offset = 0;
    Uint8List? finishedRecord;
    final buf = _pendingHandshake;
    while (buf.length - offset >= tlsHandshakeHeaderBytes) {
      final len = readUint24(buf, offset + 1);
      final end = offset + tlsHandshakeHeaderBytes + len;
      if (end > buf.length) break;
      final msg = slice(buf, offset, end);
      final type = msg[0];
      if (type == tlsHsEncryptedExtensions) {
        final ee = decodeEncryptedExtensions(msg);
        if (ee.isFailure) return Result.failure(ee.errorOrNull!);
        final selected = ee.valueOrNull!.alpnProtocol;
        if (selected != null && !alpnProtocols.contains(selected)) {
          return _fail('alpn not offered');
        }
        selectedAlpn = selected;
        final type = _selectedCertificateType(ee.valueOrNull!);
        if (type.isFailure) return _fatal(type.errorOrNull!, onWire: false);
        _certificateType = type.valueOrNull;
        final d = driveTls(machine, TlsEvent.receiveEncryptedExtensions);
        if (d.isFailure) return Result.failure(d.errorOrNull!);
        transcript.add(msg);
      } else if (type == tlsHsCertificate) {
        final d = driveTls(machine, TlsEvent.receiveCertificate);
        if (d.isFailure) return Result.failure(d.errorOrNull!);
        final cert = decodeCertificateEntries(msg);
        if (cert.isFailure) return _fatal(cert.errorOrNull!);
        final entries = cert.valueOrNull!;
        if (_certificateType == tlsCertTypeRawPublicKey) {
          if (entries.length != 1) {
            return _fatal(PqTransportError.decodeFailure('raw public key'));
          }
          if (PqX509.parse(entries.single).certificate != null) {
            return _fatal(PqTransportError.unsupportedCertificate('x509'));
          }
          final spki = decodeMlDsa65Spki(entries.single);
          if (spki.isFailure) return _fatal(spki.errorOrNull!);
          _peerPublicKey = spki.valueOrNull;
        } else {
          if (decodeMlDsa65Spki(entries.first).isSuccess &&
              PqX509.parse(entries.first).certificate == null) {
            return _fatal(
              PqTransportError.unsupportedCertificate('raw public key'),
            );
          }
          for (final der in entries) {
            final one = PqX509.parse(der);
            if (one.certificate == null) {
              return _fatal(x509Failure(one.failure!));
            }
          }
          _certificateEntries = entries;
        }
        transcript.add(msg);
      } else if (type == tlsHsCertificateVerify) {
        final toSign = tls13ServerCertVerifyContent(transcript.snapshot());
        final d = driveTls(machine, TlsEvent.receiveCertVerify);
        if (d.isFailure) return Result.failure(d.errorOrNull!);
        final sig = decodeCertVerify(msg);
        if (sig.isFailure) return Result.failure(sig.errorOrNull!);
        if (!allowUnauthenticated) {
          if (_certificateType == tlsCertTypeRawPublicKey) {
            final certPk = _peerPublicKey;
            if (certPk == null) return _fail('cv without cert');
            if (sig.valueOrNull!.scheme != tlsSignatureMldsa65 &&
                sig.valueOrNull!.scheme != tlsSignatureMldsa87) {
              return _fatal(PqTransportError.decryptError('signature_scheme'));
            }
            final ok = crypto.mlDsaVerify(
              publicKey: certPk,
              message: toSign,
              signatureBytes: sig.valueOrNull!.signature,
            );
            if (!ok) return _fail('ml-dsa verify failed');
          } else {
            final entries = _certificateEntries;
            if (entries == null) return _fail('cv without cert');
            final clock = now == null ? DateTime.now().toUtc() : now!();
            final leaf = authenticateX509(
              entries: entries,
              trustAnchors: trustAnchors,
              trustedSpki: trustedSpki,
              now: clock,
              serverName: serverName,
              verifyPeer: verifyPeer,
              verify: sig.valueOrNull!,
            );
            if (leaf.isFailure) return _fatal(leaf.errorOrNull!);
            final checked = verifyLeafSignature(
              leaf: leaf.valueOrNull!,
              verify: sig.valueOrNull!,
              content: toSign,
              mlDsaVerify: crypto.mlDsaVerify,
            );
            if (checked.isFailure) return _fatal(checked.errorOrNull!);
            final key = leaf.valueOrNull!.publicKey;
            if (key is PqX509MlDsaKey) _peerPublicKey = key.raw;
          }
          _peerAuthenticated = true;
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
        if (quic) {
          finishedRecord = clientFin;
        } else {
          finishedRecord = records!.protectWith(
            trafficSecret: schedule.clientHandshakeTraffic,
            iv: schedule.clientHandshakeIv,
            inner: TlsRecord(type: tlsContentHandshake, payload: clientFin),
            epoch: TlsRecordEpoch.handshake,
          );
        }
        schedule.deriveApplication(
          hybridSharedSecret: _hybridSs!,
          applicationTranscriptHash: transcript.snapshot(),
        );
      } else {
        return _fail('hs type $type');
      }
      offset = end;
    }
    _pendingHandshake = offset == 0
        ? buf
        : (offset == buf.length
              ? Uint8List(0)
              : slice(buf, offset, buf.length));
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
    return Result.success([wrapHandshake(encoded, quic: quic)]);
  }

  ClientHello _clientHello(Uint8List share, {Uint8List? cookie}) => ClientHello(
    random: _clientRandom!,
    group: _activeGroup,
    share: share,
    cipherSuites: offeredCipherSuites,
    alpnProtocols: alpnProtocols,
    supportedGroups: [for (final g in offeredGroups) g.codepoint],
    serverName: serverName ?? 'localhost',
    cookie: cookie,
    certificateTypes: certificateTypes,
    signatureSchemes:
        signatureSchemes ??
        (certificateTypes.contains(TlsCertificateType.x509)
            ? const [
                tlsSignatureMldsa65,
                tlsSignatureMldsa87,
                tlsSignatureEcdsaP256Sha256,
                tlsSignatureEcdsaP384Sha384,
                tlsSignatureEd25519,
                tlsSignatureRsaPssSha256,
                tlsSignatureRsaPssSha384,
                tlsSignatureRsaPssSha512,
              ]
            : const [tlsSignatureMldsa65, tlsSignatureMldsa87]),
  );

  Result<int, PqTransportError> _selectedCertificateType(
    EncryptedExtensions ee,
  ) {
    final selected = ee.serverCertificateType;
    final rawOnly =
        certificateTypes.length == 1 &&
        certificateTypes.single == TlsCertificateType.rawPublicKey;
    if (rawOnly) {
      if (selected != tlsCertTypeRawPublicKey) {
        return Result.failure(
          PqTransportError.decodeFailure(
            'EncryptedExtensions missing server_certificate_type (OPEN-04)',
          ),
        );
      }
      return Result.success(tlsCertTypeRawPublicKey);
    }
    final type = selected ?? tlsCertTypeX509;
    if (type == tlsCertTypeRawPublicKey &&
        !certificateTypes.contains(TlsCertificateType.rawPublicKey)) {
      return Result.failure(
        PqTransportError.unsupportedCertificate('raw public key'),
      );
    }
    if (type == tlsCertTypeX509 &&
        !certificateTypes.contains(TlsCertificateType.x509)) {
      return Result.failure(PqTransportError.unsupportedCertificate('x509'));
    }
    return Result.success(type);
  }

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

  PqTransportError? _certificateFailure;

  Result<List<Uint8List>, PqTransportError> _fatal(
    PqTransportError error, {
    bool onWire = true,
  }) {
    _peerAuthenticated = false;
    _peerPublicKey = null;
    _pendingHandshake = Uint8List(0);
    if (onWire) _certificateFailure = error;
    driveTls(machine, TlsEvent.fatal);
    return Result.failure(error);
  }

  /// One fatal Alert under the handshake write key, after a certificate
  /// failure. Null for older failures, for QUIC, and before the caller
  /// asks. The record is not sent by [ingest].
  Uint8List? certificateAlert(PqTransportError error) {
    if (!identical(error, _certificateFailure)) return null;
    final alert = error.alert;
    if (alert == null || quic) return null;
    final payload = Uint8List.fromList([2, alert]);
    final layer = records;
    if (layer == null) {
      return encodePlainRecord(
        TlsRecord(type: tlsContentAlert, payload: payload),
      );
    }
    return layer.protectWith(
      trafficSecret: schedule.clientHandshakeTraffic,
      iv: schedule.clientHandshakeIv,
      inner: TlsRecord(type: tlsContentAlert, payload: payload),
      epoch: TlsRecordEpoch.handshake,
    );
  }

  Result<List<Uint8List>, PqTransportError> _fail(String why) {
    _peerAuthenticated = false;
    _peerPublicKey = null;
    _pendingHandshake = Uint8List(0);
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
