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
import 'identity.dart';
import 'key_schedule.dart';
import 'machines.dart';
import 'record.dart';
import 'tls_state.dart';
import 'resumption.dart';
import 'cipher_suite.dart';
import 'certificate_policy.dart';
import 'ech.dart';
import 'key_share.dart';
import 'named_group.dart';

final class PqTlsServerIdentity {
  PqTlsServerIdentity({
    required this.publicKey,
    required this.secretKey,
    this.chain = const [],
    this.signContent,
    this.certificateMessage,
    this.leafScheme = tlsSignatureMldsa65,
  });

  final Uint8List publicKey;
  final Uint8List secretKey;
  final List<Uint8List> chain;
  final Uint8List Function(Uint8List content)? signContent;
  final Uint8List? certificateMessage;
  final int leafScheme;

  factory PqTlsServerIdentity.generate(PqTransportCrypto crypto) {
    final kp = crypto.mlDsaKeyGen();
    return PqTlsServerIdentity(
      publicKey: kp.publicKey,
      secretKey: kp.secretKey,
    );
  }

  /// RFC 9881 public key and RFC 5958 private key, PEM or DER.
  static Result<PqTlsServerIdentity, PqTransportError> parse(
    Uint8List publicKey,
    Uint8List privateKey,
  ) {
    final decoded = decodeMlDsaIdentity(publicKey, privateKey);
    if (decoded.isFailure) return Result.failure(decoded.errorOrNull!);
    final keys = decoded.valueOrNull!;
    return Result.success(
      PqTlsServerIdentity(publicKey: keys.publicKey, secretKey: keys.secretKey),
    );
  }

  /// RFC 7468 PEM. Refuses `ENCRYPTED PRIVATE KEY`.
  static Result<PqTlsServerIdentity, PqTransportError> parsePem(
    String publicKeyPem,
    String privateKeyPem,
  ) {
    final decoded = decodeMlDsaIdentityPem(publicKeyPem, privateKeyPem);
    if (decoded.isFailure) return Result.failure(decoded.errorOrNull!);
    final keys = decoded.valueOrNull!;
    return Result.success(
      PqTlsServerIdentity(publicKey: keys.publicKey, secretKey: keys.secretKey),
    );
  }

  /// X.509 chain, leaf first. The Certificate message is cached.
  /// [sign] covers the CertificateVerify content, not the certificate TBS.
  factory PqTlsServerIdentity.x509({
    required PqX509PublicKey leafKey,
    required Uint8List Function(Uint8List content) sign,
    required List<Uint8List> chain,
    String? certificateDnsName,
  }) {
    if (chain.isEmpty || chain.length > tlsCertificateListMax) {
      throw ArgumentError.value(chain.length, 'chain', 'expected 1..8');
    }
    final copies = [for (final der in chain) Uint8List.fromList(der)];
    final parsed = <PqX509Certificate>[];
    for (final der in copies) {
      final one = PqX509.parse(der);
      final certificate = one.certificate;
      if (certificate == null) {
        throw ArgumentError.value(
          one.failure,
          'chain',
          'certificate did not parse',
        );
      }
      parsed.add(certificate);
    }
    final leaf = parsed.first;
    if (!_leafKeyEquals(leaf.publicKey, leafKey)) {
      throw ArgumentError('leaf key does not match the certificate');
    }
    if (certificateDnsName != null && !_dnsName(leaf, certificateDnsName)) {
      throw ArgumentError.value(
        certificateDnsName,
        'certificateDnsName',
        'not a DNS SAN on the leaf',
      );
    }
    final scheme = switch (leaf.algorithm) {
      PqX509Algorithm.mlDsa65 => tlsSignatureMldsa65,
      PqX509Algorithm.mlDsa87 => tlsSignatureMldsa87,
      PqX509Algorithm.ecdsaP256Sha256 => tlsSignatureEcdsaP256Sha256,
      PqX509Algorithm.ecdsaP384Sha384 => tlsSignatureEcdsaP384Sha384,
      PqX509Algorithm.ed25519 => tlsSignatureEd25519,
      PqX509Algorithm.rsaPssSha256 => tlsSignatureRsaPssSha256,
      PqX509Algorithm.rsaPssSha384 => tlsSignatureRsaPssSha384,
      PqX509Algorithm.rsaPssSha512 => tlsSignatureRsaPssSha512,
      _ => null,
    };
    if (scheme == null) {
      throw ArgumentError('${leaf.algorithm} is not a TLS CertificateVerify');
    }
    final raw = switch (leafKey) {
      final PqX509MlDsaKey key => Uint8List.fromList(key.raw),
      final PqX509EcdsaP256Key key => Uint8List.fromList(key.uncompressed),
      final PqX509EcdsaP384Key key => Uint8List.fromList(key.uncompressed),
      final PqX509Ed25519Key key => Uint8List.fromList(key.raw),
      final PqX509RsaKey key => Uint8List.fromList(key.modulus),
    };
    return PqTlsServerIdentity(
      publicKey: raw,
      secretKey: Uint8List(0),
      chain: copies,
      signContent: sign,
      certificateMessage: encodeX509Certificate(copies),
      leafScheme: scheme,
    );
  }

  String get publicKeyPem => encodeMlDsaPublicKeyPem(publicKey);

  String get privateKeyPem => encodeMlDsaPrivateKeyPem(secretKey);
}

bool _leafKeyEquals(PqX509PublicKey parsed, PqX509PublicKey given) {
  if (parsed is PqX509RsaKey && given is PqX509RsaKey) {
    return _sameKey(parsed.modulus, given.modulus) &&
        _sameKey(parsed.exponent, given.exponent);
  }
  final a = switch (parsed) {
    final PqX509MlDsaKey key => key.raw,
    final PqX509EcdsaP256Key key => key.uncompressed,
    final PqX509EcdsaP384Key key => key.uncompressed,
    final PqX509Ed25519Key key => key.raw,
    final PqX509RsaKey key => key.modulus,
  };
  final b = switch (given) {
    final PqX509MlDsaKey key => key.raw,
    final PqX509EcdsaP256Key key => key.uncompressed,
    final PqX509EcdsaP384Key key => key.uncompressed,
    final PqX509Ed25519Key key => key.raw,
    final PqX509RsaKey key => key.modulus,
  };
  return _sameKey(a, b);
}

bool _sameKey(Uint8List a, Uint8List b) =>
    a.length == b.length && PqBytes.constantTimeEquals(a, b);

bool _dnsName(PqX509Certificate leaf, String name) {
  final host = name.toLowerCase();
  for (final san in leaf.subjectAltNames) {
    if (san is PqX509DnsName && san.ascii.toLowerCase() == host) return true;
  }
  return false;
}

/// TLS 1.3 server with RFC 10024 hybrid key exchange.
final class PqTlsServer {
  PqTlsServer({
    PqTransportCrypto? crypto,
    this.group = HybridGroup.x25519MlKem768,
    PqTlsServerIdentity? identity,
    List<String>? alpnProtocols,
    this.quic = false,
    this.ech,
    this.earlyData,
    this.quicTransportParameters,
  }) : crypto = crypto ?? const PqTransportCrypto(),
       identity =
           identity ??
           PqTlsServerIdentity.generate(crypto ?? const PqTransportCrypto()),
       alpnProtocols = alpnProtocols ?? const [httpAlpnH1];

  final PqTransportCrypto crypto;
  final HybridGroup group;
  final PqTlsServerIdentity identity;
  final List<String> alpnProtocols;

  /// RFC 9001: handshake messages without the TLS record layer.
  final bool quic;

  /// When set, a ClientHello that does not open under this key is refused.
  /// The outer hello is not resumed.
  final EchServerConfig? ech;

  /// Single-use 0-RTT tickets. Null rejects every resumption.
  final QuicEarlyDataStore? earlyData;

  /// Local transport parameters, sent in EncryptedExtensions.
  Uint8List? quicTransportParameters;

  /// Client's transport parameters, from ClientHello.
  Uint8List? peerQuicTransportParameters;

  Uint8List? earlyTrafficSecret;
  bool earlyDataAccepted = false;

  final StateMachine<TlsState, TlsEvent> machine = tlsServerMachine();
  final Transcript transcript = Transcript();
  late final TlsKeySchedule schedule = TlsKeySchedule(crypto);
  TlsRecordLayer? records;
  Uint8List? _hybridSs;
  Uint8List? _hrrCookie;
  TlsCipherSuite _suite = TlsCipherSuite.aes256GcmSha384;
  var helloRetryCount = 0;
  String? selectedAlpn;
  var _pskSelected = false;

  /// Group this server put in ServerHello. Null until that choice is made.
  TlsNamedGroup? negotiatedGroup;

  /// server_name from the hello that was actually accepted.
  /// Under ECH this is the inner name, never [EchServerConfig.config]'s public name.
  String? acceptedServerName;
  Uint8List _pendingHandshake = Uint8List(0);

  TlsState get state => machine.currentState;
  bool get isComplete => machine.isIn(TlsState.handshakeCompleted);
  TlsCipherSuite get cipherSuite => _suite;

  Future<Result<List<Uint8List>, PqTransportError>> ingest(
    Uint8List recordBytes,
  ) async {
    if (!quic &&
        recordBytes.isNotEmpty &&
        recordBytes[0] == tlsContentChangeCipherSpec) {
      final ignored = ignoreCompatibleChangeCipherSpec(recordBytes);
      if (ignored.isFailure) {
        driveTls(machine, TlsEvent.fatal);
        return Result.failure(ignored.errorOrNull!);
      }
      return const Result.success([]);
    }
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
    final compatible = crypto.requireGroup(group);
    if (compatible.isFailure) return Result.failure(compatible.errorOrNull!);
    final rec = unwrapHandshake(recordBytes, quic: quic);
    if (rec.isFailure) return Result.failure(rec.errorOrNull!);
    final chunk = rec.valueOrNull!;
    _pendingHandshake = _pendingHandshake.isEmpty
        ? chunk
        : concatBytes([_pendingHandshake, chunk]);
    if (_pendingHandshake.length > tlsHandshakeReassemblyMaxBytes) {
      return _fail('handshake too large');
    }
    final n = handshakeWireLength(_pendingHandshake);
    if (n < 0 || _pendingHandshake.length < n) {
      return const Result.success([]);
    }
    if (_pendingHandshake.length != n) {
      return _fail('trailing client hello');
    }
    final helloBytes = _pendingHandshake;
    _pendingHandshake = Uint8List(0);
    final opened = await _openEch(helloBytes);
    if (opened.isFailure) return Result.failure(opened.errorOrNull!);
    final acceptedHello = opened.valueOrNull!;
    final ch = ClientHello.decode(acceptedHello);
    if (ch.isFailure) return Result.failure(ch.errorOrNull!);
    final hello = ch.valueOrNull!;
    peerQuicTransportParameters = hello.quicTransportParameters;
    if (_hrrCookie != null) {
      if (!hello.cipherSuites.contains(_suite.codepoint)) {
        return _fail('cipher dropped after hrr');
      }
      return _onSecondClientHello(hello, acceptedHello);
    }
    final selected = TlsCipherSuite.select(hello.cipherSuites);
    if (selected == null) {
      return _fail('no mutually supported cipher');
    }
    _bindSuite(selected);
    final chosen = _selectGroup(hello);
    if (chosen == null) {
      if (hello.offeredGroupCodepoints.contains(group.codepoint)) {
        return _emitHelloRetry(hello, acceptedHello);
      }
      return _fail('group mismatch');
    }
    return _completeClientHello(hello, acceptedHello, chosen);
  }

  Future<Result<Uint8List, PqTransportError>> _openEch(
    Uint8List helloBytes,
  ) async {
    final key = ech;
    if (key == null) return Result.success(helloBytes);
    final opened = await openEchOuter(
      crypto: crypto,
      server: key,
      outerHandshake: helloBytes,
    );
    if (opened.isFailure) {
      _certificateFailure(opened.errorOrNull!);
      return Result.failure(opened.errorOrNull!);
    }
    return opened;
  }

  Future<Result<List<Uint8List>, PqTransportError>> _onSecondClientHello(
    ClientHello hello,
    Uint8List helloBytes,
  ) async {
    final expected = _hrrCookie!;
    final got = hello.cookie;
    if (got == null ||
        got.length != expected.length ||
        !PqBytes.constantTimeEquals(got, expected)) {
      return _fail('cookie mismatch');
    }
    if (_shareFor(hello, TlsNamedGroup.fromHybrid(group)) == null) {
      return _fail('second hello retry');
    }
    return _completeClientHello(
      hello,
      helloBytes,
      TlsNamedGroup.fromHybrid(group),
    );
  }

  Result<List<Uint8List>, PqTransportError> _emitHelloRetry(
    ClientHello hello,
    Uint8List helloBytes,
  ) {
    if (helloRetryCount >= tlsMaxHelloRetry) {
      return _fail('second hello retry');
    }
    if (!hello.offeredGroupCodepoints.contains(group.codepoint)) {
      return _fail('group mismatch');
    }
    final cookie = crypto.randomBytes(tlsCookieBytes);
    _hrrCookie = cookie;
    helloRetryCount++;
    final hrr = ServerHello.helloRetryRequest(
      selectedGroup: TlsNamedGroup.fromHybrid(group),
      cookie: cookie,
      legacySessionId: hello.legacySessionId,
      cipherSuite: _suite.codepoint,
    );
    final hrrBytes = hrr.encode();
    rewriteTranscriptForHelloRetry(
      transcript: transcript,
      clientHello1: helloBytes,
      helloRetryRequest: hrrBytes,
      hash: schedule.transcriptHash,
    );
    return Result.success([wrapHandshake(hrrBytes, quic: quic)]);
  }

  Result<void, PqTransportError> _acceptPsk(
    ClientHello hello,
    Uint8List helloBytes,
  ) {
    _pskSelected = false;
    earlyDataAccepted = false;
    earlyTrafficSecret = null;
    if (hello.pskIdentity == null) {
      if (hello.earlyData) {
        return Result.failure(
          PqTransportError.illegalParameter(PqLengthLabel.tlsExtension, 0, 1),
        );
      }
      return const Result.success(null);
    }
    if (ech != null) {
      return Result.failure(PqTransportError.unsupported('0-rtt with ech'));
    }
    final store = earlyData;
    final binder = hello.pskBinder;
    if (store == null || binder == null) return const Result.success(null);
    final ticket = store.find(hello.pskIdentity!);
    if (ticket == null || ticket.cipherSuite != _suite.codepoint) {
      return const Result.success(null);
    }
    schedule.usePsk(ticket.psk);
    final truncated = truncatePskBinders(helloBytes, binder.length);
    final binderKey = schedule.resumptionBinderKey();
    final expected = schedule.binderVerifyData(
      binderKey,
      schedule.transcriptHash(truncated),
    );
    zeroize(binderKey);
    if (!PqBytes.constantTimeEquals(expected, binder)) {
      schedule.clearPsk();
      store.take(hello.pskIdentity!);
      return Result.failure(PqTransportError.decryptError('psk binder'));
    }
    store.take(hello.pskIdentity!);
    _pskSelected = true;
    if (hello.earlyData) {
      earlyDataAccepted = true;
      earlyTrafficSecret = schedule.clientEarlyTraffic(
        schedule.transcriptHash(helloBytes),
      );
    }
    return const Result.success(null);
  }

  Future<Result<List<Uint8List>, PqTransportError>> _completeClientHello(
    ClientHello hello,
    Uint8List helloBytes,
    TlsNamedGroup selected,
  ) async {
    final driven = driveTls(machine, TlsEvent.receiveClientHello);
    if (driven.isFailure) return Result.failure(driven.errorOrNull!);
    final psk = _acceptPsk(hello, helloBytes);
    if (psk.isFailure) return Result.failure(psk.errorOrNull!);
    transcript.add(helloBytes);
    final clientShare = _shareFor(hello, selected);
    if (clientShare == null) return _fail('group mismatch');
    negotiatedGroup = selected;
    acceptedServerName = hello.serverName;
    final accepted = await acceptTlsClientShare(crypto, selected, clientShare);
    if (accepted.isFailure) {
      final error = accepted.errorOrNull!;
      if (error.code == PqTransportErrorCode.illegalParameter) {
        driveTls(machine, TlsEvent.fatal);
      }
      return Result.failure(error);
    }
    _hybridSs = accepted.valueOrNull!.secret;
    final selectedIdentity = _selectCertificate(hello);
    if (selectedIdentity.isFailure) {
      return _certificateFailure(selectedIdentity.errorOrNull!);
    }
    final sendX509 = selectedIdentity.valueOrNull!.sendX509;
    final echoType = selectedIdentity.valueOrNull!.echoType;
    final sh = ServerHello(
      random: crypto.randomBytes(handshakeRandomBytes),
      group: selected,
      share: accepted.valueOrNull!.serverShare,
      legacySessionId: hello.legacySessionId,
      cipherSuite: _suite.codepoint,
      selectedPsk: _pskSelected,
    );
    final shBytes = ech == null
        ? sh.encode()
        : echStampAcceptConfirmation(
            crypto: crypto,
            schedule: schedule,
            innerHandshake: helloBytes,
            innerRandom: hello.random,
            serverHello: sh.encode(),
          );
    transcript.add(shBytes);
    schedule.deriveHandshake(
      hybridSharedSecret: _hybridSs!,
      handshakeTranscriptHash: transcript.snapshot(),
    );
    records = TlsRecordLayer(crypto, schedule);
    final alpn = selectAlpn(
      offered: hello.alpnProtocols,
      supported: alpnProtocols,
    );
    if (alpn.isFailure) return Result.failure(alpn.errorOrNull!);
    selectedAlpn = alpn.valueOrNull;
    final ee = encodeEncryptedExtensions(
      serverCertificateType: echoType,
      alpnProtocol: selectedAlpn,
      earlyData: earlyDataAccepted,
      quicTransportParameters: quic ? quicTransportParameters : null,
    );
    transcript.add(ee);
    final cert = sendX509
        ? identity.certificateMessage!
        : encodeCertificate(identity.publicKey);
    transcript.add(cert);
    final toSign = tls13ServerCertVerifyContent(transcript.snapshot());
    final signed = identity.signContent != null
        ? identity.signContent!(toSign)
        : crypto.mlDsaSign(secretKey: identity.secretKey, message: toSign);
    final scheme = sendX509 ? identity.leafScheme : tlsSignatureMldsa65;
    final sig = wireCertificateVerifySignature(scheme, signed);
    final cv = sendX509
        ? encodeCertVerifyScheme(scheme, sig)
        : encodeCertVerify(sig);
    transcript.add(cv);
    final fin = encodeFinished(
      schedule.finishedMac(schedule.serverFinishedKey, transcript.snapshot()),
    );
    transcript.add(fin);
    final rest = concatBytes([ee, cert, cv, fin]);
    if (quic) {
      return Result.success([shBytes, rest]);
    }
    final protected = records!.protectWith(
      trafficSecret: schedule.serverHandshakeTraffic,
      iv: schedule.serverHandshakeIv,
      inner: TlsRecord(type: tlsContentHandshake, payload: rest),
      epoch: TlsRecordEpoch.handshake,
    );
    return Result.success([wrapHandshake(shBytes, quic: false), protected]);
  }

  Future<Result<List<Uint8List>, PqTransportError>> _onClientFinished(
    Uint8List recordBytes,
  ) async {
    late final Uint8List finBytes;
    if (quic) {
      finBytes = recordBytes;
    } else {
      final layer = records;
      if (layer == null) return _fail('no records');
      final inner = layer.openWith(
        trafficSecret: schedule.clientHandshakeTraffic,
        iv: schedule.clientHandshakeIv,
        wire: recordBytes,
        epoch: TlsRecordEpoch.handshake,
      );
      if (inner.isFailure) return Result.failure(inner.errorOrNull!);
      finBytes = inner.valueOrNull!.payload;
    }
    final fin = decodeFinished(finBytes, verifyDataLength: schedule.hashLen);
    if (fin.isFailure) return Result.failure(fin.errorOrNull!);
    final expected = schedule.finishedMac(
      schedule.clientFinishedKey,
      transcript.snapshot(),
    );
    if (!PqBytes.constantTimeEquals(expected, fin.valueOrNull!)) {
      return _fail('client finished mac');
    }
    // RFC 8446 §7.1. Application keys do not cover client Finished.
    schedule.deriveApplication(
      hybridSharedSecret: _hybridSs!,
      applicationTranscriptHash: transcript.snapshot(),
    );
    transcript.add(finBytes);
    final driven = driveTls(machine, TlsEvent.receiveFinished);
    if (driven.isFailure) return Result.failure(driven.errorOrNull!);
    return const Result.success([]);
  }

  Uint8List? _shareFor(ClientHello hello, TlsNamedGroup want) {
    for (final entry in hello.offeredKeyShares) {
      if (entry.group == want) return entry.share;
    }
    return null;
  }

  /// Hybrid first, and only when the peer sent that share. A peer that
  /// advertises the hybrid without a share gets HelloRetryRequest, not a
  /// silent drop to X25519. A peer that never advertised it gets the first
  /// fallback share it did send.
  TlsNamedGroup? _selectGroup(ClientHello hello) {
    final preferred = TlsNamedGroup.fromHybrid(group);
    if (_shareFor(hello, preferred) != null) return preferred;
    if (hello.offeredGroupCodepoints.contains(preferred.codepoint)) {
      return null;
    }
    for (final fallback in tlsClassicalFallbackGroups) {
      if (_shareFor(hello, fallback) != null) return fallback;
    }
    return null;
  }

  Result<({bool sendX509, int? echoType}), PqTransportError> _selectCertificate(
    ClientHello hello,
  ) {
    final sendX509 = identity.chain.isNotEmpty && hello.offersX509;
    if (!sendX509 && !hello.offersRawPublicKey) {
      return Result.failure(
        PqTransportError.unsupportedCertificate('no x509 identity'),
      );
    }
    if (!sendX509 &&
        identity.chain.isNotEmpty &&
        identity.leafScheme != tlsSignatureMldsa65 &&
        identity.leafScheme != tlsSignatureMldsa87) {
      return Result.failure(
        PqTransportError.unsupportedCertificate('raw public key'),
      );
    }
    final requiredScheme = sendX509 || identity.chain.isNotEmpty
        ? identity.leafScheme
        : tlsSignatureMldsa65;
    if (!hello.signatureSchemes.contains(requiredScheme)) {
      return Result.failure(
        PqTransportError.unsupportedCertificate(
          'signature_scheme $requiredScheme',
        ),
      );
    }
    final echoType = hello.certificateTypes == null
        ? null
        : (sendX509 ? tlsCertTypeX509 : tlsCertTypeRawPublicKey);
    return Result.success((sendX509: sendX509, echoType: echoType));
  }

  PqTransportError? _wireCertificateError;

  Result<List<Uint8List>, PqTransportError> _certificateFailure(
    PqTransportError error,
  ) {
    _wireCertificateError = error;
    driveTls(machine, TlsEvent.fatal);
    return Result.failure(error);
  }

  /// Fatal Alert for a certificate policy failure. Plaintext when the
  /// ServerHello was not sent. Null on QUIC and for older failures.
  Uint8List? certificateAlert(PqTransportError error) {
    if (!identical(error, _wireCertificateError)) return null;
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
      trafficSecret: schedule.serverHandshakeTraffic,
      iv: schedule.serverHandshakeIv,
      inner: TlsRecord(type: tlsContentAlert, payload: payload),
      epoch: TlsRecordEpoch.handshake,
    );
  }

  Result<List<Uint8List>, PqTransportError> _fail(String why) {
    _pendingHandshake = Uint8List(0);
    driveTls(machine, TlsEvent.fatal);
    return Result.failure(PqTransportError.handshakeFailure(why));
  }

  void _bindSuite(TlsCipherSuite suite) {
    _suite = suite;
    schedule.suite = suite;
    transcript.hashKind = suite.usesSha384
        ? TranscriptHashKind.sha384
        : TranscriptHashKind.sha256;
  }

  Uint8List exporter(String label, Uint8List context, int length) =>
      schedule.exporter(label, context, length);

  Future<void> close() async {
    driveTls(machine, TlsEvent.close);
    zeroize(_hybridSs);
  }
}
