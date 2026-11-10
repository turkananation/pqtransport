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
import 'certificate_policy.dart';
import 'resumption.dart';
import 'cipher_suite.dart';
import 'ech.dart';
import 'handshake.dart';
import 'key_schedule.dart';
import 'key_share.dart';
import 'machines.dart';
import 'named_group.dart';
import 'record.dart';
import 'tls_state.dart';

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

    /// Key shares to send instead of the preferred hybrid plus X25519.
    ///
    /// Null is the default: one share for [group], then an X25519 share.
    /// [supported_groups] still lists [offeredGroups] and the classical
    /// and pure groups, hybrid first. A non-null list is the whole offer.
    /// The preferred hybrid is not added back.
    this.onlyShares,

    /// RFC 9849 configuration. When set, the wire hello is ClientHelloOuter
    /// and rejection fails closed. There is no cleartext retry.
    this.ech,

    /// RFC 8446 resumption ticket. QUIC only. Sends early_data and a PSK.
    this.ticket,

    /// RFC 9001 transport parameters. Sent when QUIC and non-null.
    this.quicTransportParameters,
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

  /// Replaces the default hybrid-plus-X25519 key shares. See the constructor.
  final List<TlsNamedGroup>? onlyShares;

  /// Null means this client does not offer ECH.
  final EchConfig? ech;

  /// Set only for a QUIC resumption. Null is a full handshake.
  final QuicResumptionTicket? ticket;

  /// Local `quic_transport_parameters` extension body.
  final Uint8List? quicTransportParameters;

  /// Peer's parameters, from EncryptedExtensions. Null until then.
  Uint8List? peerQuicTransportParameters;

  Uint8List? earlyTrafficSecret;
  bool earlyDataAccepted = false;

  /// RFC 9001: handshake messages without the TLS record layer.
  final bool quic;

  final StateMachine<TlsState, TlsEvent> machine = tlsClientMachine();
  final Transcript transcript = Transcript();
  late final TlsKeySchedule schedule = TlsKeySchedule(crypto);
  TlsRecordLayer? records;

  Uint8List? _hybridSs;
  Uint8List? _clientRandom;
  List<TlsLocalShare> _localShares = [];
  List<int> _advertised = const [];
  TlsCipherSuite _suite = TlsCipherSuite.aes256GcmSha384;
  var helloRetryCount = 0;
  String? selectedAlpn;

  /// ClientHelloInner, kept for the accept_confirmation transcript.
  /// The bytes on the wire are ClientHelloOuter when this is set.
  Uint8List? _echInnerHello;

  /// Group in the peer's ServerHello. Null until that message is accepted.
  TlsNamedGroup? negotiatedGroup;
  var _peerAuthenticated = false;
  Uint8List? _peerPublicKey;
  int? _certificateType;
  List<Uint8List>? _certificateEntries;

  /// Handshake bytes that did not finish a message. RFC 8446 §5.1
  /// permits one handshake message to span records, and several
  /// messages to share a record. The encrypted flight uses this buffer.
  /// ServerHello is still cleartext, so it uses [_pendingCleartext].
  Uint8List _pendingHandshake = Uint8List(0);
  Uint8List _pendingCleartext = Uint8List(0);

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
    final shares = _sharesToMint();
    if (shares.isEmpty) {
      return Result.failure(PqTransportError.unsupported('no key share'));
    }
    for (final group in shares) {
      final hybrid = group.asHybrid;
      if (hybrid == null) continue;
      final gate = crypto.requireGroup(hybrid);
      if (gate.isFailure) return Result.failure(gate.errorOrNull!);
    }
    final driven = driveTls(machine, TlsEvent.startHandshake);
    if (driven.isFailure) return Result.failure(driven.errorOrNull!);
    _clientRandom = crypto.randomBytes(handshakeRandomBytes);
    _advertised = _supportedCodes(shares);
    for (final group in shares) {
      final minted = await mintTlsClientShare(crypto, group);
      if (minted.isFailure) {
        wipeTlsShares(_localShares);
        driveTls(machine, TlsEvent.fatal);
        return Result.failure(minted.errorOrNull!);
      }
      _localShares.add(minted.valueOrNull!);
    }
    final hello = _clientHello();
    var encoded = hello.encode();
    final resumed = ticket;
    if (resumed != null) {
      if (!quic || ech != null) {
        driveTls(machine, TlsEvent.fatal);
        return Result.failure(PqTransportError.unsupported('quic 0-rtt'));
      }
      if (!offeredCipherSuites.contains(resumed.cipherSuite)) {
        driveTls(machine, TlsEvent.fatal);
        return Result.failure(
          PqTransportError.handshakeFailure('ticket cipher suite'),
        );
      }
      final built = buildEarlyClientHello(
        baseHello: encoded,
        schedule: schedule,
        ticket: resumed,
        now: now == null ? DateTime.now().toUtc() : now!(),
      );
      encoded = built.hello;
      earlyTrafficSecret = built.earlySecret;
    }
    if (ech == null) {
      transcript.add(encoded);
      return Result.success(wrapHandshake(encoded, quic: quic));
    }
    final outer = await sealEchOuter(
      crypto: crypto,
      config: ech!,
      innerHandshake: encoded,
      inner: hello,
    );
    if (outer.isFailure) {
      driveTls(machine, TlsEvent.fatal);
      return Result.failure(outer.errorOrNull!);
    }
    _echInnerHello = encoded;
    transcript.add(encoded);
    return Result.success(wrapHandshake(outer.valueOrNull!, quic: quic));
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
    if (!quic) {
      // OpenSSL -max_send_frag splits ServerHello. The ML-KEM share
      // does not fit in 512 octets, so the first record is a prefix.
      _pendingCleartext = _pendingCleartext.isEmpty
          ? shBytes
          : concatBytes([_pendingCleartext, shBytes]);
      if (_pendingCleartext.length > tlsHandshakeReassemblyMaxBytes) {
        return _fail('handshake too large');
      }
      final n = handshakeWireLength(_pendingCleartext);
      if (n < 0 || _pendingCleartext.length < n) {
        return const Result.success([]);
      }
      if (_pendingCleartext.length != n) {
        return _fail('trailing server hello');
      }
      shBytes = _pendingCleartext;
      _pendingCleartext = Uint8List(0);
    } else {
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
      if (_echInnerHello != null) {
        return _fatal(
          PqTransportError.echRequired('ech has no cleartext retry'),
        );
      }
      if (leftover.isNotEmpty) return _fail('trailing after hrr');
      return _ingestHelloRetry(sh.valueOrNull!, shBytes);
    }
    final bound = _bindSuite(sh.valueOrNull!.cipherSuite);
    if (bound.isFailure) return Result.failure(bound.errorOrNull!);
    final innerHello = _echInnerHello;
    if (innerHello != null) {
      final accepted = echAcceptConfirmationMatches(
        crypto: crypto,
        schedule: schedule,
        innerHandshake: innerHello,
        innerRandom: _clientRandom!,
        serverHello: shBytes,
      );
      if (!accepted) {
        return _fatal(PqTransportError.echRequired('server rejected ech'));
      }
    }
    TlsLocalShare? selected;
    for (final share in _localShares) {
      if (share.group == sh.valueOrNull!.group) selected = share;
    }
    if (selected == null) return _fail('group mismatch');
    negotiatedGroup = selected.group;
    final driven = driveTls(machine, TlsEvent.receiveServerHello);
    if (driven.isFailure) return Result.failure(driven.errorOrNull!);
    transcript.add(shBytes);
    final secret = await deriveTlsSharedSecret(
      crypto,
      selected,
      sh.valueOrNull!.share,
    );
    wipeTlsShares(_localShares);
    if (secret.isFailure) {
      driveTls(machine, TlsEvent.fatal);
      return Result.failure(secret.errorOrNull!);
    }
    _hybridSs = secret.valueOrNull!;
    final resumed = ticket;
    if (sh.valueOrNull!.selectedPsk) {
      if (resumed == null) return _fail('psk not offered');
      schedule.usePsk(resumed.psk);
    } else {
      schedule.clearPsk();
      earlyTrafficSecret = null;
    }
    schedule.deriveHandshake(
      hybridSharedSecret: _hybridSs!,
      handshakeTranscriptHash: transcript.snapshot(),
    );
    records = TlsRecordLayer(crypto, schedule);
    if (quic && leftover.isNotEmpty) {
      return await _ingestEncrypted(leftover);
    }
    return const Result.success([]);
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
        peerQuicTransportParameters = ee.valueOrNull!.quicTransportParameters;
        if (ee.valueOrNull!.earlyData) {
          if (ticket == null) return _fail('early_data not offered');
          earlyDataAccepted = true;
        }
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
        // RFC 8446 §7.1: application secrets are Hash(ClientHello..server
        // Finished). Client Finished is not in that hash.
        schedule.deriveApplication(
          hybridSharedSecret: _hybridSs!,
          applicationTranscriptHash: transcript.snapshot(),
        );
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
    if (_echInnerHello != null) {
      return _fatal(PqTransportError.echRequired('ech has no cleartext retry'));
    }
    if (!_advertised.contains(hrr.group.codepoint)) {
      return _fail('hrr group not offered');
    }
    final bound = _bindSuite(hrr.cipherSuite);
    if (bound.isFailure) return Result.failure(bound.errorOrNull!);
    final hybrid = hrr.group.asHybrid;
    if (hybrid != null) {
      final compatible = crypto.requireGroup(hybrid);
      if (compatible.isFailure) return Result.failure(compatible.errorOrNull!);
    }
    final cookie = hrr.cookie;
    final ch1 = transcript.bytes;
    rewriteTranscriptForHelloRetry(
      transcript: transcript,
      clientHello1: ch1,
      helloRetryRequest: hrrBytes,
      hash: schedule.transcriptHash,
    );
    wipeTlsShares(_localShares);
    _localShares = [];
    final share = await mintTlsClientShare(crypto, hrr.group);
    if (share.isFailure) {
      driveTls(machine, TlsEvent.fatal);
      return Result.failure(share.errorOrNull!);
    }
    _localShares = [share.valueOrNull!];
    final hello = _clientHello(cookie: cookie);
    final encoded = hello.encode();
    transcript.add(encoded);
    return Result.success([wrapHandshake(encoded, quic: quic)]);
  }

  ClientHello _clientHello({Uint8List? cookie}) {
    final shares = _localShares;
    return ClientHello(
      random: _clientRandom!,
      group: shares.first.group,
      share: shares.first.wire,
      keyShares: shares.length == 1
          ? null
          : [
              for (final entry in shares)
                (group: entry.group, share: entry.wire),
            ],
      cipherSuites: offeredCipherSuites,
      alpnProtocols: alpnProtocols,
      supportedGroups: _advertised,
      serverName: serverName ?? 'localhost',
      cookie: cookie,
      certificateTypes: certificateTypes,
      echInner: ech != null,
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
      quicTransportParameters: quic ? quicTransportParameters : null,
    );
  }

  List<TlsNamedGroup> _sharesToMint() {
    if (onlyShares != null) return onlyShares!;
    return [TlsNamedGroup.fromHybrid(group), TlsNamedGroup.x25519];
  }

  List<int> _supportedCodes(List<TlsNamedGroup> shares) {
    final out = <int>[];
    if (onlyShares == null) {
      for (final offered in offeredGroups) {
        final code = offered.codepoint;
        if (!out.contains(code)) out.add(code);
      }
    }
    for (final share in shares) {
      if (!out.contains(share.codepoint)) out.add(share.codepoint);
    }
    for (final fallback in tlsClassicalFallbackGroups) {
      if (!out.contains(fallback.codepoint)) out.add(fallback.codepoint);
    }
    return out;
  }

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
    _pendingCleartext = Uint8List(0);
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
    _pendingCleartext = Uint8List(0);
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
