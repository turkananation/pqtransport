import 'dart:async';
import 'dart:typed_data';

import 'package:swissarmyknife/swissarmyknife.dart';

import '../core/crypto.dart';
import '../core/errors.dart';
import '../core/hybrid.dart';
import '../core/lengths.dart';
import '../socket/pq_transport_socket.dart';
import 'pq_tls_client.dart';
import 'pq_tls_server.dart';
import 'certificate_policy.dart';
import 'handshake.dart';
import 'record.dart';
import 'tls_state.dart';

/// Byte-channel TLS wrapper. Caller supplies any [PqTransportSocket].
final class PqTlsSocket {
  PqTlsSocket._(this._inner, this._client, this._server);

  factory PqTlsSocket.client(
    PqTransportSocket inner, {
    PqTransportCrypto? crypto,
    HybridGroup group = HybridGroup.x25519MlKem768,
    List<HybridGroup>? offeredGroups,
    List<int>? offeredCipherSuites,
    List<String>? alpnProtocols,
    bool allowUnauthenticated = false,
    List<TlsCertificateType> certificateTypes = const [
      TlsCertificateType.rawPublicKey,
    ],
    List<Uint8List> trustAnchors = const [],
    Uint8List? trustedSpki,
    PqCertificateHook? verifyPeer,
    DateTime Function()? now,
    String? serverName,
  }) => PqTlsSocket._(
    inner,
    PqTlsClient(
      crypto: crypto,
      group: group,
      offeredGroups: offeredGroups,
      offeredCipherSuites: offeredCipherSuites,
      alpnProtocols: alpnProtocols,
      allowUnauthenticated: allowUnauthenticated,
      certificateTypes: certificateTypes,
      trustAnchors: trustAnchors,
      trustedSpki: trustedSpki,
      verifyPeer: verifyPeer,
      now: now,
      serverName: serverName,
    ),
    null,
  );

  factory PqTlsSocket.server(
    PqTransportSocket inner, {
    PqTransportCrypto? crypto,
    PqTlsServerIdentity? identity,
    HybridGroup group = HybridGroup.x25519MlKem768,
    List<String>? alpnProtocols,
  }) => PqTlsSocket._(
    inner,
    null,
    PqTlsServer(
      crypto: crypto,
      identity: identity,
      group: group,
      alpnProtocols: alpnProtocols,
    ),
  );

  final PqTransportSocket _inner;
  final PqTlsClient? _client;
  final PqTlsServer? _server;
  final StreamController<Uint8List> _app = StreamController.broadcast();
  StreamSubscription<Uint8List>? _sub;
  Future<void> _inbox = Future<void>.value();
  Completer<Result<void, PqTransportError>>? _handshake;
  final List<int> _recordBytes = [];
  var _recordDead = false;

  Stream<Uint8List> get applicationData => _app.stream;

  TlsState get state =>
      _client?.state ?? _server?.state ?? TlsState.uninitialized;

  bool get isComplete => _client?.isComplete ?? _server?.isComplete ?? false;

  /// True only when the client checked CertificateVerify.
  ///
  /// A server socket is false: this stack does not authenticate the
  /// client. [allowUnauthenticated] on [PqTlsSocket.client] leaves this
  /// false after a completed handshake. That flag is not authentication.
  bool get peerAuthenticated => _client?.peerAuthenticated ?? false;

  /// RFC 7301 protocol selected in EncryptedExtensions. Null if omitted.
  String? get alpn => _client?.selectedAlpn ?? _server?.selectedAlpn;

  Future<Result<void, PqTransportError>> handshake({
    Duration timeout = const Duration(seconds: 20),
  }) async {
    final done = Completer<Result<void, PqTransportError>>();
    _handshake = done;
    _sub ??= _inner.incoming.listen((bytes) {
      _inbox = _inbox.then((_) => _onBytes(bytes));
    });
    final c = _client;
    if (c != null) {
      final ch = await c.startHandshake();
      if (ch.isFailure) return Result.failure(ch.errorOrNull!);
      final sent = await _inner.send(ch.valueOrNull!);
      if (sent.isFailure) return sent;
    }
    return done.future.timeout(
      timeout,
      onTimeout: () => Result.failure(
        PqTransportError.handshakeFailure('handshake timeout'),
      ),
    );
  }

  /// RFC 8446 §5.1. TCP delivers an undifferentiated byte stream, so a
  /// read is not a record. Bytes are held until `5 + length` arrive.
  /// [length] above 2^14+256 is a decode error.
  Future<void> _onBytes(Uint8List bytes) async {
    if (_recordDead) return;
    _recordBytes.addAll(bytes);
    while (!_recordDead) {
      if (_recordBytes.length < tlsRecordHeaderBytes) return;
      final type = _recordBytes[0];
      final version = (_recordBytes[1] << 8) | _recordBytes[2];
      final length = (_recordBytes[3] << 8) | _recordBytes[4];
      if (version != tlsLegacyVersion ||
          length > tlsMaxCiphertextBytes ||
          !_tlsContentType(type)) {
        _recordDead = true;
        _recordBytes.clear();
        _finishHandshake(
          Result.failure(PqTransportError.decodeFailure('tls record')),
        );
        return;
      }
      final total = tlsRecordHeaderBytes + length;
      if (_recordBytes.length < total) return;
      final record = Uint8List.fromList(_recordBytes.sublist(0, total));
      _recordBytes.removeRange(0, total);
      await _onRecord(record);
    }
  }

  Future<void> _onRecord(Uint8List bytes) async {
    final c = _client;
    final s = _server;
    if (c != null && !c.isComplete) {
      final out = await c.ingest(bytes);
      if (out.isFailure) {
        final error = out.errorOrNull!;
        final alert = c.certificateAlert(error);
        if (alert != null) await _inner.send(alert);
        _recordDead = true;
        _finishHandshake(Result.failure(error));
        return;
      }
      for (final rec in out.valueOrNull!) {
        final sent = await _inner.send(rec);
        if (sent.isFailure) {
          _recordDead = true;
          _finishHandshake(sent);
          return;
        }
      }
      if (c.isComplete) {
        _finishHandshake(const Result.success(null));
      }
      return;
    }
    if (s != null && !s.isComplete) {
      final out = await s.ingest(bytes);
      if (out.isFailure) {
        final error = out.errorOrNull!;
        final alert = s.certificateAlert(error);
        if (alert != null) await _inner.send(alert);
        _recordDead = true;
        _finishHandshake(Result.failure(error));
        return;
      }
      for (final rec in out.valueOrNull!) {
        final sent = await _inner.send(rec);
        if (sent.isFailure) {
          _recordDead = true;
          _finishHandshake(sent);
          return;
        }
      }
      if (s.isComplete) {
        _finishHandshake(const Result.success(null));
      }
      return;
    }
    await _openApplication(bytes);
  }

  Future<void> _openApplication(Uint8List bytes) async {
    final c = _client;
    final s = _server;
    final schedule = c?.schedule ?? s?.schedule;
    final records = c?.records ?? s?.records;
    if (schedule == null || records == null) return;
    final isClient = c != null;
    final inner = records.openWith(
      trafficSecret: isClient
          ? schedule.serverApplicationTraffic
          : schedule.clientApplicationTraffic,
      iv: isClient
          ? schedule.serverApplicationIv
          : schedule.clientApplicationIv,
      wire: bytes,
      epoch: TlsRecordEpoch.application,
    );
    if (inner.isFailure) return;
    if (inner.valueOrNull!.type == tlsContentApplicationData) {
      _app.add(inner.valueOrNull!.payload);
    }
  }

  void _finishHandshake(Result<void, PqTransportError> result) {
    final done = _handshake;
    if (done != null && !done.isCompleted) {
      done.complete(result);
    }
  }

  Future<Result<void, PqTransportError>> send(Uint8List plaintext) async {
    final c = _client;
    final s = _server;
    final schedule = c?.schedule ?? s?.schedule;
    final records = c?.records ?? s?.records;
    if (schedule == null || records == null || !isComplete) {
      return Result.failure(PqTransportError.handshakeFailure('not complete'));
    }
    final isClient = c != null;
    final sealed = records.protectWith(
      trafficSecret: isClient
          ? schedule.clientApplicationTraffic
          : schedule.serverApplicationTraffic,
      iv: isClient
          ? schedule.clientApplicationIv
          : schedule.serverApplicationIv,
      inner: TlsRecord(type: tlsContentApplicationData, payload: plaintext),
      epoch: TlsRecordEpoch.application,
    );
    return _inner.send(sealed);
  }

  Uint8List exporter(String label, Uint8List context, int length) {
    final c = _client;
    final s = _server;
    if (c != null) return c.exporter(label, context, length);
    if (s != null) return s.exporter(label, context, length);
    return Uint8List(length);
  }

  Future<void> close() async {
    await _sub?.cancel();
    await _client?.close();
    await _server?.close();
    await _app.close();
    await _inner.close();
  }
}

bool _tlsContentType(int type) =>
    type == tlsContentChangeCipherSpec ||
    type == tlsContentAlert ||
    type == tlsContentHandshake ||
    type == tlsContentApplicationData;
