import 'dart:typed_data';

import 'package:swissarmyknife/swissarmyknife.dart';

import '../core/bytes.dart';
import '../core/crypto.dart';
import '../core/errors.dart';
import '../core/hybrid.dart';
import '../core/lengths.dart';
import '../tls/key_schedule.dart';
import '../tls/pq_tls_client.dart';
import '../tls/pq_tls_server.dart';
import '../tls/record.dart';
import '../tls/tls_state.dart';
import 'packet.dart';

/// Reassembles RFC 9000 CRYPTO frames by offset (TLS handshake stream).
final class QuicCryptoStream {
  final Map<int, Uint8List> _chunks = {};
  var _read = 0;

  void add(QuicCryptoFrame frame) {
    _chunks[frame.offset] = Uint8List.fromList(frame.data);
  }

  /// Contiguous bytes from the current read cursor, or empty if a gap.
  Uint8List takeAvailable() {
    final out = BytesBuilder(copy: false);
    while (true) {
      final chunk = _chunks.remove(_read);
      if (chunk == null) break;
      out.add(chunk);
      _read += chunk.length;
    }
    return out.takeBytes();
  }
}

/// RFC 9001: TLS handshake messages in CRYPTO frames, no TLS record layer.
final class QuicTlsHandshake {
  QuicTlsHandshake.client({
    PqTransportCrypto? crypto,
    HybridGroup group = HybridGroup.x25519MlKem768,
    List<String>? alpnProtocols,
  }) : _client = PqTlsClient(
         crypto: crypto,
         group: group,
         quic: true,
         alpnProtocols: alpnProtocols,
       ),
       _server = null;

  QuicTlsHandshake.server({
    PqTransportCrypto? crypto,
    HybridGroup group = HybridGroup.x25519MlKem768,
    PqTlsServerIdentity? identity,
    List<String>? alpnProtocols,
  }) : _client = null,
       _server = PqTlsServer(
         crypto: crypto,
         group: group,
         identity: identity,
         quic: true,
         alpnProtocols: alpnProtocols,
       );

  final PqTlsClient? _client;
  final PqTlsServer? _server;
  final QuicCryptoStream inbound = QuicCryptoStream();
  var _write = 0;
  Uint8List _partial = Uint8List(0);

  TlsKeySchedule get schedule => _client?.schedule ?? _server!.schedule;

  bool get isComplete =>
      (_client?.isComplete ?? false) || (_server?.isComplete ?? false);

  String? get alpn => _client?.selectedAlpn ?? _server?.selectedAlpn;

  Uint8List exporterBytes(String label, Uint8List context, int length) {
    final c = _client;
    if (c != null) return c.exporter(label, context, length);
    return _server!.exporter(label, context, length);
  }

  Future<Result<List<QuicCryptoFrame>, PqTransportError>> start() async {
    final client = _client;
    if (client == null) {
      return Result.failure(
        PqTransportError.unexpectedMessage('server does not start'),
      );
    }
    final ch = await client.startHandshake();
    if (ch.isFailure) return Result.failure(ch.errorOrNull!);
    return Result.success(_frames(ch.valueOrNull!));
  }

  Future<Result<List<QuicCryptoFrame>, PqTransportError>> ingest(
    QuicCryptoFrame frame,
  ) async {
    inbound.add(frame);
    final available = inbound.takeAvailable();
    if (available.isNotEmpty) {
      _partial = concatBytes([_partial, available]);
    }
    final messages = _peelHandshakeMessages();
    if (messages.isEmpty) return const Result.success([]);

    final out = <QuicCryptoFrame>[];
    var i = 0;
    if (_client != null && _client.state == TlsState.clientHelloSent) {
      final r = await _client.ingest(messages[i++]);
      if (r.isFailure) return Result.failure(r.errorOrNull!);
      for (final msg in r.valueOrNull!) {
        out.addAll(_frames(msg));
      }
    } else if (_server != null && _server.state == TlsState.waitClientHello) {
      final r = await _server.ingest(messages[i++]);
      if (r.isFailure) return Result.failure(r.errorOrNull!);
      for (final msg in r.valueOrNull!) {
        out.addAll(_frames(msg));
      }
    }
    if (i < messages.length) {
      final rest = messages.length - i == 1
          ? messages[i]
          : concatBytes(messages.sublist(i));
      final flights = _client != null
          ? await _client.ingest(rest)
          : await _server!.ingest(rest);
      if (flights.isFailure) return Result.failure(flights.errorOrNull!);
      for (final msg in flights.valueOrNull!) {
        out.addAll(_frames(msg));
      }
    }
    return Result.success(out);
  }

  List<Uint8List> _peelHandshakeMessages() {
    final messages = <Uint8List>[];
    var off = 0;
    while (true) {
      if (_partial.length - off < tlsHandshakeHeaderBytes) break;
      final n = handshakeWireLength(slice(_partial, off, _partial.length));
      if (n < tlsHandshakeHeaderBytes || _partial.length - off < n) break;
      messages.add(slice(_partial, off, off + n));
      off += n;
    }
    if (off > 0) {
      _partial = off == _partial.length
          ? Uint8List(0)
          : slice(_partial, off, _partial.length);
    }
    return messages;
  }

  List<QuicCryptoFrame> _frames(Uint8List handshake) {
    if (handshake.isEmpty) return const [];
    final frame = QuicCryptoFrame(offset: _write, data: handshake);
    _write += handshake.length;
    return [frame];
  }
}
