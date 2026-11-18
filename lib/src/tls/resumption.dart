import 'dart:typed_data';

import 'package:swissarmyknife/swissarmyknife.dart';

import '../core/bytes.dart';
import '../core/crypto.dart';
import '../core/errors.dart';
import '../core/lengths.dart';
import '../core/zeroize.dart';
import 'handshake.dart';
import 'key_schedule.dart';
import 'record.dart';

/// RFC 8446 resumption ticket. The PSK is not on the wire.
final class QuicResumptionTicket {
  QuicResumptionTicket({
    required this.identity,
    required this.nonce,
    required this.psk,
    required this.ageAdd,
    required this.cipherSuite,
    required this.issuedAt,
    this.lifetimeSeconds = 86400,
    this.maxEarlyData = quicMaxDataDefault,
    this.maxEarlyStreamData = quicMaxStreamDataDefault,
    this.maxEarlyDatagram = 0,
    this.maxEarlyStreamsBidi = quicInitialMaxStreams,
    this.maxEarlyStreamsUni = quicInitialMaxStreams,
    this.allowEarlyData = true,
  });

  final Uint8List identity;
  final Uint8List nonce;
  final Uint8List psk;
  final int ageAdd;
  final int cipherSuite;
  final DateTime issuedAt;
  final int lifetimeSeconds;

  /// Server receive limits remembered for 0-RTT (RFC 9000 §7.4.1).
  final int maxEarlyData;
  final int maxEarlyStreamData;

  /// RFC 9221. Zero means the ticket did not remember a datagram limit,
  /// so 0-RTT DATAGRAM is refused.
  final int maxEarlyDatagram;

  /// RFC 9000 §18.2. `initial_max_streams_*` from the ticket.
  final int maxEarlyStreamsBidi;
  final int maxEarlyStreamsUni;

  /// False when this ticket was recovered from a stateless blob by a
  /// store that did not issue it. That store resumes, and it does not
  /// accept 0-RTT. Not an external PSK (RFC 9258).
  final bool allowEarlyData;

  int obfuscatedAge(DateTime now) {
    final age = now.toUtc().difference(issuedAt.toUtc()).inMilliseconds;
    final bounded = age < 0 ? 0 : age;
    return (bounded + ageAdd) & 0xffffffff;
  }
}

/// Single-use ticket store. A second take of the same identity fails.
///
/// [ticketKey] makes the identity an AES-256-GCM blob of the PSK and
/// the limits. A later store with the same key can resume after this
/// process is gone. 0-RTT is accepted only while the issuing store
/// still holds the identity. Not an external PSK (RFC 9258).
final class QuicEarlyDataStore {
  QuicEarlyDataStore({Uint8List? ticketKey}) : _ticketKey = ticketKey {
    if (ticketKey != null && ticketKey.length != 32) {
      throw ArgumentError.value(ticketKey.length, 'ticketKey', '32 bytes');
    }
  }

  final Map<String, QuicResumptionTicket> _live = {};
  final Uint8List? _ticketKey;
  static const _ticketAad = 'pqtransport-ticket-v1';

  static String _id(Uint8List identity) {
    final b = StringBuffer();
    for (final byte in identity) {
      b.write(byte.toRadixString(16).padLeft(2, '0'));
    }
    return b.toString();
  }

  QuicResumptionTicket issue({
    required TlsKeySchedule schedule,
    required PqTransportCrypto crypto,
    required int cipherSuite,
    DateTime? now,
    int maxEarlyData = quicMaxDataDefault,
    int maxEarlyStreamData = quicMaxStreamDataDefault,
  }) {
    final nonce = crypto.randomBytes(8);
    final ageAdd = readUint32(crypto.randomBytes(4), 0);
    final psk = schedule.ticketPsk(nonce);
    final issuedAt = (now ?? DateTime.now()).toUtc();
    final identity = _ticketKey == null
        ? crypto.randomBytes(32)
        : _sealTicket(
            crypto: crypto,
            psk: psk,
            nonce: nonce,
            ageAdd: ageAdd,
            cipherSuite: cipherSuite,
            issuedAt: issuedAt,
            lifetimeSeconds: 86400,
            maxEarlyData: maxEarlyData,
            maxEarlyStreamData: maxEarlyStreamData,
          );
    final ticket = QuicResumptionTicket(
      identity: identity,
      nonce: nonce,
      psk: psk,
      ageAdd: ageAdd,
      cipherSuite: cipherSuite,
      issuedAt: issuedAt,
      maxEarlyData: maxEarlyData,
      maxEarlyStreamData: maxEarlyStreamData,
    );
    _live[_id(identity)] = ticket;
    return ticket;
  }

  /// Removes the ticket from this process. A stateless ticket that this
  /// store did not issue is not removed, and its [allowEarlyData] is false.
  QuicResumptionTicket? take(Uint8List identity, {DateTime? now}) {
    final ticket = find(identity, now: now);
    if (ticket == null) return null;
    _live.remove(_id(identity));
    return ticket;
  }

  QuicResumptionTicket? find(Uint8List identity, {DateTime? now}) {
    final stored = _live[_id(identity)];
    final ticket = stored ?? _openTicket(identity);
    if (ticket == null) return null;
    final clock = (now ?? DateTime.now()).toUtc();
    final age = clock.difference(ticket.issuedAt.toUtc());
    if (age < const Duration(seconds: -10)) return null;
    if (age > Duration(seconds: ticket.lifetimeSeconds)) return null;
    return ticket;
  }

  Uint8List _sealTicket({
    required PqTransportCrypto crypto,
    required Uint8List psk,
    required Uint8List nonce,
    required int ageAdd,
    required int cipherSuite,
    required DateTime issuedAt,
    required int lifetimeSeconds,
    required int maxEarlyData,
    required int maxEarlyStreamData,
  }) {
    final body = BytesBuilder(copy: false);
    body.addByte(1);
    writeUint16(body, cipherSuite);
    writeUint32(body, ageAdd);
    writeUint32(body, lifetimeSeconds);
    writeUint64(body, issuedAt.millisecondsSinceEpoch);
    writeUint64(body, maxEarlyData);
    writeUint64(body, maxEarlyStreamData);
    writeOpaque8(body, nonce);
    writeOpaque8(body, psk);
    final iv = crypto.randomBytes(12);
    final sealed = crypto.aeadSeal(
      key: _ticketKey!,
      nonce: iv,
      plaintext: body.takeBytes(),
      aad: Uint8List.fromList(_ticketAad.codeUnits),
    );
    return concatBytes([iv, sealed]);
  }

  QuicResumptionTicket? _openTicket(Uint8List identity) {
    final key = _ticketKey;
    if (key == null || identity.length <= 12) return null;
    try {
      final plain = const PqTransportCrypto().aeadOpen(
        key: key,
        nonce: Uint8List.sublistView(identity, 0, 12),
        ciphertextWithTag: Uint8List.sublistView(identity, 12),
        aad: Uint8List.fromList(_ticketAad.codeUnits),
      );
      final r = ByteReader(plain);
      final version = r.u8();
      if (version.isFailure || version.valueOrNull != 1) return null;
      final suite = r.u16();
      final ageAdd = r.u32();
      final life = r.u32();
      final issued = r.u64();
      final maxData = r.u64();
      final maxStream = r.u64();
      final nonce = r.opaque8(PqLengthLabel.tlsExtension);
      final psk = r.opaque8(PqLengthLabel.tlsExtension);
      if (suite.isFailure ||
          ageAdd.isFailure ||
          life.isFailure ||
          issued.isFailure ||
          maxData.isFailure ||
          maxStream.isFailure ||
          nonce.isFailure ||
          psk.isFailure ||
          !r.isDone) {
        return null;
      }
      return QuicResumptionTicket(
        identity: Uint8List.fromList(identity),
        nonce: nonce.valueOrNull!,
        psk: psk.valueOrNull!,
        ageAdd: ageAdd.valueOrNull!,
        cipherSuite: suite.valueOrNull!,
        issuedAt: DateTime.fromMillisecondsSinceEpoch(
          issued.valueOrNull!,
          isUtc: true,
        ),
        lifetimeSeconds: life.valueOrNull!,
        maxEarlyData: maxData.valueOrNull!,
        maxEarlyStreamData: maxStream.valueOrNull!,
        allowEarlyData: false,
      );
    } on Object {
      return null;
    }
  }
}

/// RFC 8446 NewSessionTicket plus the QUIC early_data sentinel.
///
/// [transportParameters] is the server's remembered flow-control set
/// (RFC 9001 extension 57). Without it a peer will not send 0-RTT.
Uint8List encodeNewSessionTicket(
  QuicResumptionTicket ticket, {
  Uint8List? transportParameters,
}) {
  final body = BytesBuilder(copy: false);
  writeUint32(body, ticket.lifetimeSeconds);
  writeUint32(body, ticket.ageAdd);
  writeOpaque8(body, ticket.nonce);
  writeOpaque16(body, ticket.identity);
  final early = BytesBuilder(copy: false);
  writeUint32(early, quicEarlyDataUnlimited);
  final one = BytesBuilder(copy: false);
  writeUint16(one, tlsExtEarlyData);
  writeOpaque16(one, early.takeBytes());
  final params = transportParameters;
  if (params != null) {
    writeUint16(one, tlsExtQuicTransportParameters);
    writeOpaque16(one, params);
  }
  writeOpaque16(body, one.takeBytes());
  return encodeHandshake(tlsHsNewSessionTicket, body.takeBytes());
}

Result<
  ({
    Uint8List identity,
    Uint8List nonce,
    int ageAdd,
    int lifetimeSeconds,
    Uint8List? transportParameters,
  }),
  PqTransportError
>
decodeNewSessionTicket(Uint8List handshake) {
  final hs = decodeHandshake(handshake);
  if (hs.isFailure) return Result.failure(hs.errorOrNull!);
  final (type, body) = hs.valueOrNull!;
  if (type != tlsHsNewSessionTicket) {
    return Result.failure(
      PqTransportError.unexpectedMessage('expected new_session_ticket'),
    );
  }
  final r = ByteReader(body);
  final life = r.u32();
  if (life.isFailure) return Result.failure(life.errorOrNull!);
  final ageAdd = r.u32();
  if (ageAdd.isFailure) return Result.failure(ageAdd.errorOrNull!);
  final nonce = r.opaque8(PqLengthLabel.tlsExtension);
  if (nonce.isFailure) return Result.failure(nonce.errorOrNull!);
  final identity = r.opaque16(PqLengthLabel.tlsExtension);
  if (identity.isFailure) return Result.failure(identity.errorOrNull!);
  final exts = r.opaque16(PqLengthLabel.tlsExtension);
  if (exts.isFailure) return Result.failure(exts.errorOrNull!);
  if (!r.isDone) {
    return Result.failure(
      PqTransportError.decodeFailure('trailing new_session_ticket'),
    );
  }
  final extBytes = exts.valueOrNull!;
  final extensions = ByteReader(extBytes);
  Uint8List? transportParameters;
  while (extensions.remaining > 0) {
    final type = extensions.u16();
    if (type.isFailure) return Result.failure(type.errorOrNull!);
    final extBody = extensions.opaque16(PqLengthLabel.tlsExtension);
    if (extBody.isFailure) return Result.failure(extBody.errorOrNull!);
    if (type.valueOrNull == tlsExtQuicTransportParameters) {
      transportParameters = extBody.valueOrNull;
    }
  }
  return Result.success((
    identity: identity.valueOrNull!,
    nonce: nonce.valueOrNull!,
    ageAdd: ageAdd.valueOrNull!,
    lifetimeSeconds: life.valueOrNull!,
    transportParameters: transportParameters,
  ));
}

/// ClientHello with early_data and a PSK binder.
///
/// RFC 8446 §4.2.11.2: the binder covers Truncate(ClientHello). The
/// binders list is omitted from the hash input. The handshake length,
/// the extensions length, and the pre_shared_key length stay as in the
/// full hello, counting the binders that are about to be written.
({Uint8List hello, Uint8List earlySecret}) buildEarlyClientHello({
  required Uint8List baseHello,
  required TlsKeySchedule schedule,
  required QuicResumptionTicket ticket,
  List<QuicResumptionTicket> more = const [],
  required DateTime now,
}) {
  final tickets = [ticket, ...more];
  schedule.usePsk(ticket.psk);
  final placeholder = Uint8List(schedule.hashLen);
  final hello = appendHandshakeExtension(
    appendHandshakeExtension(
      appendHandshakeExtension(baseHello, encodeEarlyDataExtension()),
      encodePskKeyExchangeModesExtension(),
    ),
    encodePreSharedKeyList(
      identities: [
        for (final one in tickets)
          (identity: one.identity, obfuscatedAge: one.obfuscatedAge(now)),
      ],
      binders: [for (final _ in tickets) placeholder],
    ),
  );
  final bindersContent = tickets.length * (1 + placeholder.length);
  final truncated = truncatePskBinderList(hello, bindersContent);
  final hash = schedule.transcriptHash(truncated);
  var pos = hello.length - bindersContent;
  for (final one in tickets) {
    schedule.usePsk(one.psk);
    final binderKey = schedule.resumptionBinderKey();
    final binder = schedule.binderVerifyData(binderKey, hash);
    zeroize(binderKey);
    hello[pos] = binder.length;
    hello.setRange(pos + 1, pos + 1 + binder.length, binder);
    pos += 1 + binder.length;
  }
  schedule.usePsk(ticket.psk);
  final early = schedule.clientEarlyTraffic(schedule.transcriptHash(hello));
  return (hello: hello, earlySecret: early);
}

/// RFC 8446 §4.2.11.2 Truncate. Drops one binder. Does not shrink the
/// length fields: they already include that binder.
Uint8List truncatePskBinders(Uint8List handshake, int binderLength) {
  return truncatePskBinderList(handshake, 1 + binderLength);
}

/// Drops the whole binders list. [bindersContentLength] is the bytes
/// inside the binders opaque16, not including its 2-byte length.
Uint8List truncatePskBinderList(Uint8List handshake, int bindersContentLength) {
  final drop = 2 + bindersContentLength;
  if (handshake.length <= drop + tlsHandshakeHeaderBytes) {
    throw ArgumentError('hello shorter than its binders');
  }
  return Uint8List.sublistView(handshake, 0, handshake.length - drop);
}
