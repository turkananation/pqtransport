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

  int obfuscatedAge(DateTime now) {
    final age = now.toUtc().difference(issuedAt.toUtc()).inMilliseconds;
    final bounded = age < 0 ? 0 : age;
    return (bounded + ageAdd) & 0xffffffff;
  }
}

/// Single-use ticket store. A second take of the same identity fails.
final class QuicEarlyDataStore {
  final Map<String, QuicResumptionTicket> _live = {};

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
    final identity = crypto.randomBytes(32);
    final nonce = crypto.randomBytes(8);
    final ageAdd = readUint32(crypto.randomBytes(4), 0);
    final psk = schedule.ticketPsk(nonce);
    final ticket = QuicResumptionTicket(
      identity: identity,
      nonce: nonce,
      psk: psk,
      ageAdd: ageAdd,
      cipherSuite: cipherSuite,
      issuedAt: (now ?? DateTime.now()).toUtc(),
      maxEarlyData: maxEarlyData,
      maxEarlyStreamData: maxEarlyStreamData,
    );
    _live[_id(identity)] = ticket;
    return ticket;
  }

  /// Removes the ticket. Null means unknown, expired, or already used.
  QuicResumptionTicket? take(Uint8List identity, {DateTime? now}) {
    final ticket = find(identity, now: now);
    if (ticket == null) return null;
    _live.remove(_id(identity));
    return ticket;
  }

  QuicResumptionTicket? find(Uint8List identity, {DateTime? now}) {
    final ticket = _live[_id(identity)];
    if (ticket == null) return null;
    final clock = (now ?? DateTime.now()).toUtc();
    final age = clock.difference(ticket.issuedAt.toUtc());
    if (age < const Duration(seconds: -10)) return null;
    if (age > Duration(seconds: ticket.lifetimeSeconds)) return null;
    return ticket;
  }
}

/// RFC 8446 NewSessionTicket plus the QUIC early_data max.
Uint8List encodeNewSessionTicket(QuicResumptionTicket ticket) {
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
  writeOpaque16(body, one.takeBytes());
  return encodeHandshake(tlsHsNewSessionTicket, body.takeBytes());
}

Result<
  ({Uint8List identity, Uint8List nonce, int ageAdd, int lifetimeSeconds}),
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
  return Result.success((
    identity: identity.valueOrNull!,
    nonce: nonce.valueOrNull!,
    ageAdd: ageAdd.valueOrNull!,
    lifetimeSeconds: life.valueOrNull!,
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
  required DateTime now,
}) {
  schedule.usePsk(ticket.psk);
  final age = ticket.obfuscatedAge(now);
  final placeholder = Uint8List(schedule.hashLen);
  final hello = appendHandshakeExtension(
    appendHandshakeExtension(baseHello, encodeEarlyDataExtension()),
    encodePreSharedKeyExtension(
      identity: ticket.identity,
      obfuscatedAge: age,
      binder: placeholder,
    ),
  );
  final binderKey = schedule.resumptionBinderKey();
  final binder = schedule.binderVerifyData(
    binderKey,
    schedule.transcriptHash(truncatePskBinders(hello, placeholder.length)),
  );
  zeroize(binderKey);
  hello.setRange(hello.length - binder.length, hello.length, binder);
  final early = schedule.clientEarlyTraffic(schedule.transcriptHash(hello));
  return (hello: hello, earlySecret: early);
}

/// RFC 8446 §4.2.11.2 Truncate. Drops the binders list. Does not shrink
/// the length fields: they already include that list.
Uint8List truncatePskBinders(Uint8List handshake, int binderLength) {
  final drop = 2 + 1 + binderLength;
  if (handshake.length <= drop + tlsHandshakeHeaderBytes) {
    throw ArgumentError('hello shorter than its binders');
  }
  return Uint8List.sublistView(handshake, 0, handshake.length - drop);
}
