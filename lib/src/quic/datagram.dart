import 'dart:typed_data';

import 'package:swissarmyknife/swissarmyknife.dart';

import '../core/bytes.dart';
import '../core/crypto.dart';
import '../core/errors.dart';
import '../core/lengths.dart';
import 'packet.dart';

/// Exclusive end offset of the QUIC packet that starts at [offset].
/// A short header consumes the rest of the datagram. Null is truncated.
int? quicPacketEnd(Uint8List datagram, int offset) {
  if (offset < 0 || offset >= datagram.length) return null;
  final first = datagram[offset];
  if ((first & 0x80) == 0) return datagram.length;
  if (datagram.length < offset + 6) return null;
  final version = readUint32(datagram, offset + 1);
  var off = offset + 5;
  final dcidLen = datagram[off++];
  if (dcidLen > quicMaxConnectionIdBytes ||
      datagram.length < off + dcidLen + 1) {
    return null;
  }
  off += dcidLen;
  final scidLen = datagram[off++];
  if (scidLen > quicMaxConnectionIdBytes || datagram.length < off + scidLen) {
    return null;
  }
  off += scidLen;
  if (version == 0 || (first & 0xF0) == 0xF0) return datagram.length;
  final reader = ByteReader(datagram)..offset = off;
  if ((first & 0xF0) == 0xC0) {
    final token = readVarint(reader);
    if (token < 0 || reader.remaining < token) return null;
    reader.offset += token;
  }
  final length = readVarint(reader);
  if (length < 0) return null;
  final end = reader.offset + length;
  if (end > datagram.length) return null;
  return end;
}

/// RFC 9000 §12.2. A short-header packet is last. Retry is not coalesced.
Result<List<Uint8List>, PqTransportError> splitQuicDatagram(
  Uint8List datagram,
) {
  if (datagram.isEmpty) {
    return Result.failure(PqTransportError.decodeFailure('empty quic'));
  }
  final packets = <Uint8List>[];
  var offset = 0;
  var sawShort = false;
  while (offset < datagram.length) {
    final first = datagram[offset];
    // RFC 9000 §17.2 and §17.3. The fixed bit is 0x40. A packet with
    // that bit clear is not a QUIC v1 packet and is discarded. quiche
    // pads a datagram that carries an Initial up to 1200 bytes with
    // trailing zeros (RFC 9000 §14.1). Those zeros are not a packet.
    // Version Negotiation keeps the fixed bit clear and version 0.
    if ((first & 0x40) == 0) {
      final versionNegotiation =
          (first & 0x80) != 0 &&
          datagram.length >= offset + 5 &&
          readUint32(datagram, offset + 1) == 0;
      if (!versionNegotiation) break;
    }
    if (sawShort) {
      return Result.failure(
        PqTransportError.decodeFailure('coalesced after short header'),
      );
    }
    final end = quicPacketEnd(datagram, offset);
    if (end == null || end <= offset) {
      return Result.failure(PqTransportError.decodeFailure('coalesced quic'));
    }
    final packet = slice(datagram, offset, end);
    if (packets.isNotEmpty && (packet[0] & 0xF0) == 0xF0) {
      return Result.failure(PqTransportError.decodeFailure('coalesced retry'));
    }
    if ((packet[0] & 0x80) == 0) sawShort = true;
    packets.add(packet);
    offset = end;
    if ((packet[0] & 0xF0) == 0xF0 || readUint32(packet, 1) == 0) break;
  }
  return Result.success(packets);
}

/// RFC 9000 §17.2.1. Supported versions are 32-bit values. Version is 0.
Uint8List quicVersionNegotiation({
  required Uint8List destinationConnectionId,
  required Uint8List sourceConnectionId,
  List<int> versions = const [quicVersion1],
}) {
  final b = BytesBuilder(copy: false);
  b.addByte(0x80);
  writeUint32(b, 0);
  b.addByte(destinationConnectionId.length);
  b.add(destinationConnectionId);
  b.addByte(sourceConnectionId.length);
  b.add(sourceConnectionId);
  for (final version in versions) {
    writeUint32(b, version);
  }
  return b.takeBytes();
}

/// Versions advertised after the connection IDs. Empty when this is not
/// a Version Negotiation packet.
Result<List<int>, PqTransportError> readQuicVersionNegotiation(
  Uint8List packet,
) {
  if (packet.length < 7 || (packet[0] & 0x80) == 0) {
    return Result.failure(PqTransportError.decodeFailure('not version'));
  }
  if (readUint32(packet, 1) != 0) {
    return Result.failure(PqTransportError.decodeFailure('not version'));
  }
  var off = 5;
  final dcidLen = packet[off++];
  if (packet.length < off + dcidLen + 1) {
    return Result.failure(PqTransportError.decodeFailure('version dcid'));
  }
  off += dcidLen;
  final scidLen = packet[off++];
  if (packet.length < off + scidLen) {
    return Result.failure(PqTransportError.decodeFailure('version scid'));
  }
  off += scidLen;
  if ((packet.length - off) % 4 != 0) {
    return Result.failure(PqTransportError.decodeFailure('version list'));
  }
  final versions = <int>[];
  while (off < packet.length) {
    versions.add(readUint32(packet, off));
    off += 4;
  }
  return Result.success(versions);
}

/// RFC 9001 §5.8 Retry packet, including the integrity tag.
Uint8List quicRetryPacket({
  required PqTransportCrypto crypto,
  required Uint8List originalDestinationConnectionId,
  required Uint8List destinationConnectionId,
  required Uint8List sourceConnectionId,
  required Uint8List token,
}) {
  final header = BytesBuilder(copy: false);
  header.addByte(0xf0);
  writeUint32(header, quicVersion1);
  header.addByte(destinationConnectionId.length);
  header.add(destinationConnectionId);
  header.addByte(sourceConnectionId.length);
  header.add(sourceConnectionId);
  header.add(token);
  final packet = header.takeBytes();
  final tag = quicRetryIntegrityTag(
    crypto: crypto,
    originalDestinationConnectionId: originalDestinationConnectionId,
    retryPacketWithoutTag: packet,
  );
  return concatBytes([packet, tag]);
}

Uint8List quicRetryIntegrityTag({
  required PqTransportCrypto crypto,
  required Uint8List originalDestinationConnectionId,
  required Uint8List retryPacketWithoutTag,
}) {
  final pseudo = BytesBuilder(copy: false);
  pseudo.addByte(originalDestinationConnectionId.length);
  pseudo.add(originalDestinationConnectionId);
  pseudo.add(retryPacketWithoutTag);
  return crypto.aeadSeal(
    key: Uint8List.fromList(quicRetryIntegrityKeyV1),
    nonce: Uint8List.fromList(quicRetryIntegrityNonceV1),
    plaintext: Uint8List(0),
    aad: pseudo.takeBytes(),
    aead: TransportAead.aes128Gcm,
  );
}

/// True when [packet] carries a Retry Integrity Tag for [odcid].
bool quicRetryTagValid({
  required PqTransportCrypto crypto,
  required Uint8List originalDestinationConnectionId,
  required Uint8List packet,
}) {
  if (packet.length < quicRetryIntegrityTagBytes + 7) return false;
  if ((packet[0] & 0xF0) != 0xF0) return false;
  final body = slice(packet, 0, packet.length - quicRetryIntegrityTagBytes);
  final tag = slice(packet, body.length, packet.length);
  final expect = quicRetryIntegrityTag(
    crypto: crypto,
    originalDestinationConnectionId: originalDestinationConnectionId,
    retryPacketWithoutTag: body,
  );
  if (expect.length != tag.length) return false;
  var diff = 0;
  for (var i = 0; i < tag.length; i++) {
    diff |= tag[i] ^ expect[i];
  }
  return diff == 0;
}

/// RFC 9000 §10.3. The token is the last 16 bytes. Not a decrypt.
bool quicStatelessResetMatches(Uint8List datagram, Uint8List token) {
  if (token.length != quicStatelessResetTokenBytes) return false;
  if (datagram.length < 1 + quicStatelessResetTokenBytes + 4) return false;
  if ((datagram[0] & 0x80) != 0) return false;
  final start = datagram.length - token.length;
  for (var i = 0; i < token.length; i++) {
    if (datagram[start + i] != token[i]) return false;
  }
  return true;
}
