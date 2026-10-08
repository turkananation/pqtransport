import 'dart:convert';
import 'dart:typed_data';

import 'package:swissarmyknife/swissarmyknife.dart';

import '../core/bytes.dart';
import '../core/crypto.dart';
import '../core/errors.dart';
import '../core/lengths.dart';
import '../tls/key_schedule.dart';
import 'packet.dart';

/// RFC 9001 §5.2 Initial secrets (AES-128-GCM, SHA-256) from the DCID.
final class QuicInitialSecrets {
  const QuicInitialSecrets({required this.client, required this.server});

  final QuicPacketKeys client;
  final QuicPacketKeys server;

  factory QuicInitialSecrets.derive({
    required PqTransportCrypto crypto,
    required Uint8List destinationConnectionId,
  }) {
    final salt = Uint8List.fromList(quicInitialSaltV1);
    final initial = crypto.hkdfExtract(salt, destinationConnectionId);
    return QuicInitialSecrets(
      client: _aes128Keys(
        crypto,
        _expandLabel(crypto, initial, quicLabelClientIn, 32),
      ),
      server: _aes128Keys(
        crypto,
        _expandLabel(crypto, initial, quicLabelServerIn, 32),
      ),
    );
  }
}

/// 1-RTT / Handshake keys from a TLS traffic secret. Hash follows [schedule]
/// (SHA-384 for IANA `0x1302`). ChaCha HP is not in this slice.
QuicPacketKeys quicKeysFromTls({
  required TlsKeySchedule schedule,
  required Uint8List trafficSecret,
}) {
  if (schedule.aead == TransportAead.chacha20Poly1305) {
    throw UnsupportedError(
      'QUIC ChaCha20 header protection is not implemented (RFC 9001 §5.4.4)',
    );
  }
  final n = schedule.aead == TransportAead.aes128Gcm
      ? quicAes128KeyBytes
      : aeadKeyBytes;
  return QuicPacketKeys(
    key: schedule.quicPacketKey(trafficSecret, n),
    iv: schedule.quicPacketIv(trafficSecret),
    hp: schedule.quicHeaderProtectionKey(trafficSecret, n),
  );
}

QuicPacketKeys _aes128Keys(PqTransportCrypto crypto, Uint8List secret) {
  return QuicPacketKeys(
    key: _expandLabel(crypto, secret, quicLabelKey, quicAes128KeyBytes),
    iv: _expandLabel(crypto, secret, quicLabelIv, aeadNonceBytes),
    hp: _expandLabel(crypto, secret, quicLabelHp, quicAes128KeyBytes),
  );
}

Uint8List _expandLabel(
  PqTransportCrypto crypto,
  Uint8List secret,
  String label,
  int length,
) {
  final labelBytes = utf8.encode('$tlsHkdfLabelPrefix$label');
  final b = BytesBuilder(copy: false);
  writeUint16(b, length);
  b.addByte(labelBytes.length);
  b.add(labelBytes);
  b.addByte(0);
  return crypto.hkdfExpand(secret, b.takeBytes(), length);
}

/// RFC 9000 §17.2.2 Initial long-header packet + §5.4 header protection.
final class QuicInitialCodec {
  QuicInitialCodec({required this.crypto, required this.keys});

  final PqTransportCrypto crypto;
  final QuicPacketKeys keys;

  static const pnLength = 4;

  Result<Uint8List, PqTransportError> protect({
    required Uint8List dcid,
    required Uint8List scid,
    required int packetNumber,
    required Uint8List payload,
    Uint8List? token,
    int packetNumberLength = pnLength,
  }) {
    if (dcid.length > quicMaxConnectionIdBytes ||
        scid.length > quicMaxConnectionIdBytes) {
      return Result.failure(PqTransportError.decodeFailure('cid length'));
    }
    if (packetNumberLength < 1 ||
        packetNumberLength > quicPacketNumberMaxBytes) {
      return Result.failure(PqTransportError.decodeFailure('pn length'));
    }
    final tok = token ?? Uint8List(0);
    final headerNoPn = BytesBuilder(copy: false);
    headerNoPn.addByte(0xC0 | (packetNumberLength - 1));
    writeUint32(headerNoPn, quicVersion1);
    headerNoPn.addByte(dcid.length);
    headerNoPn.add(dcid);
    headerNoPn.addByte(scid.length);
    headerNoPn.add(scid);
    writeQuicVarint(headerNoPn, tok.length);
    headerNoPn.add(tok);
    final bodyLen = packetNumberLength + payload.length + aeadTagBytes;
    writeQuicVarint(headerNoPn, bodyLen);
    final prefix = headerNoPn.takeBytes();
    final pn = BytesBuilder(copy: false);
    writePacketNumber(pn, packetNumber, packetNumberLength);
    final hdr = concatBytes([prefix, pn.takeBytes()]);
    final body = crypto.aeadSeal(
      key: keys.key,
      nonce: quicAeadNonce(keys.iv, packetNumber),
      plaintext: payload,
      aad: hdr,
      aead: TransportAead.aes128Gcm,
    );
    final packet = concatBytes([hdr, body]);
    if (!quicHeaderProtectionSampleFits(packet.length, prefix.length)) {
      return Result.failure(PqTransportError.decodeFailure('hp sample'));
    }
    final mask = quicHeaderProtectionMask(
      crypto: crypto,
      hpKey: keys.hp,
      packet: packet,
      pnOffset: prefix.length,
    );
    applyQuicHeaderProtection(
      packet,
      mask: mask,
      pnOffset: prefix.length,
      pnLength: packetNumberLength,
      longHeader: true,
    );
    return Result.success(packet);
  }

  Result<({int packetNumber, Uint8List payload}), PqTransportError> open(
    Uint8List wire,
  ) {
    if (wire.length < 7) {
      return Result.failure(PqTransportError.decodeFailure('short initial'));
    }
    final packet = Uint8List.fromList(wire);
    if ((packet[0] & 0xF0) != 0xC0) {
      return Result.failure(PqTransportError.decodeFailure('not initial'));
    }
    if (readUint32(packet, 1) != quicVersion1) {
      return Result.failure(PqTransportError.decodeFailure('version'));
    }
    final parsed = _skipToPn(packet);
    if (parsed.isFailure) return Result.failure(parsed.errorOrNull!);
    final pnOff = parsed.valueOrNull!;
    if (!quicHeaderProtectionSampleFits(packet.length, pnOff)) {
      return Result.failure(PqTransportError.decodeFailure('hp sample'));
    }
    final mask = quicHeaderProtectionMask(
      crypto: crypto,
      hpKey: keys.hp,
      packet: packet,
      pnOffset: pnOff,
    );
    packet[0] ^= mask[0] & 0x0f;
    final pnLen = (packet[0] & 0x03) + 1;
    if (pnOff + pnLen > packet.length) {
      return Result.failure(PqTransportError.decodeFailure('pn length'));
    }
    for (var i = 0; i < pnLen; i++) {
      packet[pnOff + i] ^= mask[1 + i];
    }
    final pn = readPacketNumber(packet, pnOff, pnLen);
    final hdr = slice(packet, 0, pnOff + pnLen);
    try {
      final payload = crypto.aeadOpen(
        key: keys.key,
        nonce: quicAeadNonce(keys.iv, pn),
        ciphertextWithTag: slice(packet, pnOff + pnLen, packet.length),
        aad: hdr,
        aead: TransportAead.aes128Gcm,
      );
      return Result.success((packetNumber: pn, payload: payload));
    } on Object catch (e) {
      return Result.failure(
        PqTransportError.decryptError('quic initial ${e.runtimeType}'),
      );
    }
  }

  Result<int, PqTransportError> _skipToPn(Uint8List packet) {
    var off = 1 + 4; // first byte + version
    if (packet.length < off + 1) {
      return Result.failure(PqTransportError.decodeFailure('short initial'));
    }
    final dcidLen = packet[off++];
    if (dcidLen > quicMaxConnectionIdBytes) {
      return Result.failure(PqTransportError.decodeFailure('dcid length'));
    }
    if (packet.length < off + dcidLen + 1) {
      return Result.failure(PqTransportError.decodeFailure('short dcid'));
    }
    off += dcidLen;
    final scidLen = packet[off++];
    if (scidLen > quicMaxConnectionIdBytes) {
      return Result.failure(PqTransportError.decodeFailure('scid length'));
    }
    if (packet.length < off + scidLen) {
      return Result.failure(PqTransportError.decodeFailure('short scid'));
    }
    off += scidLen;
    final r = ByteReader(packet)..offset = off;
    final tokLen = readVarint(r);
    if (tokLen < 0) {
      return Result.failure(PqTransportError.decodeFailure('token varint'));
    }
    if (r.remaining < tokLen) {
      return Result.failure(PqTransportError.decodeFailure('short token'));
    }
    r.offset += tokLen;
    final rest = readVarint(r);
    if (rest < 0) {
      return Result.failure(PqTransportError.decodeFailure('length varint'));
    }
    return Result.success(r.offset);
  }
}
