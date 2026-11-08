import 'dart:typed_data';

import 'package:swissarmyknife/swissarmyknife.dart';

import '../core/bytes.dart';
import '../core/crypto.dart';
import '../core/errors.dart';
import '../core/lengths.dart';
import 'packet.dart';

/// RFC 9000 §17.2.3 0-RTT long header. Same Application Data number space
/// as 1-RTT. Not a fourth space.
final class QuicZeroRttCodec {
  QuicZeroRttCodec({
    required this.crypto,
    required this.keys,
    required this.aead,
  });

  final PqTransportCrypto crypto;
  final QuicPacketKeys keys;
  final TransportAead aead;

  static const pnLength = 4;

  Result<Uint8List, PqTransportError> protect({
    required Uint8List dcid,
    required Uint8List scid,
    required int packetNumber,
    required Uint8List payload,
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
    final headerNoPn = BytesBuilder(copy: false);
    headerNoPn.addByte(0xD0 | (packetNumberLength - 1));
    writeUint32(headerNoPn, quicVersion1);
    headerNoPn.addByte(dcid.length);
    headerNoPn.add(dcid);
    headerNoPn.addByte(scid.length);
    headerNoPn.add(scid);
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
      aead: aead,
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
      aead: aead,
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
    if (wire.length < 7 || (wire[0] & 0xF0) != 0xD0) {
      return Result.failure(PqTransportError.decodeFailure('not 0-rtt'));
    }
    final packet = Uint8List.fromList(wire);
    if (readUint32(packet, 1) != quicVersion1) {
      return Result.failure(PqTransportError.decodeFailure('version'));
    }
    final parsed = _pnOffset(packet);
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
      aead: aead,
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
        aead: aead,
      );
      return Result.success((packetNumber: pn, payload: payload));
    } on Object catch (e) {
      return Result.failure(
        PqTransportError.decryptError('quic 0-rtt ${e.runtimeType}'),
      );
    }
  }

  Result<int, PqTransportError> _pnOffset(Uint8List packet) {
    var off = 1 + 4;
    if (packet.length < off + 1) {
      return Result.failure(PqTransportError.decodeFailure('short 0-rtt'));
    }
    final dcidLen = packet[off++];
    if (dcidLen > quicMaxConnectionIdBytes ||
        packet.length < off + dcidLen + 1) {
      return Result.failure(PqTransportError.decodeFailure('0-rtt dcid'));
    }
    off += dcidLen;
    final scidLen = packet[off++];
    if (scidLen > quicMaxConnectionIdBytes || packet.length < off + scidLen) {
      return Result.failure(PqTransportError.decodeFailure('0-rtt scid'));
    }
    off += scidLen;
    final r = ByteReader(packet)..offset = off;
    final rest = readVarint(r);
    if (rest < 0) {
      return Result.failure(PqTransportError.decodeFailure('0-rtt length'));
    }
    return Result.success(r.offset);
  }
}
