import 'dart:typed_data';

import 'package:pqtransport/pqtransport.dart';
import 'package:test/test.dart';

void main() {
  final crypto = PqTransportCrypto();

  test('CRYPTO frame carries the 1216-byte X25519MLKEM768 share', () {
    final share = Uint8List(x25519MlKem768ClientShareBytes)..[0] = 0x11;
    final hello = ClientHello(
      random: crypto.randomBytes(handshakeRandomBytes),
      group: HybridGroup.x25519MlKem768,
      share: share,
    );
    expect(hello.share.length, x25519MlKem768ClientShareBytes);
    final frame = QuicCryptoFrame(offset: 0, data: hello.encode());
    final decoded = QuicCryptoFrame.decode(frame.encode());
    expect(decoded.isSuccess, isTrue, reason: '${decoded.errorOrNull}');
    expect(
      decoded.valueOrNull!.data.length,
      greaterThan(x25519MlKem768ClientShareBytes),
    );
    final ch = ClientHello.decode(decoded.valueOrNull!.data);
    expect(ch.isSuccess, isTrue, reason: '${ch.errorOrNull}');
    expect(ch.valueOrNull!.share.length, x25519MlKem768ClientShareBytes);
    expect(ch.valueOrNull!.share[0], 0x11);
  });

  test('packet protect round trip; bit flip fails', () {
    final key = crypto.randomBytes(aeadKeyBytes);
    final iv = crypto.randomBytes(aeadNonceBytes);
    final codec = QuicPacketCodec(crypto: crypto, key: key, iv: iv);
    final dcid = crypto.randomBytes(8);
    final hello = ClientHello(
      random: crypto.randomBytes(handshakeRandomBytes),
      group: HybridGroup.x25519MlKem768,
      share: Uint8List(x25519MlKem768ClientShareBytes),
    );
    expect(hello.share.length, x25519MlKem768ClientShareBytes);
    final cryptoFrame = QuicCryptoFrame(offset: 0, data: hello.encode());
    final sealed = codec.protect(
      dcid: dcid,
      packetNumber: 1,
      payload: cryptoFrame.encode(),
    );
    expect(sealed.isSuccess, isTrue);
    final opened = codec.open(sealed.valueOrNull!);
    expect(opened.isSuccess, isTrue);
    final wire = Uint8List.fromList(sealed.valueOrNull!);
    wire[wire.length - 1] ^= 1;
    expect(codec.open(wire).isFailure, isTrue);
  });

  test('flow control violation is an error', () {
    final fc = QuicFlowControl(maxData: 10, maxStreamData: 8);
    expect(fc.consume(0, 4).isSuccess, isTrue);
    expect(fc.consume(0, 5).isFailure, isTrue);
  });

  test('short packet is a decode failure', () {
    final codec = QuicPacketCodec(
      crypto: crypto,
      key: crypto.randomBytes(aeadKeyBytes),
      iv: crypto.randomBytes(aeadNonceBytes),
    );
    expect(codec.open(Uint8List(4)).isFailure, isTrue);
  });
}
