import 'dart:typed_data';

import 'package:pqtransport/pqtransport.dart';
import 'package:test/test.dart';

void main() {
  final crypto = PqTransportCrypto();

  Uint8List hex(String s) {
    final compact = s.replaceAll(RegExp(r'\s'), '');
    final out = Uint8List(compact.length ~/ 2);
    for (var i = 0; i < out.length; i++) {
      out[i] = int.parse(compact.substring(i * 2, i * 2 + 2), radix: 16);
    }
    return out;
  }

  test('RFC 9001 Appendix A.1 Initial secrets', () {
    final dcid = hex('8394c8f03e515708');
    final secrets = QuicInitialSecrets.derive(
      crypto: crypto,
      destinationConnectionId: dcid,
    );
    expect(secrets.client.key, hex('1f369613dd76d5467730efcbe3b1a22d'));
    expect(secrets.client.iv, hex('fa044b2f42a3fd3b46fb255c'));
    expect(secrets.client.hp, hex('9f50449e04a0e810283a1e9933adedd2'));
    expect(secrets.server.key, hex('cf3a5331653c364c88f0f379b6067e37'));
    expect(secrets.server.iv, hex('0ac1493ca1905853b0bba03e'));
    expect(secrets.server.hp, hex('c206b8d9b9f0f37644430b490eeaa314'));
  });

  test('FIPS 197 C.1 AES-128 block through the facade (QUIC HP)', () {
    final ct = crypto.aesEncryptBlock(
      key: hex('000102030405060708090a0b0c0d0e0f'),
      block: hex('00112233445566778899aabbccddeeff'),
    );
    expect(ct, hex('69c4e0d86a7b0430d8cdb78070b4c55a'));
  });

  test('FIPS 197 C.3 AES-256 block through the facade (1-RTT HP)', () {
    final ct = crypto.aesEncryptBlock(
      key: hex(
        '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f',
      ),
      block: hex('00112233445566778899aabbccddeeff'),
    );
    expect(ct, hex('8ea2b7ca516745bfeafc49904b496089'));
  });

  test('CRYPTO frame carries a live X25519MLKEM768 ClientHello', () async {
    final client = PqTlsClient(crypto: crypto, quic: true);
    final ch = await client.startHandshake();
    expect(ch.isSuccess, isTrue, reason: '${ch.errorOrNull}');
    final hello = ClientHello.decode(ch.valueOrNull!);
    expect(hello.isSuccess, isTrue, reason: '${hello.errorOrNull}');
    expect(hello.valueOrNull!.share.length, x25519MlKem768ClientShareBytes);
    expect(hello.valueOrNull!.share, isNot(everyElement(0)));
    final frame = QuicCryptoFrame(offset: 0, data: ch.valueOrNull!);
    final decoded = QuicCryptoFrame.decode(frame.encode());
    expect(decoded.isSuccess, isTrue, reason: '${decoded.errorOrNull}');
    final round = ClientHello.decode(decoded.valueOrNull!.data);
    expect(round.valueOrNull!.share, hello.valueOrNull!.share);
    await client.close();
  });

  test('1-RTT short header HP round trip; header bit-flip fails', () {
    final key = crypto.randomBytes(aeadKeyBytes);
    final iv = crypto.randomBytes(aeadNonceBytes);
    final hp = crypto.randomBytes(aeadKeyBytes);
    final codec = QuicPacketCodec(crypto: crypto, key: key, iv: iv, hpKey: hp);
    final dcid = crypto.randomBytes(quicShortDcidBytes);
    final payload = Uint8List.fromList([quicFramePing]);
    final sealed = codec.protect(dcid: dcid, packetNumber: 7, payload: payload);
    expect(sealed.isSuccess, isTrue, reason: '${sealed.errorOrNull}');
    final opened = codec.open(sealed.valueOrNull!);
    expect(opened.isSuccess, isTrue, reason: '${opened.errorOrNull}');
    expect(opened.valueOrNull!.packetNumber, 7);
    expect(opened.valueOrNull!.payload, payload);
    final flipped = Uint8List.fromList(sealed.valueOrNull!);
    flipped[0] ^= 0x01;
    expect(codec.open(flipped).isFailure, isTrue);
    final tagFlip = Uint8List.fromList(sealed.valueOrNull!);
    tagFlip[tagFlip.length - 1] ^= 1;
    expect(codec.open(tagFlip).isFailure, isTrue);
  });

  test('Initial long-header HP round trip (AES-128-GCM)', () {
    final dcid = crypto.randomBytes(8);
    final scid = crypto.randomBytes(8);
    final secrets = QuicInitialSecrets.derive(
      crypto: crypto,
      destinationConnectionId: dcid,
    );
    final codec = QuicInitialCodec(crypto: crypto, keys: secrets.client);
    final payload = QuicCryptoFrame(
      offset: 0,
      data: Uint8List.fromList([1, 2, 3, 4]),
    ).encode();
    final sealed = codec.protect(
      dcid: dcid,
      scid: scid,
      packetNumber: 2,
      payload: payload,
    );
    expect(sealed.isSuccess, isTrue, reason: '${sealed.errorOrNull}');
    final opened = codec.open(sealed.valueOrNull!);
    expect(opened.isSuccess, isTrue, reason: '${opened.errorOrNull}');
    expect(opened.valueOrNull!.packetNumber, 2);
    expect(opened.valueOrNull!.payload, payload);
  });

  test('ACK frame encode/decode and processor', () {
    final proc = QuicAckProcessor();
    proc.onReceived(1);
    proc.onReceived(2);
    proc.onReceived(5);
    proc.onSent(9, Uint8List.fromList([9]));
    proc.onSent(10, Uint8List.fromList([10]));
    final pending = proc.pendingAck();
    expect(pending.isSuccess, isTrue, reason: '${pending.errorOrNull}');
    final ack = pending.valueOrNull!;
    final round = QuicAckFrame.decode(ack.encode());
    expect(round.isSuccess, isTrue, reason: '${round.errorOrNull}');
    expect(round.valueOrNull!.packetNumbers().toSet(), {5, 2, 1});
    final inbound = QuicAckFrame(largest: 10, delay: 0, firstRange: 1);
    expect(proc.applyAck(inbound), [10, 9]);
    expect(proc.inFlight, isEmpty);
  });

  test('RFC 9001 TLS-in-QUIC live handshake, exporters match', () async {
    final identity = PqTlsServerIdentity.generate(crypto);
    final client = QuicTlsHandshake.client(crypto: crypto);
    final server = QuicTlsHandshake.server(crypto: crypto, identity: identity);
    final ch = await client.start();
    expect(ch.isSuccess, isTrue, reason: '${ch.errorOrNull}');
    expect(ch.valueOrNull, hasLength(1));
    final shFlight = await server.ingest(ch.valueOrNull!.single);
    expect(shFlight.isSuccess, isTrue, reason: '${shFlight.errorOrNull}');
    expect(shFlight.valueOrNull, hasLength(2));
    var last = await client.ingest(shFlight.valueOrNull!.first);
    expect(last.isSuccess, isTrue, reason: '${last.errorOrNull}');
    last = await client.ingest(shFlight.valueOrNull!.last);
    expect(last.isSuccess, isTrue, reason: '${last.errorOrNull}');
    expect(last.valueOrNull, hasLength(1));
    final done = await server.ingest(last.valueOrNull!.single);
    expect(done.isSuccess, isTrue, reason: '${done.errorOrNull}');
    expect(client.isComplete, isTrue);
    expect(server.isComplete, isTrue);
    final ctx = Uint8List(0);
    expect(
      client.exporterBytes('quic exporter', ctx, 32),
      server.exporterBytes('quic exporter', ctx, 32),
    );
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
      hpKey: crypto.randomBytes(aeadKeyBytes),
    );
    expect(codec.open(Uint8List(4)).isFailure, isTrue);
  });

  test('CRYPTO stream reassembles out-of-order offsets', () {
    final s = QuicCryptoStream();
    s.add(QuicCryptoFrame(offset: 3, data: Uint8List.fromList([3, 4, 5])));
    expect(s.takeAvailable(), isEmpty);
    s.add(QuicCryptoFrame(offset: 0, data: Uint8List.fromList([0, 1, 2])));
    expect(s.takeAvailable(), [0, 1, 2, 3, 4, 5]);
    expect(s.takeAvailable(), isEmpty);
  });

  test('decodeQuicPayload skips PADDING and reads CRYPTO + ACK', () {
    final cryptoFrame = QuicCryptoFrame(
      offset: 0,
      data: Uint8List.fromList([9, 9]),
    );
    final ack = QuicAckFrame(largest: 3, delay: 0, firstRange: 1);
    final payload = concatBytes([
      Uint8List.fromList([quicFramePadding, quicFramePing]),
      cryptoFrame.encode(),
      ack.encode(),
      Uint8List(8),
    ]);
    final parsed = decodeQuicPayload(payload);
    expect(parsed.isSuccess, isTrue, reason: '${parsed.errorOrNull}');
    expect(parsed.valueOrNull!.crypto.single.data, [9, 9]);
    expect(parsed.valueOrNull!.acks.single.largest, 3);
  });

  test('ChaCha20 QUIC header protection fails closed', () {
    final codec = QuicPacketCodec(
      crypto: crypto,
      key: crypto.randomBytes(aeadKeyBytes),
      iv: crypto.randomBytes(aeadNonceBytes),
      hpKey: crypto.randomBytes(aeadKeyBytes),
      aead: TransportAead.chacha20Poly1305,
    );
    final sealed = codec.protect(
      dcid: crypto.randomBytes(quicShortDcidBytes),
      packetNumber: 1,
      payload: Uint8List.fromList([quicFramePing]),
    );
    expect(sealed.isFailure, isTrue);
    expect(sealed.errorOrNull!.code, PqTransportErrorCode.unsupported);
    final chacha = TlsKeySchedule(
      crypto,
      suite: TlsCipherSuite.chacha20Poly1305Sha256,
    );
    expect(
      () => quicKeysFromTls(
        schedule: chacha,
        trafficSecret: crypto.randomBytes(sha256HashBytes),
      ),
      throwsA(isA<UnsupportedError>()),
    );
  });

  test('ACK additional ranges: 1,2,5,6,9', () {
    final proc = QuicAckProcessor();
    for (final pn in [1, 2, 5, 6, 9]) {
      proc.onReceived(pn);
    }
    final ack = proc.pendingAck().valueOrNull!;
    expect(ack.packetNumbers().toSet(), {9, 6, 5, 2, 1});
    final round = QuicAckFrame.decode(ack.encode());
    expect(round.valueOrNull!.packetNumbers().toSet(), {9, 6, 5, 2, 1});
  });

  test('Initial header and tag bit-flips fail closed', () {
    final dcid = crypto.randomBytes(8);
    final secrets = QuicInitialSecrets.derive(
      crypto: crypto,
      destinationConnectionId: dcid,
    );
    final codec = QuicInitialCodec(crypto: crypto, keys: secrets.client);
    final sealed = codec.protect(
      dcid: dcid,
      scid: crypto.randomBytes(8),
      packetNumber: 0,
      payload: Uint8List.fromList([quicFramePing]),
    );
    expect(sealed.isSuccess, isTrue, reason: '${sealed.errorOrNull}');
    final hdrFlip = Uint8List.fromList(sealed.valueOrNull!)..[0] ^= 0x01;
    expect(codec.open(hdrFlip).isFailure, isTrue);
    final tagFlip = Uint8List.fromList(sealed.valueOrNull!);
    tagFlip[tagFlip.length - 1] ^= 1;
    expect(codec.open(tagFlip).isFailure, isTrue);
  });

  test('server QuicTlsHandshake.start fails closed', () async {
    final r = await QuicTlsHandshake.server(crypto: crypto).start();
    expect(r.isFailure, isTrue);
    expect(r.errorOrNull!.code, PqTransportErrorCode.unexpectedMessage);
  });

  test(
    'Initial packets carry a live TLS-in-QUIC handshake (HP + CRYPTO)',
    () async {
      final identity = PqTlsServerIdentity.generate(crypto);
      final client = QuicTlsHandshake.client(crypto: crypto);
      final server = QuicTlsHandshake.server(
        crypto: crypto,
        identity: identity,
      );
      final dcid = crypto.randomBytes(8);
      final scid = crypto.randomBytes(8);
      final secrets = QuicInitialSecrets.derive(
        crypto: crypto,
        destinationConnectionId: dcid,
      );
      final clientSeal = QuicInitialCodec(crypto: crypto, keys: secrets.client);
      final clientOpen = QuicInitialCodec(crypto: crypto, keys: secrets.server);
      final serverSeal = QuicInitialCodec(crypto: crypto, keys: secrets.server);
      final serverOpen = QuicInitialCodec(crypto: crypto, keys: secrets.client);

      Future<List<QuicCryptoFrame>> send({
        required QuicInitialCodec seal,
        required QuicInitialCodec open,
        required List<QuicCryptoFrame> frames,
        required int pn,
        required bool pad,
      }) async {
        final payload = BytesBuilder(copy: false);
        for (final f in frames) {
          payload.add(f.encode());
        }
        var body = payload.takeBytes();
        if (pad && body.length < quicMinClientInitialUdpBytes) {
          body = concatBytes([
            body,
            Uint8List(quicMinClientInitialUdpBytes - body.length),
          ]);
        }
        final pkt = seal.protect(
          dcid: dcid,
          scid: scid,
          packetNumber: pn,
          payload: body,
        );
        expect(pkt.isSuccess, isTrue, reason: '${pkt.errorOrNull}');
        if (pad) {
          expect(
            pkt.valueOrNull!.length,
            greaterThanOrEqualTo(quicMinClientInitialUdpBytes),
          );
        }
        final opened = open.open(pkt.valueOrNull!);
        expect(opened.isSuccess, isTrue, reason: '${opened.errorOrNull}');
        expect(opened.valueOrNull!.packetNumber, pn);
        final parsed = decodeQuicPayload(opened.valueOrNull!.payload);
        expect(parsed.isSuccess, isTrue, reason: '${parsed.errorOrNull}');
        return parsed.valueOrNull!.crypto;
      }

      final ch = await client.start();
      expect(ch.isSuccess, isTrue, reason: '${ch.errorOrNull}');
      final toServer = await send(
        seal: clientSeal,
        open: serverOpen,
        frames: ch.valueOrNull!,
        pn: 0,
        pad: true,
      );
      expect(toServer, hasLength(1));
      final shFlight = await server.ingest(toServer.single);
      expect(shFlight.isSuccess, isTrue, reason: '${shFlight.errorOrNull}');
      expect(shFlight.valueOrNull, hasLength(2));
      final toClient = await send(
        seal: serverSeal,
        open: clientOpen,
        frames: shFlight.valueOrNull!,
        pn: 0,
        pad: false,
      );
      expect(toClient, hasLength(2));
      var last = await client.ingest(toClient.first);
      expect(last.isSuccess, isTrue, reason: '${last.errorOrNull}');
      last = await client.ingest(toClient.last);
      expect(last.isSuccess, isTrue, reason: '${last.errorOrNull}');
      expect(last.valueOrNull, hasLength(1));
      final fin = await send(
        seal: clientSeal,
        open: serverOpen,
        frames: last.valueOrNull!,
        pn: 1,
        pad: true,
      );
      final done = await server.ingest(fin.single);
      expect(done.isSuccess, isTrue, reason: '${done.errorOrNull}');
      expect(client.isComplete, isTrue);
      expect(server.isComplete, isTrue);
      final ctx = Uint8List(0);
      expect(
        client.exporterBytes('quic exporter', ctx, 32),
        server.exporterBytes('quic exporter', ctx, 32),
      );

      final cKeys = quicKeysFromTls(
        schedule: client.schedule,
        trafficSecret: client.schedule.clientApplicationTraffic,
      );
      final sKeys = quicKeysFromTls(
        schedule: server.schedule,
        trafficSecret: server.schedule.clientApplicationTraffic,
      );
      expect(cKeys.key, sKeys.key);
      expect(cKeys.iv, sKeys.iv);
      expect(cKeys.hp, sKeys.hp);
      final oneRttSend = QuicPacketCodec.fromKeys(crypto, cKeys);
      final oneRttRecv = QuicPacketCodec.fromKeys(crypto, sKeys);
      final appDcid = crypto.randomBytes(quicShortDcidBytes);
      final app = oneRttSend.protect(
        dcid: appDcid,
        packetNumber: 4,
        payload: Uint8List.fromList([quicFramePing]),
      );
      expect(app.isSuccess, isTrue, reason: '${app.errorOrNull}');
      final openedApp = oneRttRecv.open(app.valueOrNull!);
      expect(openedApp.isSuccess, isTrue, reason: '${openedApp.errorOrNull}');
      expect(openedApp.valueOrNull!.packetNumber, 4);
      expect(openedApp.valueOrNull!.payload, [quicFramePing]);
    },
  );

  test('SecP256r1MLKEM768 TLS-in-QUIC exporters match', () async {
    final identity = PqTlsServerIdentity.generate(crypto);
    const g = HybridGroup.secP256r1MlKem768;
    final client = QuicTlsHandshake.client(crypto: crypto, group: g);
    final server = QuicTlsHandshake.server(
      crypto: crypto,
      group: g,
      identity: identity,
    );
    final ch = await client.start();
    expect(ch.isSuccess, isTrue, reason: '${ch.errorOrNull}');
    final shFlight = await server.ingest(ch.valueOrNull!.single);
    expect(shFlight.isSuccess, isTrue, reason: '${shFlight.errorOrNull}');
    var last = await client.ingest(shFlight.valueOrNull!.first);
    expect(last.isSuccess, isTrue, reason: '${last.errorOrNull}');
    last = await client.ingest(shFlight.valueOrNull!.last);
    expect(last.isSuccess, isTrue, reason: '${last.errorOrNull}');
    final done = await server.ingest(last.valueOrNull!.single);
    expect(done.isSuccess, isTrue, reason: '${done.errorOrNull}');
    expect(client.isComplete, isTrue);
    expect(server.isComplete, isTrue);
    expect(
      client.exporterBytes('p256 quic', Uint8List(0), 32),
      server.exporterBytes('p256 quic', Uint8List(0), 32),
    );
  });

  test('RFC 9001 Appendix A.2 client Initial packet', () {
    final dcid = hex('8394c8f03e515708');
    final secrets = QuicInitialSecrets.derive(
      crypto: crypto,
      destinationConnectionId: dcid,
    );
    expect(secrets.client.hp, hex('9f50449e04a0e810283a1e9933adedd2'));
    final codec = QuicInitialCodec(crypto: crypto, keys: secrets.client);
    final cryptoFrame = hex(
      '060040f1010000ed0303ebf8fa56f12939b9584a3896472ec40bb863cfd3e868'
      '04fe3a47f06a2b69484c00000413011302010000c000000010000e00000b6578'
      '616d706c652e636f6dff01000100000a00080006001d00170018001000070005'
      '04616c706e000500050100000000003300260024001d00209370b2c9caa47fba'
      'baf4559fedba753de171fa71f50f1ce15d43e994ec74d748002b000302030400'
      '0d0010000e0403050306030203080408050806002d00020101001c0002400100'
      '3900320408ffffffffffffffff05048000ffff07048000ffff08011001048000'
      '75300901100f088394c8f03e51570806048000ffff',
    );
    const payloadBytes = 1162; // RFC 9001 A.2: 4-byte PN + frames + 16-byte tag
    expect(cryptoFrame.length, lessThan(payloadBytes));
    final payload = concatBytes([
      cryptoFrame,
      Uint8List(payloadBytes - cryptoFrame.length),
    ]);
    final sealed = codec.protect(
      dcid: dcid,
      scid: Uint8List(0),
      packetNumber: 2,
      payload: payload,
    );
    expect(sealed.isSuccess, isTrue, reason: '${sealed.errorOrNull}');
    final packet = sealed.valueOrNull!;
    expect(packet.length, quicMinClientInitialUdpBytes);
    expect(
      slice(packet, 0, 22),
      hex('c000000001088394c8f03e5157080000449e7b9aec34'),
    );
    expect(slice(packet, 22, 38), hex('d1b1c98dd7689fb8ec11d242b123dc9b'));
    expect(
      packet,
      hex(
        'c000000001088394c8f03e5157080000449e7b9aec34d1b1c98dd7689fb8ec11'
        'd242b123dc9bd8bab936b47d92ec356c0bab7df5976d27cd449f63300099f399'
        '1c260ec4c60d17b31f8429157bb35a1282a643a8d2262cad67500cadb8e7378c'
        '8eb7539ec4d4905fed1bee1fc8aafba17c750e2c7ace01e6005f80fcb7df6212'
        '30c83711b39343fa028cea7f7fb5ff89eac2308249a02252155e2347b63d58c5'
        '457afd84d05dfffdb20392844ae812154682e9cf012f9021a6f0be17ddd0c208'
        '4dce25ff9b06cde535d0f920a2db1bf362c23e596d11a4f5a6cf3948838a3aec'
        '4e15daf8500a6ef69ec4e3feb6b1d98e610ac8b7ec3faf6ad760b7bad1db4ba3'
        '485e8a94dc250ae3fdb41ed15fb6a8e5eba0fc3dd60bc8e30c5c4287e53805db'
        '059ae0648db2f64264ed5e39be2e20d82df566da8dd5998ccabdae053060ae6c'
        '7b4378e846d29f37ed7b4ea9ec5d82e7961b7f25a9323851f681d582363aa5f8'
        '9937f5a67258bf63ad6f1a0b1d96dbd4faddfcefc5266ba6611722395c906556'
        'be52afe3f565636ad1b17d508b73d8743eeb524be22b3dcbc2c7468d54119c74'
        '68449a13d8e3b95811a198f3491de3e7fe942b330407abf82a4ed7c1b311663a'
        'c69890f4157015853d91e923037c227a33cdd5ec281ca3f79c44546b9d90ca00'
        'f064c99e3dd97911d39fe9c5d0b23a229a234cb36186c4819e8b9c5927726632'
        '291d6a418211cc2962e20fe47feb3edf330f2c603a9d48c0fcb5699dbfe58964'
        '25c5bac4aee82e57a85aaf4e2513e4f05796b07ba2ee47d80506f8d2c25e50fd'
        '14de71e6c418559302f939b0e1abd576f279c4b2e0feb85c1f28ff18f58891ff'
        'ef132eef2fa09346aee33c28eb130ff28f5b766953334113211996d20011a198'
        'e3fc433f9f2541010ae17c1bf202580f6047472fb36857fe843b19f5984009dd'
        'c324044e847a4f4a0ab34f719595de37252d6235365e9b84392b061085349d73'
        '203a4a13e96f5432ec0fd4a1ee65accdd5e3904df54c1da510b0ff20dcc0c77f'
        'cb2c0e0eb605cb0504db87632cf3d8b4dae6e705769d1de354270123cb11450e'
        'fc60ac47683d7b8d0f811365565fd98c4c8eb936bcab8d069fc33bd801b03ade'
        'a2e1fbc5aa463d08ca19896d2bf59a071b851e6c239052172f296bfb5e724047'
        '90a2181014f3b94a4e97d117b438130368cc39dbb2d198065ae3986547926cd2'
        '162f40a29f0c3c8745c0f50fba3852e566d44575c29d39a03f0cda721984b6f4'
        '40591f355e12d439ff150aab7613499dbd49adabc8676eef023b15b65bfc5ca0'
        '6948109f23f350db82123535eb8a7433bdabcb909271a6ecbcb58b936a88cd4e'
        '8f2e6ff5800175f113253d8fa9ca8885c2f552e657dc603f252e1a8e308f76f0'
        'be79e2fb8f5d5fbbe2e30ecadd220723c8c0aea8078cdfcb3868263ff8f09400'
        '54da48781893a7e49ad5aff4af300cd804a6b6279ab3ff3afb64491c85194aab'
        '760d58a606654f9f4400e8b38591356fbf6425aca26dc85244259ff2b19c41b9'
        'f96f3ca9ec1dde434da7d2d392b905ddf3d1f9af93d1af5950bd493f5aa731b4'
        '056df31bd267b6b90a079831aaf579be0a39013137aac6d404f518cfd4684064'
        '7e78bfe706ca4cf5e9c5453e9f7cfd2b8b4c8d169a44e55c88d4a9a7f9474241'
        'e221af44860018ab0856972e194cd934',
      ),
    );
    final opened = codec.open(packet);
    expect(opened.isSuccess, isTrue, reason: '${opened.errorOrNull}');
    expect(opened.valueOrNull!.packetNumber, 2);
    expect(opened.valueOrNull!.payload, payload);
    final parsed = decodeQuicPayload(opened.valueOrNull!.payload);
    expect(parsed.isSuccess, isTrue, reason: '${parsed.errorOrNull}');
    expect(parsed.valueOrNull!.crypto, isNotEmpty);
    expect(parsed.valueOrNull!.crypto.first.offset, 0);
  });

  test('Initial 2-byte packet number HP round trip', () {
    final dcid = crypto.randomBytes(8);
    final secrets = QuicInitialSecrets.derive(
      crypto: crypto,
      destinationConnectionId: dcid,
    );
    final codec = QuicInitialCodec(crypto: crypto, keys: secrets.client);
    final payload = Uint8List.fromList([quicFramePing, 1, 2, 3, 4, 5, 6, 7, 8]);
    final sealed = codec.protect(
      dcid: dcid,
      scid: crypto.randomBytes(8),
      packetNumber: 2,
      payload: payload,
      packetNumberLength: 2,
    );
    expect(sealed.isSuccess, isTrue, reason: '${sealed.errorOrNull}');
    final opened = codec.open(sealed.valueOrNull!);
    expect(opened.isSuccess, isTrue, reason: '${opened.errorOrNull}');
    expect(opened.valueOrNull!.packetNumber, 2);
    expect(opened.valueOrNull!.payload, payload);
  });

  test('1-RTT 2-byte packet number HP round trip', () {
    final key = crypto.randomBytes(aeadKeyBytes);
    final iv = crypto.randomBytes(aeadNonceBytes);
    final hp = crypto.randomBytes(aeadKeyBytes);
    final codec = QuicPacketCodec(crypto: crypto, key: key, iv: iv, hpKey: hp);
    final dcid = crypto.randomBytes(quicShortDcidBytes);
    final payload = Uint8List.fromList([quicFramePing, 9, 9, 9, 9]);
    final sealed = codec.protect(
      dcid: dcid,
      packetNumber: 7,
      payload: payload,
      packetNumberLength: 2,
    );
    expect(sealed.isSuccess, isTrue, reason: '${sealed.errorOrNull}');
    final opened = codec.open(sealed.valueOrNull!);
    expect(opened.isSuccess, isTrue, reason: '${opened.errorOrNull}');
    expect(opened.valueOrNull!.packetNumber, 7);
    expect(opened.valueOrNull!.payload, payload);
  });

  test('illegal packet-number length fails closed', () {
    final dcid = crypto.randomBytes(8);
    final secrets = QuicInitialSecrets.derive(
      crypto: crypto,
      destinationConnectionId: dcid,
    );
    final codec = QuicInitialCodec(crypto: crypto, keys: secrets.client);
    expect(
      codec
          .protect(
            dcid: dcid,
            scid: Uint8List(0),
            packetNumber: 1,
            payload: Uint8List.fromList([quicFramePing]),
            packetNumberLength: 0,
          )
          .isFailure,
      isTrue,
    );
    expect(
      codec
          .protect(
            dcid: dcid,
            scid: Uint8List(0),
            packetNumber: 1,
            payload: Uint8List.fromList([quicFramePing]),
            packetNumberLength: 5,
          )
          .isFailure,
      isTrue,
    );
  });

  test('STREAM frames decode; ACK-ECN still fail closed', () {
    final stream = QuicStreamFrame(
      id: 0,
      offset: 0,
      data: Uint8List.fromList([1]),
    ).encode();
    final parsed = decodeQuicPayload(stream);
    expect(parsed.isSuccess, isTrue, reason: '${parsed.errorOrNull}');
    expect(parsed.valueOrNull!.streams.single.id, 0);
    expect(parsed.valueOrNull!.streams.single.data, [1]);
    expect(
      decodeQuicPayload(Uint8List.fromList([quicFrameAckEcn])).isFailure,
      isTrue,
    );
  });

  test('CRYPTO frames out of order still complete TLS-in-QUIC', () async {
    final identity = PqTlsServerIdentity.generate(crypto);
    final client = QuicTlsHandshake.client(crypto: crypto);
    final server = QuicTlsHandshake.server(crypto: crypto, identity: identity);
    final ch = await client.start();
    expect(ch.isSuccess, isTrue, reason: '${ch.errorOrNull}');
    final shFlight = await server.ingest(ch.valueOrNull!.single);
    expect(shFlight.isSuccess, isTrue, reason: '${shFlight.errorOrNull}');
    expect(shFlight.valueOrNull, hasLength(2));
    final sh = shFlight.valueOrNull!.first;
    final rest = shFlight.valueOrNull!.last;
    expect(rest.offset, sh.data.length);
    final early = await client.ingest(rest);
    expect(early.isSuccess, isTrue, reason: '${early.errorOrNull}');
    expect(early.valueOrNull, isEmpty);
    expect(client.isComplete, isFalse);
    final last = await client.ingest(sh);
    expect(last.isSuccess, isTrue, reason: '${last.errorOrNull}');
    expect(last.valueOrNull, hasLength(1));
    final done = await server.ingest(last.valueOrNull!.single);
    expect(done.isSuccess, isTrue, reason: '${done.errorOrNull}');
    expect(client.isComplete, isTrue);
    expect(server.isComplete, isTrue);
  });

  test('fragmented ClientHello CRYPTO frames reassemble', () async {
    final identity = PqTlsServerIdentity.generate(crypto);
    final client = QuicTlsHandshake.client(crypto: crypto);
    final server = QuicTlsHandshake.server(crypto: crypto, identity: identity);
    final ch = await client.start();
    expect(ch.isSuccess, isTrue, reason: '${ch.errorOrNull}');
    final data = ch.valueOrNull!.single.data;
    final mid = data.length ~/ 2;
    final first = QuicCryptoFrame(offset: 0, data: slice(data, 0, mid));
    final second = QuicCryptoFrame(
      offset: mid,
      data: slice(data, mid, data.length),
    );
    final gap = await server.ingest(first);
    expect(gap.isSuccess, isTrue, reason: '${gap.errorOrNull}');
    expect(gap.valueOrNull, isEmpty);
    final shFlight = await server.ingest(second);
    expect(shFlight.isSuccess, isTrue, reason: '${shFlight.errorOrNull}');
    expect(shFlight.valueOrNull, hasLength(2));
  });
}
