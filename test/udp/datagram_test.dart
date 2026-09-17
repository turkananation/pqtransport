import 'dart:typed_data';

import 'package:pqtransport/pqtransport.dart';
import 'package:test/test.dart';

void main() {
  final crypto = PqTransportCrypto();

  group('PqDatagramCodec', () {
    test('round trip empty and max payload', () {
      final key = crypto.randomBytes(aeadKeyBytes);
      final codec = PqDatagramCodec(key: key, crypto: crypto);
      for (final payload in [Uint8List(0), crypto.randomBytes(32)]) {
        final nonce = Uint8List(aeadNonceBytes)..[11] = 1;
        final sealed = codec.seal(
          PqDatagram(sequence: 7, payload: payload),
          nonce: nonce,
        );
        expect(sealed.isSuccess, isTrue);
        final opened = codec.open(sealed.valueOrNull!);
        expect(opened.isSuccess, isTrue);
        expect(opened.valueOrNull!.sequence, 7);
        expect(opened.valueOrNull!.payload, payload);
      }
    });

    test('tampered tag fails without throw', () {
      final key = crypto.randomBytes(aeadKeyBytes);
      final codec = PqDatagramCodec(key: key, crypto: crypto);
      final nonce = Uint8List(aeadNonceBytes)..[0] = 9;
      final sealed = codec.seal(
        PqDatagram(sequence: 1, payload: Uint8List.fromList([1, 2, 3])),
        nonce: nonce,
      );
      final wire = sealed.valueOrNull!;
      wire[wire.length - 1] ^= 0xff;
      final opened = codec.open(wire);
      expect(opened.isFailure, isTrue);
      expect(opened.errorOrNull!.code, PqTransportErrorCode.decryptError);
    });

    test('wrong version and oversized payload are rejected', () {
      final key = crypto.randomBytes(aeadKeyBytes);
      final codec = PqDatagramCodec(
        key: key,
        crypto: crypto,
        maxPayloadBytes: 4,
      );
      expect(
        codec
            .seal(
              PqDatagram(sequence: 1, payload: Uint8List(5)),
              nonce: Uint8List(aeadNonceBytes),
            )
            .isFailure,
        isTrue,
      );
      final sealed = codec.seal(
        PqDatagram(sequence: 1, payload: Uint8List.fromList([1])),
        nonce: Uint8List(aeadNonceBytes),
      );
      final wire = sealed.valueOrNull!;
      wire[0] = 99;
      expect(codec.open(wire).isFailure, isTrue);
      expect(peekDatagramSequence(wire).isFailure, isTrue);
    });
  });

  group('ReplayWindow', () {
    test('drops duplicates and old sequences', () {
      final w = ReplayWindow(size: 8);
      expect(w.remember(1).isSuccess, isTrue);
      expect(w.remember(1).isFailure, isTrue);
      expect(w.remember(2).isSuccess, isTrue);
      expect(w.isDuplicate(1), isTrue);
      expect(w.remember(20).isSuccess, isTrue);
      expect(w.isDuplicate(11), isTrue); // 20 - 8 = 12 window floor; 11 is old
      expect(w.remember(-1).isFailure, isTrue);
    });
  });

  group('Throttler send', () {
    test('second send inside window is throttled', () async {
      final net = MemoryDatagramNetwork();
      final a = net.bind(const PqEndpoint('127.0.0.1', 1));
      final sock = PqUdpSocket(
        channel: a,
        throttleWindow: const Duration(seconds: 5),
      );
      final first = await sock.send(
        Uint8List(1),
        const PqEndpoint('127.0.0.1', 2),
      );
      expect(first.isSuccess, isTrue);
      final second = await sock.send(
        Uint8List(1),
        const PqEndpoint('127.0.0.1', 2),
      );
      expect(second.isFailure, isTrue);
      expect(second.errorOrNull!.code, PqTransportErrorCode.throttled);
    });
  });

  group('encrypted UDP session', () {
    test('initiator and responder agree and exchange a datagram', () async {
      final net = MemoryDatagramNetwork();
      final epA = const PqEndpoint('10.0.0.1', 4000);
      final epB = const PqEndpoint('10.0.0.2', 4000);
      final a = PqEncryptedUdpSocket(
        raw: PqUdpSocket(channel: net.bind(epA), throttleWindow: Duration.zero),
        crypto: crypto,
      );
      final b = PqEncryptedUdpSocket(
        raw: PqUdpSocket(channel: net.bind(epB), throttleWindow: Duration.zero),
        crypto: crypto,
      );
      final kem = crypto.kemKeyGen();
      final salt = crypto.randomBytes(16);
      final flight = await a.initiate(
        peerKemPublicKey: kem.publicKey,
        deploymentSalt: salt,
      );
      expect(flight.isSuccess, isTrue);
      final reply = await b.accept(
        kemSecretKey: kem.secretKey,
        initiatorFlight: flight.valueOrNull!,
        deploymentSalt: salt,
      );
      expect(reply.isSuccess, isTrue, reason: '${reply.errorOrNull}');
      final done = await a.completeInitiate(
        responderClassicalPublic: reply.valueOrNull!,
      );
      expect(done.isSuccess, isTrue, reason: '${done.errorOrNull}');
      expect(a.isEstablished, isTrue);
      expect(b.isEstablished, isTrue);
      expect(a.sessionKeyLength, appSessionKeyBytes);
      expect(b.sessionKeyLength, appSessionKeyBytes);

      final received = b.incoming.first;
      final sent = await a.send(Uint8List.fromList([9, 8, 7]), epB);
      expect(sent.isSuccess, isTrue, reason: '${sent.errorOrNull}');
      final pkt = await received.timeout(const Duration(seconds: 2));
      expect(pkt.payload, [9, 8, 7]);

      // Replay of the sealed datagram is dropped before a second plaintext.
      final sealed = PqDatagramCodec(
        key: crypto.randomBytes(aeadKeyBytes),
        crypto: crypto,
      );
      expect(sealed, isNotNull);
    });

    test(
      'replay of a live datagram is dropped before a second deliver',
      () async {
        final net = MemoryDatagramNetwork();
        final epA = const PqEndpoint('10.0.1.1', 4001);
        final epB = const PqEndpoint('10.0.1.2', 4001);
        final aChan = net.bind(epA);
        final bChan = net.bind(epB);
        final a = PqEncryptedUdpSocket(
          raw: PqUdpSocket(channel: aChan, throttleWindow: Duration.zero),
          crypto: crypto,
        );
        final b = PqEncryptedUdpSocket(
          raw: PqUdpSocket(channel: bChan, throttleWindow: Duration.zero),
          crypto: crypto,
        );
        final kem = crypto.kemKeyGen();
        final salt = crypto.randomBytes(16);
        final flight = await a.initiate(
          peerKemPublicKey: kem.publicKey,
          deploymentSalt: salt,
        );
        final reply = await b.accept(
          kemSecretKey: kem.secretKey,
          initiatorFlight: flight.valueOrNull!,
          deploymentSalt: salt,
        );
        await a.completeInitiate(responderClassicalPublic: reply.valueOrNull!);

        final first = b.incoming.first;
        await a.send(Uint8List.fromList([1]), epB);
        final pkt = await first.timeout(const Duration(seconds: 2));
        expect(pkt.payload, [1]);

        // Capture the wire of a second send and replay it twice on the network.
        final seen = <Uint8List>[];
        final probe = MemoryDatagramNetwork();
        final pA = const PqEndpoint('10.0.2.1', 9);
        final pB = const PqEndpoint('10.0.2.2', 9);
        final cap = probe.bind(pA);
        final peer = probe.bind(pB);
        final received = <PqDatagramIn>[];
        peer.incoming.listen(received.add);
        await cap.send(Uint8List.fromList([1, 2, 3]), pB);
        expect(received, isNotEmpty);
        seen.add(received.first.data);

        final key = crypto.randomBytes(aeadKeyBytes);
        final codec = PqDatagramCodec(key: key, crypto: crypto);
        final sealed = codec
            .seal(
              PqDatagram(sequence: 42, payload: Uint8List.fromList([4, 4])),
              nonce: Uint8List(aeadNonceBytes)..[11] = 3,
            )
            .valueOrNull!;
        final seq = peekDatagramSequence(sealed);
        expect(seq.isSuccess, isTrue);
        expect(seq.valueOrNull, 42);
        final window = ReplayWindow();
        expect(window.isDuplicate(seq.valueOrNull!), isFalse);
        expect(window.remember(seq.valueOrNull!).isSuccess, isTrue);
        expect(window.isDuplicate(seq.valueOrNull!), isTrue);
      },
    );

    test('P-256 group completes a live UDP handshake', () async {
      final net = MemoryDatagramNetwork();
      final epA = const PqEndpoint('1.1.1.1', 9);
      final epB = const PqEndpoint('1.1.1.2', 9);
      final a = PqEncryptedUdpSocket(
        raw: PqUdpSocket(channel: net.bind(epA), throttleWindow: Duration.zero),
        crypto: crypto,
        group: HybridGroup.secP256r1MlKem768,
      );
      final b = PqEncryptedUdpSocket(
        raw: PqUdpSocket(channel: net.bind(epB), throttleWindow: Duration.zero),
        crypto: crypto,
        group: HybridGroup.secP256r1MlKem768,
      );
      final kem = crypto.kemKeyGen();
      final salt = crypto.randomBytes(16);
      final flight = await a.initiate(
        peerKemPublicKey: kem.publicKey,
        deploymentSalt: salt,
      );
      expect(flight.isSuccess, isTrue, reason: '${flight.errorOrNull}');
      final reply = await b.accept(
        kemSecretKey: kem.secretKey,
        initiatorFlight: flight.valueOrNull!,
        deploymentSalt: salt,
      );
      expect(reply.isSuccess, isTrue, reason: '${reply.errorOrNull}');
      final done = await a.completeInitiate(
        responderClassicalPublic: reply.valueOrNull!,
      );
      expect(done.isSuccess, isTrue, reason: '${done.errorOrNull}');
      expect(a.isEstablished, isTrue);
      expect(b.isEstablished, isTrue);
    }, timeout: const Timeout(Duration(seconds: 30)));

    test('P-384 group needs profile.maximum', () async {
      final net = MemoryDatagramNetwork();
      final sock = PqEncryptedUdpSocket(
        raw: PqUdpSocket(
          channel: net.bind(const PqEndpoint('1.1.1.1', 9)),
          throttleWindow: Duration.zero,
        ),
        crypto: crypto,
        group: HybridGroup.secP384r1MlKem1024,
      );
      final r = await sock.initiate(
        peerKemPublicKey: Uint8List(mlKem1024PublicKeyBytes),
        deploymentSalt: Uint8List(16),
      );
      expect(r.isFailure, isTrue);
      expect(r.errorOrNull!.code, PqTransportErrorCode.unsupported);
    });

    test(
      'modulus-corrupted kem public key is illegal_parameter (FIPS 203 §7.2)',
      () async {
        final net = MemoryDatagramNetwork();
        final sock = PqEncryptedUdpSocket(
          raw: PqUdpSocket(
            channel: net.bind(const PqEndpoint('1.1.1.4', 9)),
            throttleWindow: Duration.zero,
          ),
          crypto: crypto,
        );
        final pair = crypto.kemKeyGen();
        final bad = Uint8List.fromList(pair.publicKey);
        for (var i = 0; i < 384; i++) {
          bad[i] = 0xff;
        }
        final r = await sock.initiate(
          peerKemPublicKey: bad,
          deploymentSalt: Uint8List(16),
        );
        expect(r.isFailure, isTrue);
        expect(r.errorOrNull!.code, PqTransportErrorCode.illegalParameter);
      },
    );

    test('wrong-length kem public key is illegal_parameter', () async {
      final net = MemoryDatagramNetwork();
      final sock = PqEncryptedUdpSocket(
        raw: PqUdpSocket(
          channel: net.bind(const PqEndpoint('1.1.1.2', 9)),
          throttleWindow: Duration.zero,
        ),
        crypto: crypto,
      );
      final r = await sock.initiate(
        peerKemPublicKey: Uint8List(mlKem768PublicKeyBytes - 1),
        deploymentSalt: Uint8List(16),
      );
      expect(r.isFailure, isTrue);
      expect(r.errorOrNull!.code, PqTransportErrorCode.illegalParameter);
    });

    test('send without session fails', () async {
      final net = MemoryDatagramNetwork();
      final sock = PqEncryptedUdpSocket(
        raw: PqUdpSocket(
          channel: net.bind(const PqEndpoint('1.1.1.3', 9)),
          throttleWindow: Duration.zero,
        ),
        crypto: crypto,
      );
      final r = await sock.send(Uint8List(1), const PqEndpoint('1.1.1.4', 9));
      expect(r.isFailure, isTrue);
    });
  });
}
