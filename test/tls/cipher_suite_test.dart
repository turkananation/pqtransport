import 'dart:typed_data';

import 'package:pqtransport/pqtransport.dart';
import 'package:test/test.dart';

void main() {
  final crypto = PqTransportCrypto();

  test('default live handshake selects IANA 0x1302', () async {
    final identity = PqTlsServerIdentity.generate(crypto);
    final client = PqTlsClient(crypto: crypto);
    final server = PqTlsServer(crypto: crypto, identity: identity);
    final ch = await client.startHandshake();
    final flight = await server.ingest(ch.valueOrNull!);
    expect(flight.isSuccess, isTrue, reason: '${flight.errorOrNull}');
    await client.ingest(flight.valueOrNull![0]);
    final fin = await client.ingest(flight.valueOrNull![1]);
    await server.ingest(fin.valueOrNull![0]);
    expect(client.isComplete, isTrue);
    expect(server.isComplete, isTrue);
    expect(client.cipherSuite, TlsCipherSuite.aes256GcmSha384);
    expect(server.cipherSuite, TlsCipherSuite.aes256GcmSha384);
    expect(client.cipherSuite.codepoint, tlsCipherAes256GcmSha384);
  });

  test('ChaCha-only offer selects 0x1303 and exporters match', () async {
    final identity = PqTlsServerIdentity.generate(crypto);
    final client = PqTlsClient(
      crypto: crypto,
      offeredCipherSuites: const [tlsCipherChaCha20Poly1305Sha256],
    );
    final server = PqTlsServer(crypto: crypto, identity: identity);
    final ch = await client.startHandshake();
    expect(ch.isSuccess, isTrue, reason: '${ch.errorOrNull}');
    final flight = await server.ingest(ch.valueOrNull!);
    expect(flight.isSuccess, isTrue, reason: '${flight.errorOrNull}');
    await client.ingest(flight.valueOrNull![0]);
    final fin = await client.ingest(flight.valueOrNull![1]);
    expect(fin.isSuccess, isTrue, reason: '${fin.errorOrNull}');
    await server.ingest(fin.valueOrNull![0]);
    expect(client.isComplete, isTrue);
    expect(server.isComplete, isTrue);
    expect(client.cipherSuite, TlsCipherSuite.chacha20Poly1305Sha256);
    expect(server.cipherSuite, TlsCipherSuite.chacha20Poly1305Sha256);
    final ctx = Uint8List.fromList([1, 2, 3]);
    expect(client.exporter('test', ctx, 32), server.exporter('test', ctx, 32));
  }, timeout: const Timeout(Duration(seconds: 30)));

  test('server prefers 0x1302 when client offers both', () async {
    final identity = PqTlsServerIdentity.generate(crypto);
    final client = PqTlsClient(
      crypto: crypto,
      offeredCipherSuites: tlsDefaultOfferedCipherSuites,
    );
    final server = PqTlsServer(crypto: crypto, identity: identity);
    final ch = (await client.startHandshake()).valueOrNull!;
    final hello = ClientHello.decode(
      decodePlainRecord(ch).valueOrNull!.payload,
    );
    expect(hello.valueOrNull!.cipherSuites, tlsDefaultOfferedCipherSuites);
    final flight = await server.ingest(ch);
    final sh = ServerHello.decode(
      decodePlainRecord(flight.valueOrNull![0]).valueOrNull!.payload,
    );
    expect(sh.valueOrNull!.cipherSuite, tlsCipherAes256GcmSha384);
  });

  test('ChaCha AEAD round-trip; bit-flip fails (OPEN-13)', () {
    final key = crypto.randomBytes(aeadKeyBytes);
    final nonce = crypto.randomBytes(aeadNonceBytes);
    final pt = Uint8List.fromList([1, 2, 3, 4]);
    final ct = crypto.aeadSeal(
      key: key,
      nonce: nonce,
      plaintext: pt,
      aead: TransportAead.chacha20Poly1305,
    );
    expect(
      crypto.aeadOpen(
        key: key,
        nonce: nonce,
        ciphertextWithTag: ct,
        aead: TransportAead.chacha20Poly1305,
      ),
      pt,
    );
    final flipped = Uint8List.fromList(ct)..[0] ^= 1;
    expect(
      () => crypto.aeadOpen(
        key: key,
        nonce: nonce,
        ciphertextWithTag: flipped,
        aead: TransportAead.chacha20Poly1305,
      ),
      throwsA(isA<Object>()),
    );
  });

  test('SHA-384 Extract/Expand is not SHA-256 (OPEN-02)', () {
    final salt = Uint8List(sha384HashBytes);
    final ikm = Uint8List.fromList(List<int>.filled(22, 0x0b));
    final sha384 = crypto.hkdfExtractSha384(salt, ikm);
    final sha256 = crypto.hkdfExtract(Uint8List(sha256HashBytes), ikm);
    expect(sha384.length, sha384HashBytes);
    expect(sha256.length, sha256HashBytes);
    expect(sha384.sublist(0, 32), isNot(equals(sha256)));
    final info = Uint8List.fromList([1, 2, 3]);
    expect(crypto.hkdfExpandSha384(sha384, info, 16).length, 16);
    expect(
      crypto.hkdfSha384(ikm: ikm, salt: salt, info: info, length: 32).length,
      32,
    );
  });

  test('default ClientHello offers 0x1302 then 0x1303 on every runtime', () {
    expect(crypto.supportsChaCha20Poly1305, isTrue);
    expect(
      PqTlsClient(crypto: crypto).offeredCipherSuites,
      tlsDefaultOfferedCipherSuites,
    );
    expect(
      TlsCipherSuite.select(const [tlsCipherChaCha20Poly1305Sha256]),
      TlsCipherSuite.chacha20Poly1305Sha256,
    );
    expect(
      TlsCipherSuite.select(tlsDefaultOfferedCipherSuites),
      TlsCipherSuite.aes256GcmSha384,
    );
    expect(TlsCipherSuite.select(const [0xFF00]), isNull);
  });
}
