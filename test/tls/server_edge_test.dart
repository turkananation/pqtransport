import 'dart:typed_data';

import 'package:pqforge/pqforge.dart';
import 'package:pqtransport/pqtransport.dart';
import 'package:test/test.dart';

void main() {
  final crypto = PqTransportCrypto();

  test(
    'compatible change_cipher_spec is ignored, then Finished completes',
    () async {
      final client = PqTlsClient(crypto: crypto);
      final server = PqTlsServer(crypto: crypto);
      final hello = await client.startHandshake();
      expect(hello.isSuccess, isTrue, reason: '${hello.errorOrNull}');
      final flight = await server.ingest(hello.valueOrNull!);
      expect(flight.isSuccess, isTrue, reason: '${flight.errorOrNull}');
      final sh = await client.ingest(flight.valueOrNull![0]);
      expect(sh.isSuccess, isTrue, reason: '${sh.errorOrNull}');
      final fin = await client.ingest(flight.valueOrNull![1]);
      expect(fin.isSuccess, isTrue, reason: '${fin.errorOrNull}');

      final ignored = await server.ingest(_ccs(const [1]));
      expect(ignored.isSuccess, isTrue, reason: '${ignored.errorOrNull}');
      expect(ignored.valueOrNull, isEmpty);
      expect(server.state, TlsState.serverHelloSent);

      final done = await server.ingest(fin.valueOrNull!.single);
      expect(done.isSuccess, isTrue, reason: '${done.errorOrNull}');
      expect(server.isComplete, isTrue);
      expect(client.isComplete, isTrue);
    },
  );

  test(
    'change_cipher_spec between ClientHello fragments is not transcript',
    () async {
      final client = PqTlsClient(crypto: crypto);
      final server = PqTlsServer(crypto: crypto);
      final hello = (await client.startHandshake()).valueOrNull!;
      final payload = unwrapHandshake(hello, quic: false).valueOrNull!;
      final mid = payload.length ~/ 2;
      final first = await server.ingest(
        wrapHandshake(Uint8List.sublistView(payload, 0, mid), quic: false),
      );
      expect(first.isSuccess, isTrue, reason: '${first.errorOrNull}');
      expect(first.valueOrNull, isEmpty);
      expect(server.state, TlsState.waitClientHello);

      final between = await server.ingest(_ccs(const [1]));
      expect(between.isSuccess, isTrue, reason: '${between.errorOrNull}');
      expect(server.state, TlsState.waitClientHello);

      final second = await server.ingest(
        wrapHandshake(Uint8List.sublistView(payload, mid), quic: false),
      );
      expect(second.isSuccess, isTrue, reason: '${second.errorOrNull}');
      expect(second.valueOrNull, hasLength(2));
      expect(server.state, TlsState.serverHelloSent);
    },
  );

  test('malformed change_cipher_spec is fatal', () async {
    final server = PqTlsServer(crypto: crypto);
    final bad = await server.ingest(_ccs(const [0]));
    expect(bad.isFailure, isTrue);
    expect(bad.errorOrNull!.message, contains('change_cipher_spec'));
    expect(server.state, TlsState.failed);

    final later = PqTlsServer(crypto: crypto);
    final hello = await PqTlsClient(crypto: crypto).startHandshake();
    await later.ingest(hello.valueOrNull!);
    final extra = await later.ingest(_ccs(const [1, 1]));
    expect(extra.isFailure, isTrue);
    expect(later.state, TlsState.failed);
    expect(later.isComplete, isFalse);
  });

  test(
    'server picks its group when the first key share is another hybrid',
    () async {
      final x = HybridGroup.x25519MlKem768;
      final p = HybridGroup.secP256r1MlKem768;
      final pShare = await _realShare(crypto, p);
      final xShare = await _realShare(crypto, x);
      final hello = ClientHello(
        random: _random(1),
        group: p.named,
        share: pShare,
        keyShares: [
          (group: p.named, share: pShare),
          (group: x.named, share: xShare),
        ],
        certificateTypes: const [TlsCertificateType.x509],
        signatureSchemes: const [tlsSignatureMldsa65],
      );
      final decoded = ClientHello.decode(hello.encode());
      expect(decoded.isSuccess, isTrue, reason: '${decoded.errorOrNull}');
      expect(decoded.valueOrNull!.group, p.named);
      expect(decoded.valueOrNull!.offeredKeyShares, hasLength(2));

      final server = PqTlsServer(
        crypto: crypto,
        group: x,
        identity: _leaf(crypto),
      );
      final flight = await server.ingest(
        wrapHandshake(hello.encode(), quic: false),
      );
      expect(flight.isSuccess, isTrue, reason: '${flight.errorOrNull}');
      expect(flight.valueOrNull, hasLength(2));
      final sh = ServerHello.decode(
        unwrapHandshake(flight.valueOrNull![0], quic: false).valueOrNull!,
      );
      expect(sh.valueOrNull!.group, x.named);
      expect(server.state, TlsState.serverHelloSent);
    },
    timeout: const Timeout(Duration(seconds: 45)),
  );

  test(
    'unknown X448 key share is skipped when a hybrid share was offered',
    () async {
      const x448 = 0x001e;
      final group = HybridGroup.x25519MlKem768;
      final share = await _realShare(crypto, group);
      final hello = ClientHello(
        random: _random(2),
        group: group.named,
        share: share,
        ignoredKeyShareGroups: const [x448],
        supportedGroups: [x448, group.codepoint],
        certificateTypes: const [TlsCertificateType.x509],
        signatureSchemes: const [tlsSignatureMldsa65],
      );
      final decoded = ClientHello.decode(hello.encode());
      expect(decoded.isSuccess, isTrue, reason: '${decoded.errorOrNull}');
      expect(decoded.valueOrNull!.offeredKeyShares, hasLength(1));
      expect(decoded.valueOrNull!.group, group.named);
      expect(decoded.valueOrNull!.supportedGroups, contains(x448));

      final server = PqTlsServer(crypto: crypto, identity: _leaf(crypto));
      final flight = await server.ingest(
        wrapHandshake(hello.encode(), quic: false),
      );
      expect(flight.isSuccess, isTrue, reason: '${flight.errorOrNull}');
      expect(flight.valueOrNull, hasLength(2));
    },
  );

  test('duplicate key_share is a decode error', () {
    final group = HybridGroup.x25519MlKem768;
    final share = Uint8List(group.clientShareBytes)..[0] = 1;
    final hello = ClientHello(
      random: _random(3),
      group: group.named,
      share: share,
      keyShares: [
        (group: group.named, share: share),
        (group: group.named, share: share),
      ],
    );
    final decoded = ClientHello.decode(hello.encode());
    expect(decoded.isFailure, isTrue);
    expect(decoded.errorOrNull!.code, PqTransportErrorCode.decodeFailure);
    expect(decoded.errorOrNull!.message, contains('duplicate key_share'));
  });

  test('key share absent from supported_groups is illegal_parameter', () {
    final group = HybridGroup.x25519MlKem768;
    final hello = ClientHello(
      random: _random(4),
      group: group.named,
      share: Uint8List(group.clientShareBytes),
      supportedGroups: const [0x001d],
    );
    final decoded = ClientHello.decode(hello.encode());
    expect(decoded.isFailure, isTrue);
    expect(decoded.errorOrNull!.code, PqTransportErrorCode.illegalParameter);
    expect(decoded.errorOrNull!.alert, tlsAlertIllegalParameter);
  });

  test('ClientHello split across two records is reassembled', () async {
    final client = PqTlsClient(crypto: crypto);
    final server = PqTlsServer(crypto: crypto);
    final hello = (await client.startHandshake()).valueOrNull!;
    final payload = unwrapHandshake(hello, quic: false).valueOrNull!;
    expect(payload.length, greaterThan(8));
    final mid = 5;
    final first = await server.ingest(
      wrapHandshake(Uint8List.sublistView(payload, 0, mid), quic: false),
    );
    expect(first.isSuccess, isTrue, reason: '${first.errorOrNull}');
    expect(first.valueOrNull, isEmpty);
    expect(server.isComplete, isFalse);
    expect(server.state, TlsState.waitClientHello);

    final second = await server.ingest(
      wrapHandshake(Uint8List.sublistView(payload, mid), quic: false),
    );
    expect(second.isSuccess, isTrue, reason: '${second.errorOrNull}');
    expect(second.valueOrNull, hasLength(2));
    expect(server.state, TlsState.serverHelloSent);
  });
}

Uint8List _ccs(List<int> payload) => encodePlainRecord(
  TlsRecord(
    type: tlsContentChangeCipherSpec,
    payload: Uint8List.fromList(payload),
  ),
);

Uint8List _random(int tag) => Uint8List(handshakeRandomBytes)..[0] = tag;

Future<Uint8List> _realShare(
  PqTransportCrypto crypto,
  HybridGroup group,
) async {
  final kem = crypto.kemKeyGen();
  final classical = await crypto.classicalKeyGen(group);
  final encoded = encodeClientShare(
    HybridClientShare(
      group: group,
      kemEncapsulationKey: kem.publicKey,
      classicalShare: classical.publicKey,
    ),
  );
  expect(encoded.isSuccess, isTrue, reason: '${encoded.errorOrNull}');
  return encoded.valueOrNull!;
}

PqTlsServerIdentity _leaf(PqTransportCrypto crypto) {
  final keys = crypto.mlDsaKeyGen();
  final notBefore = DateTime.utc(2026, 1, 1);
  final notAfter = DateTime.utc(2027, 1, 1);
  final leafKey = PqX509MlDsaKey(PqX509Algorithm.mlDsa65, keys.publicKey);
  final der = PqX509.mintLeaf(
    subject: PqX509Name.commonName('localhost'),
    publicKey: leafKey,
    algorithm: PqX509Algorithm.mlDsa65,
    sign: (tbs) => crypto.mlDsaSign(secretKey: keys.secretKey, message: tbs),
    notBefore: notBefore,
    notAfter: notAfter,
    serial: Uint8List.fromList([1]),
    subjectAltNames: const [PqX509DnsName('localhost')],
  );
  return PqTlsServerIdentity.x509(
    leafKey: leafKey,
    sign: (content) =>
        crypto.mlDsaSign(secretKey: keys.secretKey, message: content),
    chain: [der],
    certificateDnsName: 'localhost',
  );
}
