import 'dart:typed_data';

import 'package:pqtransport/pqtransport.dart';
import 'package:test/test.dart';

void main() {
  test('probe announce browse', () async {
    final net = MemoryDatagramNetwork();
    final srvEp = const PqEndpoint('10.1.0.1', mdnsPort);
    final cliEp = const PqEndpoint('10.1.0.2', mdnsPort);
    final server = PqMdnsServer(channel: net.bind(srvEp), local: srvEp);
    final client = PqMdnsClient(channel: net.bind(cliEp));
    expect(server.beginProbe('foo._pq._tcp.local.').isSuccess, isTrue);
    expect(server.completeProbe(collision: false).isSuccess, isTrue);
    expect(server.completeProbe(collision: false).isSuccess, isTrue);
    expect(server.state, MdnsState.announcing);
    final added = client.bus.on<MdnsServiceEvent>().first;
    await client.browse();
    final rr = DnsA(
      name: 'foo._pq._tcp.local.',
      address: Uint8List.fromList([10, 1, 0, 1]),
    );
    final ann = await server.announce(rr);
    expect(ann.isSuccess, isTrue, reason: '${ann.errorOrNull}');
    final ev = await added.timeout(const Duration(seconds: 2));
    expect(ev.name, 'foo._pq._tcp.local.');
  });

  test('ML-DSA-65 signed TXT verifies; mutation fails', () {
    final crypto = PqTransportCrypto();
    final kp = crypto.mlDsaKeyGen();
    final signed = signTxt(
      crypto: crypto,
      secretKey: kp.secretKey,
      name: 'svc.local.',
      body: ['path=/', 'tls=1'],
    );
    expect(signed.isSuccess, isTrue);
    expect(
      verifyTxt(
        crypto: crypto,
        publicKey: kp.publicKey,
        txt: signed.valueOrNull!,
      ).isSuccess,
      isTrue,
    );
    final mutated = DnsTxt(
      name: 'svc.local.',
      strings: [
        ...signed.valueOrNull!.strings.take(2),
        '${signed.valueOrNull!.strings.last.substring(0, 10)}AAAA',
      ],
    );
    expect(
      verifyTxt(
        crypto: crypto,
        publicKey: kp.publicKey,
        txt: mutated,
      ).isFailure,
      isTrue,
    );
  });

  test('illegal mdns event fails closed', () {
    final m = mdnsMachine();
    expect(m.trigger(MdnsEvent.announce).isFailure, isTrue);
    m.trigger(MdnsEvent.fatal);
    expect(m.currentState, MdnsState.failed);
  });
}
