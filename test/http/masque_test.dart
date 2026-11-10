import 'dart:typed_data';

import 'package:pqtransport/pqtransport.dart';
import 'package:test/test.dart';

void main() {
  test('CONNECT-UDP target, datagram, and HTTP/1.1 upgrade', () {
    expect(
      connectUdpPath(targetHost: '2001:db8::42', targetPort: 443).valueOrNull,
      '/.well-known/masque/udp/2001%3Adb8%3A%3A42/443/',
    );
    expect(
      connectUdpPath(targetHost: 'example.com', targetPort: 0).isFailure,
      isTrue,
    );
    expect(
      connectUdpPath(targetHost: 'fe80::1%eth0', targetPort: 53).isFailure,
      isTrue,
    );
    expect(encodeProxyDatagram(0, Uint8List.fromList([0x68, 0x69])), [
      0x00,
      0x68,
      0x69,
    ]);
    final decoded = decodeProxyDatagram(Uint8List.fromList([0x00, 0x68, 0x69]));
    expect(decoded!.contextId, 0);
    expect(decoded.payload, [0x68, 0x69]);
    final request = connectUdpRequest(
      proxyHost: 'proxy.example',
      targetHost: 'example.com',
      targetPort: 53,
    );
    expect(request.valueOrNull!.protocol, 'connect-udp');
    expect(request.valueOrNull!.headers['capsule-protocol'], '?1');
    final upgrade = encodeHttp1Upgrade(
      host: 'proxy.example',
      path: '/.well-known/masque/udp/example.com/53/',
      protocol: 'connect-udp',
    );
    final text = String.fromCharCodes(upgrade);
    expect(text, contains('Upgrade: connect-udp\r\n'));
    expect(text, startsWith('GET '));
    final response = parseHttp1UpgradeResponse(
      Uint8List.fromList(
        'HTTP/1.1 200 OK\r\nCapsule-Protocol: ?1\r\nUpgrade: connect-udp\r\n\r\n'
            .codeUnits,
      ),
    );
    expect(http1UpgradeAccepted(response!, 'connect-udp'), isTrue);
  });

  test('CONNECT-IP capsules, routes, and the drop rules', () {
    final assign = encodeAddressAssign([
      AssignedAddress(
        requestId: 1,
        prefix: IpPrefix(
          version: 4,
          address: Uint8List.fromList([192, 0, 2, 11]),
          prefixLength: 32,
        ),
      ),
    ]);
    expect(assign.valueOrNull, [0x01, 0x04, 0xc0, 0x00, 0x02, 0x0b, 0x20]);
    final capsule = HttpCapsule(
      type: 0x01,
      value: assign.valueOrNull!,
    ).encode();
    expect(capsule, [0x01, 0x07, 0x01, 0x04, 0xc0, 0x00, 0x02, 0x0b, 0x20]);
    expect(encodeAddressRequest(const []).isFailure, isTrue);
    final routes = encodeRouteAdvertisement([
      IpRange(
        version: 4,
        start: Uint8List.fromList([0, 0, 0, 0]),
        end: Uint8List.fromList([255, 255, 255, 255]),
        protocol: 0,
      ),
    ]);
    expect(routes.isSuccess, isTrue);
    expect(
      encodeRouteAdvertisement([
        IpRange(
          version: 4,
          start: Uint8List.fromList([10, 0, 0, 0]),
          end: Uint8List.fromList([10, 255, 255, 255]),
          protocol: 0,
        ),
        IpRange(
          version: 4,
          start: Uint8List.fromList([10, 1, 0, 0]),
          end: Uint8List.fromList([10, 1, 255, 255]),
          protocol: 0,
        ),
      ]).isFailure,
      isTrue,
    );
    final policy = IpProxyPolicy()
      ..assign(assign.valueOrNull!)
      ..advertise(routes.valueOrNull!);
    final packet = Uint8List(20);
    packet[0] = 0x45;
    packet[9] = 17;
    packet.setRange(12, 16, [192, 0, 2, 11]);
    packet.setRange(16, 20, [198, 51, 100, 1]);
    expect(policy.allow(packet), isTrue);
    packet.setRange(12, 16, [192, 0, 2, 12]);
    expect(policy.allow(packet), isFalse);
    final path = connectIpPath(target: '*', ipProtocol: '*');
    expect(path.valueOrNull, '/.well-known/masque/ip/*/*/');
    final icmp = icmpPacketTooBig(packet, 1280);
    expect(icmp[0] >> 4, 4);
    expect(icmp[9], 1);
    expect(icmp[20], 3);
    expect(icmp[21], 4);
  });
}
