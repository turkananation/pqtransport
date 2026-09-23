@TestOn('vm')
library;

import 'dart:io';
import 'dart:typed_data';

import 'package:pqtransport/pqtransport_io.dart';
import 'package:test/test.dart';

void main() {
  test('IoDatagramChannel bind/send/receive/close', () async {
    final a = await IoDatagramChannel.bind(InternetAddress.loopbackIPv4, 0);
    final b = await IoDatagramChannel.bind(InternetAddress.loopbackIPv4, 0);
    final received = b.incoming.first;
    final sent = await a.send(
      Uint8List.fromList([1, 2, 3]),
      PqEndpoint(b.address.address, b.port),
    );
    expect(sent.isSuccess, isTrue);
    final pkt = await received.timeout(const Duration(seconds: 2));
    expect(pkt.data, [1, 2, 3]);
    await a.close();
    expect(a.isClosed, isTrue);
    final after = await a.send(
      Uint8List.fromList([9]),
      PqEndpoint(b.address.address, b.port),
    );
    expect(after.isFailure, isTrue);
    await b.close();
  });

  test(
    'OPEN-09 IPv4 joinMulticast loopback delivers to the joined peer',
    () async {
      final a = await IoDatagramChannel.bind(InternetAddress.anyIPv4, 0);
      final b = await IoDatagramChannel.bind(InternetAddress.anyIPv4, 0);
      addTearDown(() async {
        await a.close();
        await b.close();
      });
      final group = PqEndpoint(mdnsIpv4Group, b.port);
      expect((await a.joinMulticast(group)).isSuccess, isTrue);
      expect((await b.joinMulticast(group)).isSuccess, isTrue);
      final got = b.incoming.first;
      final sent = await a.send(Uint8List.fromList([9, 9, 9]), group);
      expect(sent.isSuccess, isTrue, reason: '${sent.errorOrNull}');
      final pkt = await got.timeout(const Duration(seconds: 3));
      expect(pkt.data, [9, 9, 9]);
    },
  );

  // Linux IPv4 sockets bound to INADDR_ANY still see 224.0.0.0/4 on that
  // port when `IP_MULTICAST_ALL=1` (the kernel default). joinMulticast is
  // still required for IGMP so a real LAN forwards the group; group
  // filtering without join is proven on MemoryDatagramNetwork, not here.
  test('OPEN-09 IPv4 joinMulticast of a unicast host is refused', () async {
    final a = await IoDatagramChannel.bind(InternetAddress.anyIPv4, 0);
    addTearDown(a.close);
    final r = await a.joinMulticast(PqEndpoint(a.address.address, a.port));
    expect(r.isFailure, isTrue);
    expect(r.errorOrNull!.code, PqTransportErrorCode.unsupported);
  });

  test('OPEN-09 leaveMulticast after join succeeds', () async {
    final a = await IoDatagramChannel.bind(InternetAddress.anyIPv4, 0);
    addTearDown(a.close);
    final group = PqEndpoint(mdnsIpv4Group, a.port);
    expect((await a.joinMulticast(group)).isSuccess, isTrue);
    expect((await a.leaveMulticast(group)).isSuccess, isTrue);
  });

  test('OPEN-09 IPv4 socket refuses IPv6 mDNS group', () async {
    final a = await IoDatagramChannel.bind(InternetAddress.anyIPv4, 0);
    addTearDown(a.close);
    final r = await a.joinMulticast(PqEndpoint.mdnsV6);
    expect(r.isFailure, isTrue);
    expect(r.errorOrNull!.code, PqTransportErrorCode.unsupported);
    expect(r.errorOrNull!.message, contains('family'));
  });

  test('OPEN-09 joinMulticast on a closed channel fails', () async {
    final a = await IoDatagramChannel.bind(InternetAddress.loopbackIPv4, 0);
    await a.close();
    final r = await a.joinMulticast(PqEndpoint.mdnsV4);
    expect(r.isFailure, isTrue);
    expect(r.errorOrNull!.code, PqTransportErrorCode.closed);
  });
}
