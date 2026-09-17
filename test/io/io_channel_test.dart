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
}
