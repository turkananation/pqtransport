import 'dart:typed_data';

import 'package:pqtransport/pqtransport.dart';
import 'package:test/test.dart';

void main() {
  test('DNS_ASSIGN and PREF64 round-trip, and the refusals', () {
    final encoded = encodeDnsAssign([
      DnsAssignConfiguration(
        nameservers: [
          DnsAssignNameserver(
            priority: 1,
            ipv4: [
              Uint8List.fromList([192, 0, 2, 53]),
            ],
            authenticationDomain: '',
          ),
        ],
        internalDomains: const ['internal.example'],
        searchDomains: const ['example'],
      ),
    ]);
    expect(encoded.isSuccess, isTrue, reason: '${encoded.errorOrNull}');
    final decoded = decodeDnsAssign(encoded.valueOrNull!);
    expect(decoded.isSuccess, isTrue, reason: '${decoded.errorOrNull}');
    final ns = decoded.valueOrNull!.single.nameservers.single;
    expect(ns.priority, 1);
    expect(ns.ipv4.single, [192, 0, 2, 53]);
    expect(decoded.valueOrNull!.single.internalDomains, ['internal.example']);
    expect(decodeDnsAssign(Uint8List(0)).valueOrNull, isEmpty);

    expect(
      encodeDnsAssign([
        const DnsAssignConfiguration(
          nameservers: [DnsAssignNameserver(priority: 0, ipv4: [])],
        ),
      ]).isFailure,
      isTrue,
    );
    expect(
      encodeDnsAssign([
        DnsAssignConfiguration(
          nameservers: [
            DnsAssignNameserver(priority: 1, serviceParameters: [0, 4, 0, 0]),
          ],
        ),
      ]).isFailure,
      isTrue,
    );

    final pref = encodePref64([
      Nat64Prefix(
        prefixLength: 96,
        prefix: Uint8List.fromList([
          0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, //
        ]),
      ),
    ]);
    expect(pref.isSuccess, isTrue, reason: '${pref.errorOrNull}');
    final back = decodePref64(pref.valueOrNull!);
    expect(back.valueOrNull!.single.prefixLength, 96);
    expect(decodePref64(Uint8List(0)).valueOrNull, isEmpty);
    expect(decodePref64(Uint8List(12)).isFailure, isTrue);
    expect(
      encodePref64([
        Nat64Prefix(prefixLength: 16, prefix: Uint8List(12)),
      ]).isFailure,
      isTrue,
    );
    expect(dnsAssignCapsule(const []).type, capsuleDnsAssign);
    expect(pref64Capsule(const []).type, capsulePref64);
  });
}
