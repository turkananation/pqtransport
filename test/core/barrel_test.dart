import 'package:pqtransport/pqtransport.dart';
import 'package:test/test.dart';

void main() {
  test('public barrel exports the frozen v1 names', () {
    expect(HybridGroup.x25519MlKem768.codepoint, namedGroupX25519MlKem768);
    expect(TlsState.uninitialized, isNotNull);
    expect(PqDatagram, isNotNull);
    expect(PqTlsClient, isNotNull);
    expect(PqTlsServer, isNotNull);
    expect(PqTlsSocket, isNotNull);
    expect(PqDnsClient, isNotNull);
    expect(PqMdnsClient, isNotNull);
    expect(PqMdnsServer, isNotNull);
    expect(PqHttpClient, isNotNull);
    expect(PqTransportError, isNotNull);
  });
}
