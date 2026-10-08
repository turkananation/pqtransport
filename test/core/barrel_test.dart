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
    expect(PqHttp2Session, isNotNull);
    expect(PqHttp3Session, isNotNull);
    expect(HpackCodec, isNotNull);
    expect(QpackCodec, isNotNull);
    expect(Http2Frame, isNotNull);
    expect(Http3Frame, isNotNull);
    expect(PqQuicConn, isNotNull);
    expect(EncryptedExtensions, isNotNull);
    expect(PqTransportError, isNotNull);
    expect(QuicTlsHandshake, isNotNull);
    expect(QuicInitialSecrets, isNotNull);
    expect(QuicAckProcessor, isNotNull);
  });
}
