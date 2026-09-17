import 'package:pqtransport/pqtransport.dart';
import 'package:test/test.dart';

void main() {
  group('TLS client machine', () {
    test('happy path reaches handshakeCompleted', () {
      final m = tlsClientMachine();
      expect(driveTls(m, TlsEvent.startHandshake).isSuccess, isTrue);
      expect(m.currentState, TlsState.clientHelloSent);
      expect(driveTls(m, TlsEvent.receiveServerHello).isSuccess, isTrue);
      expect(m.currentState, TlsState.serverHelloProcessed);
      expect(
        driveTls(m, TlsEvent.receiveEncryptedExtensions).isSuccess,
        isTrue,
      );
      expect(driveTls(m, TlsEvent.receiveCertificate).isSuccess, isTrue);
      expect(driveTls(m, TlsEvent.receiveCertVerify).isSuccess, isTrue);
      expect(driveTls(m, TlsEvent.receiveFinished).isSuccess, isTrue);
      expect(m.currentState, TlsState.handshakeCompleted);
    });

    test('illegal event from uninitialized fails closed', () {
      final m = tlsClientMachine();
      final r = driveTls(m, TlsEvent.receiveFinished);
      expect(r.isFailure, isTrue);
      expect(m.currentState, TlsState.failed);
    });

    test('HelloRetryRequest allowed once then fail', () {
      final client = PqTlsClient();
      driveTls(client.machine, TlsEvent.startHandshake);
      expect(client.state, TlsState.clientHelloSent);
      expect(client.noteHelloRetry().isSuccess, isTrue);
      expect(client.state, TlsState.clientHelloSent);
      final second = client.noteHelloRetry();
      expect(second.isFailure, isTrue);
      expect(client.state, TlsState.failed);
    });
  });

  group('UDP reliability machine', () {
    test('illegal event fails closed', () {
      final m = udpStateMachine();
      final r = m.trigger(UdpEvent.peerAck);
      expect(r.isFailure, isTrue);
      m.trigger(UdpEvent.fatal);
      expect(m.currentState, UdpState.failed);
    });
  });

  group('QUIC machines', () {
    test('connection and stream illegal events', () {
      final c = quicConnMachine();
      expect(c.trigger(QuicConnectionEvent.handshakeDone).isFailure, isTrue);
      c.trigger(QuicConnectionEvent.fatal);
      expect(c.currentState, QuicConnectionState.failed);
      final s = quicStreamMachine();
      expect(s.trigger(QuicStreamEvent.fin).isFailure, isTrue);
    });
  });
}
