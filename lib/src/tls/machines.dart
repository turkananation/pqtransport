import 'package:swissarmyknife/swissarmyknife.dart';

import '../core/errors.dart';
import 'tls_state.dart';

StateMachine<TlsState, TlsEvent> tlsClientMachine() {
  final m = StateMachine<TlsState, TlsEvent>(
    initialState: TlsState.uninitialized,
  );
  m.addTransition(
    TlsState.uninitialized,
    TlsEvent.startHandshake,
    TlsState.clientHelloSent,
  );
  m.addTransition(TlsState.uninitialized, TlsEvent.fatal, TlsState.failed);
  m.addTransition(TlsState.uninitialized, TlsEvent.close, TlsState.closed);
  m.addTransition(
    TlsState.clientHelloSent,
    TlsEvent.receiveHelloRetry,
    TlsState.clientHelloSent,
  );
  m.addTransition(
    TlsState.clientHelloSent,
    TlsEvent.receiveServerHello,
    TlsState.serverHelloProcessed,
  );
  m.addTransition(TlsState.clientHelloSent, TlsEvent.fatal, TlsState.failed);
  m.addTransition(TlsState.clientHelloSent, TlsEvent.close, TlsState.closed);
  m.addTransition(
    TlsState.serverHelloProcessed,
    TlsEvent.receiveEncryptedExtensions,
    TlsState.waitCertificate,
  );
  m.addTransition(
    TlsState.serverHelloProcessed,
    TlsEvent.fatal,
    TlsState.failed,
  );
  m.addTransition(
    TlsState.serverHelloProcessed,
    TlsEvent.close,
    TlsState.closed,
  );
  m.addTransition(
    TlsState.waitCertificate,
    TlsEvent.receiveCertificate,
    TlsState.waitCertVerify,
  );
  m.addTransition(TlsState.waitCertificate, TlsEvent.fatal, TlsState.failed);
  m.addTransition(TlsState.waitCertificate, TlsEvent.close, TlsState.closed);
  m.addTransition(
    TlsState.waitCertVerify,
    TlsEvent.receiveCertVerify,
    TlsState.waitFinished,
  );
  m.addTransition(TlsState.waitCertVerify, TlsEvent.fatal, TlsState.failed);
  m.addTransition(TlsState.waitCertVerify, TlsEvent.close, TlsState.closed);
  m.addTransition(
    TlsState.waitFinished,
    TlsEvent.receiveFinished,
    TlsState.handshakeCompleted,
  );
  m.addTransition(TlsState.waitFinished, TlsEvent.fatal, TlsState.failed);
  m.addTransition(TlsState.waitFinished, TlsEvent.close, TlsState.closed);
  m.addTransition(
    TlsState.handshakeCompleted,
    TlsEvent.receiveAppData,
    TlsState.handshakeCompleted,
  );
  m.addTransition(TlsState.handshakeCompleted, TlsEvent.close, TlsState.closed);
  m.addTransition(TlsState.handshakeCompleted, TlsEvent.fatal, TlsState.failed);
  m.addTransition(TlsState.failed, TlsEvent.close, TlsState.closed);
  return m;
}

StateMachine<TlsState, TlsEvent> tlsServerMachine() {
  final m = StateMachine<TlsState, TlsEvent>(
    initialState: TlsState.waitClientHello,
  );
  m.addTransition(
    TlsState.waitClientHello,
    TlsEvent.receiveClientHello,
    TlsState.serverHelloSent,
  );
  m.addTransition(TlsState.waitClientHello, TlsEvent.fatal, TlsState.failed);
  m.addTransition(TlsState.waitClientHello, TlsEvent.close, TlsState.closed);
  m.addTransition(
    TlsState.serverHelloSent,
    TlsEvent.receiveFinished,
    TlsState.handshakeCompleted,
  );
  m.addTransition(TlsState.serverHelloSent, TlsEvent.fatal, TlsState.failed);
  m.addTransition(TlsState.serverHelloSent, TlsEvent.close, TlsState.closed);
  m.addTransition(
    TlsState.handshakeCompleted,
    TlsEvent.receiveAppData,
    TlsState.handshakeCompleted,
  );
  m.addTransition(TlsState.handshakeCompleted, TlsEvent.close, TlsState.closed);
  m.addTransition(TlsState.handshakeCompleted, TlsEvent.fatal, TlsState.failed);
  m.addTransition(TlsState.failed, TlsEvent.close, TlsState.closed);
  return m;
}

Result<void, PqTransportError> driveTls(
  StateMachine<TlsState, TlsEvent> machine,
  TlsEvent event,
) {
  final r = machine.trigger(event);
  if (r.isSuccess) return const Result.success(null);
  final fatal = machine.trigger(TlsEvent.fatal);
  if (fatal.isFailure && !machine.isIn(TlsState.failed)) {
    machine.reset(TlsState.failed);
  }
  return Result.failure(
    PqTransportError.unexpectedMessage(r.errorOrNull!.message),
  );
}
