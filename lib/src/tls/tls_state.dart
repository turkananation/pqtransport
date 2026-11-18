enum TlsState {
  uninitialized,
  waitClientHello,
  clientHelloSent,
  serverHelloSent,
  serverHelloProcessed,
  waitEncryptedExtensions,
  waitCertificate,
  waitCertVerify,
  waitFinished,
  handshakeCompleted,
  failed,
  closed,
}

enum TlsEvent {
  startHandshake,
  receiveClientHello,
  receiveHelloRetry,
  receiveServerHello,
  sendServerHello,
  receiveEncryptedExtensions,
  receiveCertificate,
  receiveCertVerify,
  resumeWithPsk,
  receiveFinished,
  receiveAppData,
  fatal,
  close,
}

enum TlsRole { client, server }
