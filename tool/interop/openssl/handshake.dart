import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:pqtransport/pqtransport.dart';

Future<void> main(List<String> args) async {
  if (args.length != 1) {
    stderr.writeln(
      'usage: dart run tool/interop/openssl/handshake.dart <openssl>',
    );
    exitCode = 64;
    return;
  }
  await handshakeX25519MlKem768(args.single);
  stdout.writeln('OpenSSL 3.5 X25519MLKEM768 handshake complete');
}

/// Completes one TLS 1.3 handshake with OpenSSL `s_server`.
///
/// Auth mode: RFC 7250 raw public key, ML-DSA-65. The server certificate
/// is an ML-DSA-65 X.509 certificate; `-enable_server_rpk` makes OpenSSL
/// send the SubjectPublicKeyInfo instead of the certificate. Group is
/// X25519MLKEM768. Suite is TLS_AES_256_GCM_SHA384 (`0x1302`).
Future<void> handshakeX25519MlKem768(String opensslBin) async {
  final dir = await Directory.systemTemp.createTemp('pq-openssl-');
  final conf =
      Platform.environment['OPENSSL_CONF'] ??
      '${Directory.current.path}/tool/interop/openssl/openssl.cnf';
  final env = {
    ...Platform.environment,
    'LD_LIBRARY_PATH': _libDir(opensslBin),
    'OPENSSL_CONF': conf,
  };
  try {
    await _run(opensslBin, env, [
      'genpkey',
      '-algorithm',
      'ML-DSA-65',
      '-out',
      '${dir.path}/key.pem',
    ]);
    await _run(opensslBin, env, [
      'req',
      '-new',
      '-x509',
      '-key',
      '${dir.path}/key.pem',
      '-config',
      conf,
      '-subj',
      '/CN=localhost',
      '-days',
      '1',
      '-out',
      '${dir.path}/cert.pem',
    ]);
    await _run(opensslBin, env, [
      'pkey',
      '-in',
      '${dir.path}/key.pem',
      '-pubout',
      '-outform',
      'DER',
      '-out',
      '${dir.path}/spki.der',
    ]);
    final spki = decodeMlDsa65Spki(
      await File('${dir.path}/spki.der').readAsBytes(),
    );
    if (spki.isFailure) {
      throw StateError('OpenSSL SPKI: ${spki.errorOrNull}');
    }

    final probe = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
    final port = probe.port;
    await probe.close();
    final keylog = File('${dir.path}/keylog.txt');
    env['SSLKEYLOGFILE'] = keylog.path;
    final server = await Process.start(opensslBin, [
      's_server',
      '-accept',
      '127.0.0.1:$port',
      '-tls1_3',
      '-cert',
      '${dir.path}/cert.pem',
      '-key',
      '${dir.path}/key.pem',
      '-enable_server_rpk',
      '-groups',
      'X25519MLKEM768',
      '-ciphersuites',
      'TLS_AES_256_GCM_SHA384',
      '-naccept',
      '1',
      '-state',
      '-keylogfile',
      keylog.path,
    ], environment: env);
    final errBuf = StringBuffer();
    server.stderr.transform(utf8.decoder).listen(errBuf.write);
    unawaited(server.stdout.drain());

    final crypto = PqTransportCrypto();
    final client = PqTlsClient(
      crypto: crypto,
      offeredCipherSuites: const [tlsCipherAes256GcmSha384],
    );
    Socket? socket;
    try {
      socket = await _connect(port);
      final records = _Records(socket);
      final hello = await client.startHandshake();
      if (hello.isFailure) {
        throw StateError('start: ${hello.errorOrNull}');
      }
      socket.add(hello.valueOrNull!);
      await socket.flush();
      final ch = hello.valueOrNull!;
      final chHs = Uint8List.sublistView(ch, tlsRecordHeaderBytes);
      Uint8List? shHs;

      while (!client.isComplete) {
        final rec = await records.next();
        if (rec == null) {
          throw StateError('peer closed before Finished\n$errBuf');
        }
        if (rec[0] == 20) continue;
        if (rec[0] == 21) {
          throw StateError('alert ${rec.sublist(5)}');
        }
        if (rec[0] == 22) {
          shHs = Uint8List.sublistView(rec, tlsRecordHeaderBytes);
        }
        stderr.writeln(
          'rec type=${rec[0]} len=${rec.length} head=${hex(Uint8List.sublistView(rec, 0, rec.length < 8 ? rec.length : 8))}',
        );
        final out = await client.ingest(rec);
        if (out.isFailure) {
          final tr = client.transcript.bytes;
          final sh = shHs ?? Uint8List(0);
          final glued = Uint8List(chHs.length + sh.length)
            ..setRange(0, chHs.length, chHs)
            ..setRange(chHs.length, chHs.length + sh.length, sh);
          stderr.writeln(
            'tr ${tr.length} glued ${glued.length} equal ${_eqFull(tr, glued)}',
          );
          stderr.writeln('hash ${hex(client.transcript.snapshot())}');
          stderr.writeln(
            'ours s_hs ${hex(client.schedule.serverHandshakeTraffic)}',
          );
          stderr.writeln(
            'keylog\n${keylog.existsSync() ? keylog.readAsStringSync() : "missing"}',
          );
          final peerLine = keylog
              .readAsStringSync()
              .split('\n')
              .firstWhere(
                (l) => l.startsWith('SERVER_HANDSHAKE_TRAFFIC_SECRET '),
              );
          final peer = _unhex(peerLine.split(' ').last);
          final opened = _tryPeerSecret(crypto, peer, rec);
          stderr.writeln('peer secret opens record: $opened');
          throw StateError('ingest: ${out.errorOrNull}\n$errBuf');
        }
        for (final flight in out.valueOrNull!) {
          socket.add(flight);
        }
        await socket.flush();
      }
      if (!client.peerAuthenticated) {
        throw StateError('handshake finished without CertificateVerify');
      }
      if (client.cipherSuite != TlsCipherSuite.aes256GcmSha384) {
        throw StateError('suite ${client.cipherSuite}');
      }
      await socket.close();
      socket = null;
    } finally {
      await socket?.close();
      server.kill();
      await server.exitCode.timeout(
        const Duration(seconds: 5),
        onTimeout: () => -1,
      );
    }
    final text = errBuf.toString();
    if (!text.contains('TLS_AES_256_GCM_SHA384') &&
        !text.contains('X25519MLKEM768')) {
      throw StateError(
        'OpenSSL did not report the expected suite/group:\n$text',
      );
    }
  } finally {
    await dir.delete(recursive: true);
  }
}

String _libDir(String bin) {
  final lib = Directory('${File(bin).parent.parent.path}/lib');
  final extra = Platform.environment['LD_LIBRARY_PATH'];
  if (!lib.existsSync()) return extra ?? '';
  return extra == null || extra.isEmpty ? lib.path : '${lib.path}:$extra';
}

String hex(Uint8List b) =>
    b.map((x) => x.toRadixString(16).padLeft(2, '0')).join();

Uint8List _unhex(String s) {
  final out = Uint8List(s.length ~/ 2);
  for (var i = 0; i < out.length; i++) {
    out[i] = int.parse(s.substring(i * 2, i * 2 + 2), radix: 16);
  }
  return out;
}

String _tryPeerSecret(
  PqTransportCrypto crypto,
  Uint8List secret,
  Uint8List rec,
) {
  try {
    final key = _label(crypto, secret, 'key', 32);
    final iv = _label(crypto, secret, 'iv', 12);
    final plain = crypto.aeadOpen(
      key: key,
      nonce: iv,
      ciphertextWithTag: Uint8List.sublistView(rec, tlsRecordHeaderBytes),
      aad: Uint8List.sublistView(rec, 0, tlsRecordHeaderBytes),
    );
    return 'ok len=${plain.length} type=${plain.isEmpty ? -1 : plain.last}';
  } on Object catch (e) {
    return '$e';
  }
}

Uint8List _label(
  PqTransportCrypto crypto,
  Uint8List secret,
  String label,
  int length,
) {
  final labelBytes = utf8.encode('tls13 $label');
  final b = BytesBuilder(copy: false);
  writeUint16(b, length);
  b.addByte(labelBytes.length);
  b.add(labelBytes);
  b.addByte(0);
  return crypto.hkdfExpandSha384(secret, b.takeBytes(), length);
}

bool _eqFull(Uint8List a, Uint8List b) {
  if (a.length != b.length) return false;
  for (var i = 0; i < a.length; i++) {
    if (a[i] != b[i]) return false;
  }
  return true;
}

Future<Socket> _connect(int port) async {
  Object? last;
  for (var i = 0; i < 50; i++) {
    try {
      return await Socket.connect(
        InternetAddress.loopbackIPv4,
        port,
        timeout: const Duration(milliseconds: 200),
      );
    } on SocketException catch (e) {
      last = e;
      await Future<void>.delayed(const Duration(milliseconds: 50));
    }
  }
  throw StateError('s_server did not accept: $last');
}

Future<void> _run(
  String bin,
  Map<String, String> env,
  List<String> args,
) async {
  final result = await Process.run(bin, args, environment: env);
  if (result.exitCode != 0) {
    throw StateError('$bin ${args.first} failed\n${result.stderr}');
  }
}

final class _Records {
  _Records(this._socket);

  final Socket _socket;
  final List<int> _pending = [];
  late final StreamIterator<Uint8List> _it = StreamIterator(_socket);

  Future<Uint8List?> next() async {
    while (true) {
      final rec = _take();
      if (rec != null) return rec;
      if (!await _it.moveNext().timeout(const Duration(seconds: 15))) {
        return null;
      }
      _pending.addAll(_it.current);
    }
  }

  Uint8List? _take() {
    if (_pending.length < tlsRecordHeaderBytes) return null;
    final len = (_pending[3] << 8) | _pending[4];
    final total = tlsRecordHeaderBytes + len;
    if (_pending.length < total) return null;
    final rec = Uint8List.fromList(_pending.sublist(0, total));
    _pending.removeRange(0, total);
    return rec;
  }
}
