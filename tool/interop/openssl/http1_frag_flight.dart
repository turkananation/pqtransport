import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:pqforge/pqforge.dart';
import 'package:pqtransport/pqtransport_io.dart';
import 'package:swissarmyknife/swissarmyknife.dart';

/// OpenSSL `s_server -max_send_frag` is the sender. [PqHttpClient] is
/// the recipient. The body is longer than one record, so a parser that
/// treats one TLS record as one HTTP message fails.
///
/// OpenSSL refuses a fragment below 512. 512 is the floor. The body is
/// 2048 octets, so the response cannot fit in one record.
Future<void> main(List<String> args) async {
  if (args.length != 1) {
    stderr.writeln(
      'usage: dart run tool/interop/openssl/http1_frag_flight.dart <openssl>',
    );
    exitCode = 64;
    return;
  }
  final openssl = File(args.single).absolute.path;
  const frag = 512;
  const bodyLen = 2048;
  // TLS 1.3 record length is plaintext + content type + GCM tag.
  const maxCipher = frag + 1 + 16;
  final dir = await Directory.systemTemp.createTemp('pq-h1-frag-');
  final conf =
      '${Directory.current.path}/tool/interop/openssl/openssl-x509.cnf';
  final env = {
    ...Platform.environment,
    'LD_LIBRARY_PATH': _libDir(openssl),
    'OPENSSL_CONF': conf,
  };
  Process? server;
  try {
    await _run(openssl, env, [
      'genpkey',
      '-algorithm',
      'ML-DSA-65',
      '-out',
      '${dir.path}/ca.key',
    ]);
    await _run(openssl, env, [
      'req',
      '-new',
      '-x509',
      '-key',
      '${dir.path}/ca.key',
      '-config',
      conf,
      '-extensions',
      'ca_ext',
      '-subj',
      '/CN=pqtransport-ca',
      '-days',
      '1',
      '-out',
      '${dir.path}/ca.pem',
    ]);
    await _run(openssl, env, [
      'genpkey',
      '-algorithm',
      'ML-DSA-65',
      '-out',
      '${dir.path}/leaf.key',
    ]);
    await _run(openssl, env, [
      'req',
      '-new',
      '-key',
      '${dir.path}/leaf.key',
      '-config',
      conf,
      '-subj',
      '/CN=localhost',
      '-out',
      '${dir.path}/leaf.csr',
    ]);
    await _run(openssl, env, [
      'x509',
      '-req',
      '-in',
      '${dir.path}/leaf.csr',
      '-CA',
      '${dir.path}/ca.pem',
      '-CAkey',
      '${dir.path}/ca.key',
      '-CAcreateserial',
      '-days',
      '1',
      '-extfile',
      conf,
      '-extensions',
      'leaf_ext',
      '-out',
      '${dir.path}/leaf.pem',
    ]);
    await _run(openssl, env, [
      'x509',
      '-in',
      '${dir.path}/ca.pem',
      '-outform',
      'DER',
      '-out',
      '${dir.path}/ca.der',
    ]);
    final anchor = await File('${dir.path}/ca.der').readAsBytes();
    final parsed = PqX509.parse(anchor);
    if (parsed.certificate == null) {
      throw StateError('OpenSSL CA did not parse: ${parsed.failure}');
    }
    final body = Uint8List(bodyLen);
    for (var i = 0; i < body.length; i++) {
      body[i] = 0x71;
    }
    final page = BytesBuilder(copy: false)
      ..add(
        Uint8List.fromList(
          'HTTP/1.1 200 OK\r\n'
                  'Content-Type: text/plain\r\n'
                  'Content-Length: $bodyLen\r\n'
                  'Connection: close\r\n'
                  '\r\n'
              .codeUnits,
        ),
      )
      ..add(body);
    await File('${dir.path}/body').writeAsBytes(page.takeBytes());

    final probe = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
    final port = probe.port;
    await probe.close();
    server = await Process.start(
      openssl,
      [
        's_server',
        '-accept',
        '127.0.0.1:$port',
        '-tls1_3',
        '-cert',
        '${dir.path}/leaf.pem',
        '-key',
        '${dir.path}/leaf.key',
        '-groups',
        'X25519MLKEM768',
        '-ciphersuites',
        'TLS_AES_256_GCM_SHA384',
        '-max_send_frag',
        '$frag',
        '-naccept',
        '1',
        '-HTTP',
      ],
      environment: env,
      workingDirectory: dir.path,
    );
    final errBuf = StringBuffer();
    final outBuf = StringBuffer();
    server.stderr.transform(utf8.decoder).listen(errBuf.write);
    server.stdout.transform(utf8.decoder).listen(outBuf.write);

    final raw = await _connect(port);
    final tap = _RecordTap(raw);
    final tls = PqTlsSocket.client(
      tap,
      certificateTypes: const [TlsCertificateType.x509],
      trustAnchors: [anchor],
      serverName: 'localhost',
      offeredCipherSuites: const [tlsCipherAes256GcmSha384],
    );
    final hs = await tls.handshake(timeout: const Duration(seconds: 20));
    if (hs.isFailure) {
      throw StateError(
        'handshake: ${hs.errorOrNull}\nstdout:\n$outBuf\nstderr:\n$errBuf',
      );
    }
    if (!tls.peerAuthenticated) {
      throw StateError('peerAuthenticated is false\n$errBuf');
    }
    final before = tap.lengths.length;
    final resp = await PqHttpClient().roundTripH1(
      tls: tls,
      timeout: const Duration(seconds: 20),
      request: PqHttpRequest(
        method: 'GET',
        uri: Uri.parse('https://localhost/body'),
      ),
    );
    if (resp.isFailure || resp.valueOrNull!.status != 200) {
      throw StateError(
        'response: ${resp.errorOrNull ?? resp.valueOrNull?.status}\n'
        'stdout:\n$outBuf\nstderr:\n$errBuf',
      );
    }
    final got = resp.valueOrNull!.body;
    if (got.length != bodyLen || got.any((b) => b != 0x71)) {
      throw StateError(
        'body ${got.length} is not $bodyLen octets of 0x71\n$errBuf',
      );
    }
    final after = tap.lengths.skip(before).toList();
    final widest = after.isEmpty ? 0 : after.reduce((a, b) => a > b ? a : b);
    if (after.isEmpty || widest > maxCipher || widest < 1) {
      throw StateError(
        's_server -max_send_frag $frag did not split the response. '
        'post-handshake record lengths: $after (max ciphertext $maxCipher)\n'
        '$errBuf',
      );
    }
    // One record cannot hold 2048 octets when every record is at most
    // [frag] bytes of plaintext. Reassembly is the only way the body
    // matches.
    if (after.length < (bodyLen / frag).ceil()) {
      throw StateError(
        'expected at least ${(bodyLen / frag).ceil()} records, got $after',
      );
    }
    stdout.writeln(
      'OpenSSL s_server -max_send_frag $frag split a $bodyLen-octet '
      'HTTP/1.1 body across ${after.length} TLS records '
      '(widest ciphertext $widest). PqHttpClient reassembled it.',
    );
    await tls.close();
  } finally {
    server?.kill(ProcessSignal.sigkill);
    await server?.exitCode.timeout(
      const Duration(seconds: 5),
      onTimeout: () => -1,
    );
    await dir.delete(recursive: true);
  }
}

/// Counts TLS record ciphertext lengths while forwarding the byte stream.
final class _RecordTap implements PqTransportSocket {
  _RecordTap(this._inner);

  final IoTcpSocket _inner;
  final List<int> lengths = [];
  final List<int> _buf = [];

  @override
  Stream<Uint8List> get incoming => _inner.incoming.map((chunk) {
    _buf.addAll(chunk);
    while (_buf.length >= tlsRecordHeaderBytes) {
      final len = (_buf[3] << 8) | _buf[4];
      if (len > tlsMaxCiphertextBytes) break;
      final total = tlsRecordHeaderBytes + len;
      if (_buf.length < total) break;
      lengths.add(len);
      _buf.removeRange(0, total);
    }
    return chunk;
  });

  @override
  bool get isClosed => _inner.isClosed;

  @override
  Future<Result<void, PqTransportError>> send(Uint8List bytes) =>
      _inner.send(bytes);

  @override
  Future<void> close() => _inner.close();
}

String _libDir(String bin) {
  final lib = Directory('${File(bin).parent.parent.path}/lib');
  final extra = Platform.environment['LD_LIBRARY_PATH'];
  if (!lib.existsSync()) return extra ?? '';
  return extra == null || extra.isEmpty ? lib.path : '${lib.path}:$extra';
}

Future<IoTcpSocket> _connect(int port) async {
  Object? last;
  for (var i = 0; i < 50; i++) {
    try {
      return await IoTcpSocket.connect(
        InternetAddress.loopbackIPv4.address,
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
