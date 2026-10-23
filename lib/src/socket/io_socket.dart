import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

import 'package:swissarmyknife/swissarmyknife.dart';

import '../core/errors.dart';
import '../core/lengths.dart';
import '../tls/pq_tls_server.dart';
import 'pq_transport_socket.dart';

/// `dart:io` UDP driver. Not exported from the web-safe barrel.
final class IoDatagramChannel implements PqDatagramChannel {
  IoDatagramChannel._(this._socket, this._controller);

  final RawDatagramSocket _socket;
  final StreamController<PqDatagramIn> _controller;
  StreamSubscription<RawSocketEvent>? _sub;
  var _closed = false;

  int get port => _socket.port;
  InternetAddress get address => _socket.address;

  /// Bind a UDP socket. [reuseAddress] defaults on so mDNS can share 5353.
  /// [reusePort] is SO_REUSEPORT — pass `true` when binding [mdnsPort].
  /// [multicastLoopback] must stay on for same-host mDNS tests.
  static Future<IoDatagramChannel> bind(
    InternetAddress addr,
    int port, {
    bool reuseAddress = true,
    bool reusePort = false,
    bool multicastLoopback = true,
  }) async {
    final sock = await RawDatagramSocket.bind(
      addr,
      port,
      reuseAddress: reuseAddress,
      reusePort: reusePort,
    );
    sock.multicastLoopback = multicastLoopback;
    // ignore: close_sinks
    final controller = StreamController<PqDatagramIn>.broadcast();
    final ch = IoDatagramChannel._(sock, controller);
    ch._sub = sock.listen((event) {
      if (event != RawSocketEvent.read) return;
      final d = sock.receive();
      if (d == null) return;
      controller.add(
        PqDatagramIn(
          data: Uint8List.fromList(d.data),
          peer: PqEndpoint(d.address.address, d.port),
        ),
      );
    });
    return ch;
  }

  @override
  Stream<PqDatagramIn> get incoming => _controller.stream;

  @override
  bool get isClosed => _closed;

  @override
  Future<Result<void, PqTransportError>> send(
    Uint8List data,
    PqEndpoint peer,
  ) async {
    if (_closed) {
      return Result.failure(PqTransportError.closed('io udp'));
    }
    _socket.send(data, InternetAddress(peer.host), peer.port);
    return const Result.success(null);
  }

  @override
  Future<Result<void, PqTransportError>> joinMulticast(PqEndpoint group) async {
    if (_closed) {
      return Result.failure(PqTransportError.closed('joinMulticast'));
    }
    if (!group.isMulticast) {
      return Result.failure(
        PqTransportError.unsupported('not a multicast group ${group.host}'),
      );
    }
    final addr = InternetAddress(group.host);
    if (addr.type != _socket.address.type) {
      return Result.failure(
        PqTransportError.unsupported(
          'joinMulticast family mismatch ${addr.type} vs ${_socket.address.type}',
        ),
      );
    }
    try {
      if (group.host == mdnsIpv4Group || group.host == mdnsIpv6Group) {
        _socket.multicastHops = 255;
      }
      _socket.joinMulticast(addr);
      return const Result.success(null);
    } on Object catch (e) {
      return Result.failure(
        PqTransportError.unsupported('joinMulticast ${group.host}: $e'),
      );
    }
  }

  @override
  Future<Result<void, PqTransportError>> leaveMulticast(
    PqEndpoint group,
  ) async {
    if (_closed) {
      return Result.failure(PqTransportError.closed('leaveMulticast'));
    }
    try {
      _socket.leaveMulticast(InternetAddress(group.host));
      return const Result.success(null);
    } on Object catch (e) {
      return Result.failure(
        PqTransportError.unsupported('leaveMulticast ${group.host}: $e'),
      );
    }
  }

  @override
  Future<void> close() async {
    _closed = true;
    await _sub?.cancel();
    _socket.close();
    await _controller.close();
  }
}

/// TCP byte pipe. Records are reassembled by [PqTlsSocket], not here.
final class IoTcpSocket implements PqTransportSocket {
  IoTcpSocket._(this._socket);

  final Socket _socket;
  var _closed = false;

  /// Connect to [host]:[port].
  static Future<IoTcpSocket> connect(
    String host,
    int port, {
    Duration timeout = const Duration(seconds: 10),
  }) async {
    // ignore: close_sinks
    final socket = await Socket.connect(host, port, timeout: timeout);
    return IoTcpSocket._(socket);
  }

  /// Wrap an accepted [Socket].
  factory IoTcpSocket.from(Socket socket) => IoTcpSocket._(socket);

  @override
  Stream<Uint8List> get incoming => _socket;

  @override
  bool get isClosed => _closed;

  @override
  Future<Result<void, PqTransportError>> send(Uint8List bytes) async {
    if (_closed) {
      return Result.failure(PqTransportError.closed('tcp send'));
    }
    _socket.add(bytes);
    await _socket.flush();
    return const Result.success(null);
  }

  @override
  Future<void> close() async {
    if (_closed) return;
    _closed = true;
    await _socket.close();
  }
}

/// TCP accept loop. Each connection is an [IoTcpSocket].
final class IoTcpServer {
  IoTcpServer._(this._server);

  final ServerSocket _server;

  static Future<IoTcpServer> bind(Object address, int port) async {
    final server = await ServerSocket.bind(address, port);
    return IoTcpServer._(server);
  }

  Stream<IoTcpSocket> get connections => _server.map(IoTcpSocket.from);

  int get port => _server.port;

  InternetAddress get address => _server.address;

  Future<void> close() => _server.close();
}

/// Read an RFC 7468 ML-DSA identity from two files.
Future<Result<PqTlsServerIdentity, PqTransportError>> readMlDsaIdentityPem(
  String publicKeyPath,
  String privateKeyPath,
) async {
  try {
    return PqTlsServerIdentity.parsePem(
      await File(publicKeyPath).readAsString(),
      await File(privateKeyPath).readAsString(),
    );
  } on IOException {
    return Result.failure(PqTransportError.decodeFailure('identity file'));
  }
}
