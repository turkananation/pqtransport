import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

import 'package:swissarmyknife/swissarmyknife.dart';

import '../core/errors.dart';
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

  static Future<IoDatagramChannel> bind(InternetAddress addr, int port) async {
    final sock = await RawDatagramSocket.bind(addr, port);
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
  Future<void> close() async {
    _closed = true;
    await _sub?.cancel();
    _socket.close();
    await _controller.close();
  }
}
