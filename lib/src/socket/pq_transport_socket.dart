import 'dart:async';
import 'dart:typed_data';

import 'package:swissarmyknife/swissarmyknife.dart';

import '../core/errors.dart';
import '../core/lengths.dart';

/// Bytes-in / bytes-out transport. Web-safe. No crypto.
abstract interface class PqTransportSocket {
  Stream<Uint8List> get incoming;
  Future<Result<void, PqTransportError>> send(Uint8List bytes);
  Future<void> close();
  bool get isClosed;
}

/// Datagram channel (addressed). Web-safe codec layer; IO driver elsewhere.
final class PqDatagramIn {
  const PqDatagramIn({required this.data, required this.peer});

  final Uint8List data;
  final PqEndpoint peer;
}

final class PqEndpoint {
  const PqEndpoint(this.host, this.port);

  final String host;
  final int port;

  @override
  String toString() => '$host:$port';

  @override
  bool operator ==(Object other) =>
      other is PqEndpoint && other.host == host && other.port == port;

  @override
  int get hashCode => Object.hash(host, port);

  bool get isMulticast =>
      host == mdnsIpv4Group ||
      host == mdnsIpv6Group ||
      host.startsWith('224.') ||
      host.toLowerCase().startsWith('ff');
}

abstract interface class PqDatagramChannel {
  Stream<PqDatagramIn> get incoming;
  Future<Result<void, PqTransportError>> send(Uint8List data, PqEndpoint peer);
  Future<void> close();
  bool get isClosed;
}

/// In-memory duplex byte pipe for tests and local loops.
///
/// Buffers sends until a listener is attached so handshake races do not drop
/// the ClientHello.
final class MemoryByteSocket implements PqTransportSocket {
  MemoryByteSocket._(this._inbound, this._outbound);

  final StreamController<Uint8List> _inbound;
  final _BufferedSink _outbound;
  var _closed = false;

  static (MemoryByteSocket, MemoryByteSocket) pair() {
    // ignore: close_sinks
    final aToB = StreamController<Uint8List>.broadcast();
    // ignore: close_sinks
    final bToA = StreamController<Uint8List>.broadcast();
    final pendingForB = <Uint8List>[];
    final pendingForA = <Uint8List>[];
    aToB.onListen = () {
      for (final p in pendingForB) {
        aToB.add(p);
      }
      pendingForB.clear();
    };
    bToA.onListen = () {
      for (final p in pendingForA) {
        bToA.add(p);
      }
      pendingForA.clear();
    };
    return (
      MemoryByteSocket._(bToA, _BufferedSink(aToB, pendingForB)),
      MemoryByteSocket._(aToB, _BufferedSink(bToA, pendingForA)),
    );
  }

  @override
  Stream<Uint8List> get incoming => _inbound.stream;

  @override
  bool get isClosed => _closed;

  @override
  Future<Result<void, PqTransportError>> send(Uint8List bytes) async {
    if (_closed || _outbound.isClosed) {
      return Result.failure(PqTransportError.closed('send on closed socket'));
    }
    _outbound.add(Uint8List.fromList(bytes));
    return const Result.success(null);
  }

  @override
  Future<void> close() async {
    _closed = true;
    await _outbound.close();
  }
}

final class _BufferedSink {
  _BufferedSink(this.controller, this.pending);

  final StreamController<Uint8List> controller;
  final List<Uint8List> pending;
  var isClosed = false;

  void add(Uint8List bytes) {
    if (controller.hasListener) {
      controller.add(bytes);
    } else {
      pending.add(bytes);
    }
  }

  Future<void> close() async {
    isClosed = true;
    if (!controller.isClosed) {
      await controller.close();
    }
  }
}

/// In-memory datagram network keyed by [PqEndpoint].
final class MemoryDatagramNetwork {
  MemoryDatagramNetwork();

  final Map<PqEndpoint, _Mailbox> _mailboxes = {};

  MemoryDatagramChannel bind(PqEndpoint local) {
    // ignore: close_sinks
    final box = StreamController<PqDatagramIn>.broadcast();
    final pending = <PqDatagramIn>[];
    box.onListen = () {
      for (final p in pending) {
        box.add(p);
      }
      pending.clear();
    };
    final mailbox = _Mailbox(box, pending);
    _mailboxes[local] = mailbox;
    return MemoryDatagramChannel._(this, local, mailbox);
  }

  void deliver(PqEndpoint from, PqEndpoint to, Uint8List data) {
    final packet = PqDatagramIn(data: Uint8List.fromList(data), peer: from);
    if (to.isMulticast) {
      for (final entry in _mailboxes.entries) {
        if (entry.key == from) continue;
        if (entry.key.port != to.port) continue;
        entry.value.add(packet);
      }
      return;
    }
    _mailboxes[to]?.add(packet);
  }
}

final class _Mailbox {
  _Mailbox(this.controller, this.pending);

  final StreamController<PqDatagramIn> controller;
  final List<PqDatagramIn> pending;

  Stream<PqDatagramIn> get stream => controller.stream;

  void add(PqDatagramIn packet) {
    if (controller.hasListener) {
      controller.add(packet);
    } else {
      pending.add(packet);
    }
  }

  Future<void> close() async {
    if (!controller.isClosed) {
      await controller.close();
    }
  }
}

final class MemoryDatagramChannel implements PqDatagramChannel {
  MemoryDatagramChannel._(this._net, this.local, this._box);

  final MemoryDatagramNetwork _net;
  final PqEndpoint local;
  final _Mailbox _box;
  var _closed = false;

  @override
  Stream<PqDatagramIn> get incoming => _box.stream;

  @override
  bool get isClosed => _closed;

  @override
  Future<Result<void, PqTransportError>> send(
    Uint8List data,
    PqEndpoint peer,
  ) async {
    if (_closed) {
      return Result.failure(PqTransportError.closed('send on closed channel'));
    }
    _net.deliver(local, peer, data);
    return const Result.success(null);
  }

  @override
  Future<void> close() async {
    _closed = true;
    await _box.close();
  }
}
