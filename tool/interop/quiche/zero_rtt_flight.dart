import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

import 'package:pqforge/pqforge.dart';
import 'package:pqtransport/pqtransport_io.dart';
import 'package:swissarmyknife/swissarmyknife.dart';

/// quiche 0.30 client sends QUIC 0-RTT, then offers the same session again.
///
/// The first handshake is given a NewSessionTicket. quiche caches that
/// session, including the server transport parameters. The next
/// connection writes `pq-0rtt` on stream 4 before the handshake
/// finishes. The third connection is the same session. The ticket is
/// single-use, so that handshake completes and accepts no early data.
Future<void> main(List<String> args) async {
  if (args.length != 1) {
    stderr.writeln(
      'usage: dart run tool/interop/quiche/zero_rtt_flight.dart <quiche_peer>',
    );
    exitCode = 64;
    return;
  }
  final peerBin = args.single;
  final crypto = const PqTransportCrypto();
  final minted = _mint(crypto);
  final store = QuicEarlyDataStore();
  final dir = await Directory.systemTemp.createTemp('pq-quiche-0rtt-');
  final caPath = '${dir.path}/ca.pem';
  await File(caPath).writeAsString(minted.caPem);
  final channel = await IoDatagramChannel.bind(InternetAddress.loopbackIPv4, 0);
  final table = _QuicTable(
    channel: channel,
    crypto: crypto,
    identity: minted.identity,
    store: store,
  );
  final sub = channel.incoming.listen(table.receive);
  final process = await Process.start(peerBin, [
    '0rtt-client',
    '127.0.0.1:${channel.port}',
    caPath,
  ]);
  final log = StringBuffer();
  void note(List<int> bytes) {
    final text = String.fromCharCodes(bytes);
    log.write(text);
    stderr.write(text);
  }

  process.stdout.listen(note);
  process.stderr.listen(note);
  final code = await process.exitCode.timeout(
    const Duration(seconds: 40),
    onTimeout: () {
      process.kill();
      return -1;
    },
  );
  final text = log.toString();
  final early = table.at(1);
  final replay = table.at(2);
  final earlyText = early == null ? '' : _earlyText(early);
  stderr.writeln(
    'quiche 0-rtt bytes=$earlyText accepted=${early?.earlyDataAccepted} '
    'replay_bytes=${replay == null ? '' : _earlyText(replay)} '
    'replay_accepted=${replay?.earlyDataAccepted} exit=$code',
  );
  final ok =
      code == 0 &&
      text.contains('quiche-0rtt sent=pq-0rtt') &&
      text.contains('quiche-0rtt replay established=true') &&
      earlyText == 'pq-0rtt' &&
      early?.earlyDataAccepted == true &&
      replay?.isComplete == true &&
      replay?.earlyDataAccepted == false &&
      (replay == null || replay.earlyData.isEmpty);
  for (final loss in table.losses) {
    loss.cancel();
  }
  await sub.cancel();
  await channel.close();
  await dir.delete(recursive: true);
  if (!ok) exitCode = 1;
}

final class _Slot {
  _Slot(this.conn, this.loss);

  final PqQuicConn conn;
  final QuicLossSubscription loss;
  PqEndpoint? peer;
}

final class _QuicTable {
  _QuicTable({
    required this.channel,
    required this.crypto,
    required this.identity,
    required this.store,
  });

  final IoDatagramChannel channel;
  final PqTransportCrypto crypto;
  final PqTlsServerIdentity identity;
  final QuicEarlyDataStore store;
  final List<_Slot> _slots = [];
  final Map<String, _Slot> _byCid = {};
  final Map<String, List<({Uint8List data, PqEndpoint peer})>> _held = {};
  Future<void> _pump = Future<void>.value();
  var _ticketSent = false;

  List<QuicLossSubscription> get losses => [
    for (final slot in _slots) slot.loss,
  ];

  PqQuicConn? at(int index) =>
      _slots.length > index ? _slots[index].conn : null;

  void receive(PqDatagramIn datagram) {
    _pump = _pump.then((_) => _take(datagram));
  }

  Future<void> _take(PqDatagramIn datagram) async {
    final wire = datagram.data;
    final dcid = _dcid(wire);
    if (dcid == null) return;
    final key = _cid(dcid);
    final known = _byCid[key];
    if (known != null) {
      known.peer = datagram.peer;
      await _ingest(known, wire);
      return;
    }
    final type = wire[0] & 0xf0;
    final initial = (wire[0] & 0x80) != 0 && type == 0xc0;
    if (!initial) {
      if (type == 0xd0) {
        (_held[key] ??= []).add((data: wire, peer: datagram.peer));
      }
      return;
    }
    final slot = _spawn();
    _byCid[key] = slot;
    _byCid[_cid(slot.conn.localCid)] = slot;
    slot.peer = datagram.peer;
    await _ingest(slot, wire);
    final held = _held.remove(key);
    if (held == null) return;
    for (final one in held) {
      slot.peer = one.peer;
      await _ingest(slot, one.data);
    }
  }

  _Slot _spawn() {
    late _Slot slot;
    final conn = PqQuicConn.server(
      crypto: crypto,
      identity: identity,
      alpnProtocols: const ['h3'],
      earlyData: store,
      deliver: (packet) {
        final to = slot.peer;
        if (to == null) {
          return Future.value(Result.failure(PqTransportError.closed('quic')));
        }
        return channel.send(packet, to);
      },
    );
    slot = _Slot(conn, conn.bindLossTimer());
    _slots.add(slot);
    return slot;
  }

  Future<void> _ingest(_Slot slot, Uint8List wire) async {
    final got = await slot.conn.ingestDatagram(wire);
    stderr.writeln(
      got.isFailure
          ? 'ingest ${got.errorOrNull}'
          : 'ingest ok complete=${slot.conn.isComplete} '
                'early=${slot.conn.earlyDataAccepted}',
    );
    if (got.isFailure || _ticketSent || slot != _slots.first) return;
    if (!slot.conn.isComplete) return;
    _ticketSent = true;
    final issued = await slot.conn.sendNewSessionTicket(store);
    stderr.writeln(
      issued.isFailure
          ? 'ticket ${issued.errorOrNull}'
          : 'ticket sent ${issued.valueOrNull!.identity.length}',
    );
  }
}

String _earlyText(PqQuicConn conn) {
  final out = BytesBuilder(copy: false);
  for (final frame in conn.earlyData) {
    out.add(frame.data);
  }
  return String.fromCharCodes(out.takeBytes());
}

Uint8List? _dcid(Uint8List packet) {
  if (packet.isEmpty) return null;
  if ((packet[0] & 0x80) == 0) {
    if (packet.length < 1 + quicShortDcidBytes) return null;
    return Uint8List.sublistView(packet, 1, 1 + quicShortDcidBytes);
  }
  if (packet.length < 7) return null;
  final length = packet[5];
  if (packet.length < 6 + length) return null;
  return Uint8List.sublistView(packet, 6, 6 + length);
}

String _cid(Uint8List cid) {
  final out = StringBuffer();
  for (final byte in cid) {
    out.write(byte.toRadixString(16).padLeft(2, '0'));
  }
  return out.toString();
}

({PqTlsServerIdentity identity, String caPem}) _mint(PqTransportCrypto crypto) {
  final now = DateTime.now().toUtc();
  final notBefore = now.subtract(const Duration(hours: 1));
  final notAfter = now.add(const Duration(days: 1));
  final rootKeys = crypto.mlDsaKeyGen();
  final rootName = PqX509Name.commonName('pqtransport-ca');
  final rootKey = PqX509MlDsaKey(PqX509Algorithm.mlDsa65, rootKeys.publicKey);
  final root = PqX509.mint(
    issuer: rootName,
    subject: rootName,
    publicKey: rootKey,
    algorithm: PqX509Algorithm.mlDsa65,
    sign: (tbs) =>
        crypto.mlDsaSign(secretKey: rootKeys.secretKey, message: tbs),
    notBefore: notBefore,
    notAfter: notAfter,
    serial: Uint8List.fromList([1]),
    ca: true,
    keyCertSign: true,
    includeEku: false,
  );
  final leafKeys = crypto.mlDsaKeyGen();
  final leafKey = PqX509MlDsaKey(PqX509Algorithm.mlDsa65, leafKeys.publicKey);
  final leaf = PqX509.mint(
    issuer: rootName,
    subject: PqX509Name.commonName('localhost'),
    publicKey: leafKey,
    algorithm: PqX509Algorithm.mlDsa65,
    sign: (tbs) =>
        crypto.mlDsaSign(secretKey: rootKeys.secretKey, message: tbs),
    notBefore: notBefore,
    notAfter: notAfter,
    serial: Uint8List.fromList([2]),
    subjectAltNames: const [PqX509DnsName('localhost')],
  );
  return (
    identity: PqTlsServerIdentity.x509(
      leafKey: leafKey,
      sign: (content) =>
          crypto.mlDsaSign(secretKey: leafKeys.secretKey, message: content),
      chain: [leaf],
      certificateDnsName: 'localhost',
    ),
    caPem: PqX509.toPem(root),
  );
}
