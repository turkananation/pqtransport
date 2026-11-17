import 'dart:async';
import 'dart:isolate';
import 'dart:typed_data';

import 'package:pqforge/pqforge.dart';

import 'lengths.dart';
import 'zeroize.dart';

/// VM path. One worker isolate owns ML-KEM and ML-DSA so a Shelf
/// handler is not stuck behind a handshake. Copies of secrets are
/// wiped in the worker before the reply is sent.
Future<({Uint8List publicKey, Uint8List secretKey})> offloadKemKeyGen(
  PqKemAlgorithm algorithm, {
  Uint8List? seed,
}) async {
  final result = await _call(0, [algorithm.index, seed]);
  final pair = result as List<Object?>;
  return (publicKey: pair[0]! as Uint8List, secretKey: pair[1]! as Uint8List);
}

Future<({Uint8List sharedSecret, Uint8List ciphertext})> offloadKemEncapsulate(
  PqKemAlgorithm algorithm,
  Uint8List publicKey,
) async {
  final result = await _call(1, [algorithm.index, publicKey]);
  final pair = result as List<Object?>;
  return (
    sharedSecret: pair[0]! as Uint8List,
    ciphertext: pair[1]! as Uint8List,
  );
}

Future<Uint8List> offloadKemDecapsulate(
  PqKemAlgorithm algorithm,
  Uint8List secretKey,
  Uint8List ciphertext,
) async {
  final result = await _call(2, [algorithm.index, secretKey, ciphertext]);
  return result as Uint8List;
}

Future<Uint8List> offloadMlDsaSign({
  required PqSignatureAlgorithm algorithm,
  required Uint8List secretKey,
  required Uint8List message,
  Uint8List? context,
}) async {
  final result = await _call(3, [algorithm.index, secretKey, message, context]);
  return result as Uint8List;
}

Future<bool> offloadMlDsaVerify({
  required Uint8List publicKey,
  required Uint8List message,
  required Uint8List signatureBytes,
  Uint8List? context,
}) async {
  final result = await _call(4, [publicKey, message, signatureBytes, context]);
  return result == true;
}

RawReceivePort? _inbox;
SendPort? _worker;
Future<void>? _boot;
final _waiters = <int, Completer<Object?>>{};
var _nextId = 0;
var _workerReady = false;

void _syncAlive() {
  // An idle worker must not pin the root isolate. A server socket does
  // that. A finished `dart run` has to be able to exit.
  _inbox?.keepIsolateAlive = !_workerReady || _waiters.isNotEmpty;
}

Future<Object?> _call(int op, List<Object?> args) async {
  await _ensure();
  if (_inbox == null || _worker == null) {
    throw StateError('offload worker');
  }
  final id = _nextId++;
  final done = Completer<Object?>();
  _waiters[id] = done;
  _syncAlive();
  _worker!.send([id, op, args]);
  return done.future;
}

Future<void> _ensure() {
  final existing = _boot;
  if (existing != null) return existing;
  final starting = _start();
  _boot = starting;
  return starting;
}

Future<void> _start() async {
  final inbox = RawReceivePort();
  _inbox = inbox;
  _workerReady = false;
  _syncAlive();
  final ready = Completer<SendPort>();
  inbox.handler = (Object? message) {
    if (message is SendPort) {
      _worker = message;
      _workerReady = true;
      _syncAlive();
      if (!ready.isCompleted) ready.complete(message);
      return;
    }
    final list = message! as List<Object?>;
    final waiter = _waiters.remove(list[0] as int);
    _syncAlive();
    if (waiter == null || waiter.isCompleted) return;
    if (list[1] == 0) {
      waiter.complete(list[2]);
    } else {
      waiter.completeError(StateError('${list[2]}'));
    }
  };
  await Isolate.spawn(
    _workerMain,
    inbox.sendPort,
    debugName: 'pqtransport-offload',
  );
  await ready.future;
}

void _workerMain(SendPort parent) {
  final inbox = ReceivePort();
  parent.send(inbox.sendPort);
  inbox.listen((message) {
    final list = message as List<Object?>;
    final id = list[0] as int;
    final op = list[1] as int;
    final args = list[2]! as List<Object?>;
    try {
      parent.send([id, 0, _run(op, args)]);
    } on Object catch (error) {
      parent.send([id, 1, '$error']);
    }
  });
}

Object? _run(int op, List<Object?> args) {
  switch (op) {
    case 0:
      final seed = args[1] as Uint8List?;
      final copy = seed == null ? null : Uint8List.fromList(seed);
      try {
        final kp = PqKemPrimitives.generateKeyPair(
          PqKemAlgorithm.values[args[0] as int],
          seed: copy,
        );
        return [kp.publicKey, kp.secretKey];
      } finally {
        zeroize(copy);
        zeroize(seed);
      }
    case 1:
      final pk = Uint8List.fromList(args[1] as Uint8List);
      try {
        final enc = PqKemPrimitives.encapsulate(
          PqKemAlgorithm.values[args[0] as int],
          pk,
        );
        return [enc.sharedSecret, enc.ciphertext];
      } finally {
        zeroize(pk);
        zeroize(args[1] as Uint8List);
      }
    case 2:
      final sk = Uint8List.fromList(args[1] as Uint8List);
      final ct = Uint8List.fromList(args[2] as Uint8List);
      try {
        return PqKemPrimitives.decapsulate(
          PqKemAlgorithm.values[args[0]! as int],
          sk,
          ct,
        );
      } finally {
        zeroize(sk);
        zeroize(ct);
        zeroize(args[1] as Uint8List);
        zeroize(args[2] as Uint8List);
      }
    case 3:
      final sk = Uint8List.fromList(args[1] as Uint8List);
      try {
        return PqSignaturePrimitives.sign(
          PqSignatureAlgorithm.values[args[0] as int],
          sk,
          args[2] as Uint8List,
          context: args[3] as Uint8List?,
        );
      } finally {
        zeroize(sk);
        zeroize(args[1] as Uint8List);
      }
    case 4:
      final pk = args[0] as Uint8List;
      final sig = args[2] as Uint8List;
      final algorithm = switch ((pk.length, sig.length)) {
        (mlDsa65PublicKeyBytes, mlDsa65SignatureBytes) =>
          PqSignatureAlgorithm.mlDsa65,
        (mlDsa87PublicKeyBytes, mlDsa87SignatureBytes) =>
          PqSignatureAlgorithm.mlDsa87,
        _ => null,
      };
      if (algorithm == null) return false;
      return PqSignaturePrimitives.verify(
        algorithm,
        pk,
        args[1] as Uint8List,
        sig,
        context: args[3] as Uint8List?,
      );
    default:
      throw StateError('offload op $op');
  }
}
