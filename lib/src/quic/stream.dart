import 'dart:typed_data';

import 'package:swissarmyknife/swissarmyknife.dart';

import '../core/errors.dart';
import '../core/lengths.dart';
import 'packet.dart';

bool quicStreamIsUnidirectional(int id) =>
    (id & quicStreamIdTypeMask) == quicStreamIdClientUni ||
    (id & quicStreamIdTypeMask) == quicStreamIdServerUni;

bool quicStreamIsClientInitiated(int id) =>
    (id & 0x01) == quicStreamIdClientBidi;

/// Offset reassembly + FIN for one QUIC STREAM (RFC 9000 §2.2 / §19.8).
final class QuicStreamReassembler {
  QuicStreamReassembler(this.id);

  final int id;
  final Map<int, Uint8List> _chunks = {};
  var _read = 0;
  var _finAt = -1;
  var _reset = false;
  final machine = quicStreamMachine();

  bool get isFin => _finAt >= 0 && _read >= _finAt;
  bool get isReset => _reset;
  int get buffered => _read;
  bool get hasBuffered => _chunks.containsKey(_read);

  Result<void, PqTransportError> add(QuicStreamFrame frame) {
    if (frame.id != id) {
      return Result.failure(PqTransportError.decodeFailure('stream id mix'));
    }
    if (_reset) {
      return Result.failure(PqTransportError.decodeFailure('stream reset'));
    }
    if (machine.currentState == QuicStreamState.idle) {
      final opened = machine.trigger(QuicStreamEvent.open);
      if (opened.isFailure) {
        return Result.failure(
          PqTransportError.decodeFailure('stream open illegal'),
        );
      }
    }
    if (frame.data.isNotEmpty) {
      _chunks[frame.offset] = Uint8List.fromList(frame.data);
      machine.trigger(QuicStreamEvent.data);
    }
    if (frame.fin) {
      final end = frame.offset + frame.data.length;
      if (_finAt >= 0 && _finAt != end) {
        return Result.failure(PqTransportError.decodeFailure('stream fin'));
      }
      _finAt = end;
      machine.trigger(QuicStreamEvent.fin);
    }
    return const Result.success(null);
  }

  Uint8List takeAvailable() {
    final out = BytesBuilder(copy: false);
    while (true) {
      final chunk = _chunks.remove(_read);
      if (chunk == null) break;
      out.add(chunk);
      _read += chunk.length;
    }
    if (isFin && machine.currentState == QuicStreamState.halfClosed) {
      machine.trigger(QuicStreamEvent.close);
    }
    return out.takeBytes();
  }

  void reset() {
    _reset = true;
    _chunks.clear();
    machine.trigger(QuicStreamEvent.reset);
  }
}

/// Per-connection STREAM map. Allocates client/server bidi and uni IDs.
final class QuicStreamMap {
  QuicStreamMap({required this.isClient})
    : _nextBidi = isClient ? quicStreamIdClientBidi : quicStreamIdServerBidi,
      _nextUni = isClient ? quicStreamIdClientUni : quicStreamIdServerUni;

  final bool isClient;
  final Map<int, QuicStreamReassembler> streams = {};
  var _nextBidi = 0;
  var _nextUni = 0;

  int openBidi() {
    final id = _nextBidi;
    _nextBidi += quicStreamIdIncrement;
    streams.putIfAbsent(id, () => QuicStreamReassembler(id));
    return id;
  }

  int openUni() {
    final id = _nextUni;
    _nextUni += quicStreamIdIncrement;
    streams.putIfAbsent(id, () => QuicStreamReassembler(id));
    return id;
  }

  Result<QuicStreamReassembler, PqTransportError> ingest(
    QuicStreamFrame frame,
  ) {
    final s = streams.putIfAbsent(
      frame.id,
      () => QuicStreamReassembler(frame.id),
    );
    final added = s.add(frame);
    if (added.isFailure) return Result.failure(added.errorOrNull!);
    return Result.success(s);
  }

  List<int> peerBidi({required bool clientInitiated}) {
    return streams.keys
        .where(
          (id) =>
              !quicStreamIsUnidirectional(id) &&
              quicStreamIsClientInitiated(id) == clientInitiated,
        )
        .toList();
  }
}
