import 'dart:typed_data';

import 'package:swissarmyknife/swissarmyknife.dart';

import '../core/bytes.dart';
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
  final List<_QuicByteSpan> _spans = [];
  var _read = 0;
  var _finAt = -1;
  var _reset = false;
  final machine = quicStreamMachine();

  bool get isFin => _finAt >= 0 && _read >= _finAt;
  bool get isReset => _reset;
  int get buffered => _read;
  bool get hasBuffered => _spans.isNotEmpty && _spans.first.offset == _read;

  /// RFC 9000 §2.2. Overlapping STREAM data is legal when every shared
  /// byte matches. A retransmission must not be delivered twice.
  Result<void, PqTransportError> _merge(int offset, Uint8List data) {
    if (data.isEmpty) return const Result.success(null);
    var start = offset;
    var bytes = data;
    if (start < _read) {
      final skip = _read - start;
      if (skip >= bytes.length) return const Result.success(null);
      bytes = Uint8List.sublistView(bytes, skip);
      start = _read;
    }
    final end = start + bytes.length;
    for (final span in _spans) {
      final overlapStart = start > span.offset ? start : span.offset;
      final overlapEnd = end < span.end ? end : span.end;
      if (overlapStart >= overlapEnd) continue;
      for (var i = overlapStart; i < overlapEnd; i++) {
        if (bytes[i - start] != span.data[i - span.offset]) {
          return Result.failure(
            PqTransportError.decodeFailure('stream conflict'),
          );
        }
      }
    }
    _spans.add(_QuicByteSpan(start, Uint8List.fromList(bytes)));
    _coalesce();
    return const Result.success(null);
  }

  void _coalesce() {
    if (_spans.length < 2) return;
    _spans.sort((a, b) => a.offset.compareTo(b.offset));
    final merged = <_QuicByteSpan>[_spans.first];
    for (var i = 1; i < _spans.length; i++) {
      final next = _spans[i];
      final prev = merged.last;
      if (next.offset > prev.end) {
        merged.add(next);
        continue;
      }
      if (next.end <= prev.end) continue;
      final skip = prev.end - next.offset;
      final tail = Uint8List.sublistView(next.data, skip);
      prev.data = concatBytes([prev.data, tail]);
    }
    _spans
      ..clear()
      ..addAll(merged);
  }

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
      final merged = _merge(frame.offset, frame.data);
      if (merged.isFailure) return Result.failure(merged.errorOrNull!);
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
    while (_spans.isNotEmpty && _spans.first.offset == _read) {
      final span = _spans.removeAt(0);
      out.add(span.data);
      _read += span.data.length;
    }
    if (isFin && machine.currentState == QuicStreamState.halfClosed) {
      machine.trigger(QuicStreamEvent.close);
    }
    return out.takeBytes();
  }

  void reset() {
    _reset = true;
    _spans.clear();
    machine.trigger(QuicStreamEvent.reset);
  }
}

final class _QuicByteSpan {
  _QuicByteSpan(this.offset, this.data);

  final int offset;
  Uint8List data;

  int get end => offset + data.length;
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
