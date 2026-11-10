import 'dart:typed_data';

import 'package:swissarmyknife/swissarmyknife.dart';

import '../core/bytes.dart';
import '../core/errors.dart';
import '../core/lengths.dart';
import 'packet.dart';

/// RFC 9000 §18 transport parameters. Unknown identifiers are ignored.
/// A duplicated identifier is a connection error.
final class QuicTransportParameters {
  const QuicTransportParameters({
    this.originalDestinationConnectionId,
    this.maxIdleTimeout = 0,
    this.statelessResetToken,
    this.maxUdpPayloadSize,
    this.initialMaxData = 0,
    this.initialMaxStreamDataBidiLocal = 0,
    this.initialMaxStreamDataBidiRemote = 0,
    this.initialMaxStreamDataUni = 0,
    this.initialMaxStreamsBidi = 0,
    this.initialMaxStreamsUni = 0,
    this.ackDelayExponent = quicAckDelayExponentDefault,
    this.maxAckDelay = quicMaxAckDelayMsDefault,
    this.disableActiveMigration = false,
    this.activeConnectionIdLimit = quicActiveConnectionIdLimitDefault,
    this.initialSourceConnectionId,
    this.retrySourceConnectionId,
    this.maxDatagramFrameSize = 0,
    this.initialMaxPathId,
  });

  final Uint8List? originalDestinationConnectionId;
  final int maxIdleTimeout;
  final Uint8List? statelessResetToken;
  final int? maxUdpPayloadSize;
  final int initialMaxData;
  final int initialMaxStreamDataBidiLocal;
  final int initialMaxStreamDataBidiRemote;
  final int initialMaxStreamDataUni;
  final int initialMaxStreamsBidi;
  final int initialMaxStreamsUni;
  final int ackDelayExponent;
  final int maxAckDelay;
  final bool disableActiveMigration;
  final int activeConnectionIdLimit;
  final Uint8List? initialSourceConnectionId;
  final Uint8List? retrySourceConnectionId;

  /// RFC 9221. Zero means datagrams are not offered.
  final int maxDatagramFrameSize;

  /// RFC 10069. Null means this endpoint does not offer multipath.
  /// A value of 0 offers the extension and no extra path yet.
  final int? initialMaxPathId;

  int get streamDataLimit {
    final values = [
      initialMaxStreamDataBidiLocal,
      initialMaxStreamDataBidiRemote,
      initialMaxStreamDataUni,
    ];
    var min = values.first;
    for (final value in values) {
      if (value < min) min = value;
    }
    return min;
  }

  Uint8List encode() {
    final b = BytesBuilder(copy: false);
    final odcid = originalDestinationConnectionId;
    if (odcid != null) {
      _bytes(b, quicTpOriginalDestinationConnectionId, odcid);
    }
    if (maxIdleTimeout > 0) {
      _varint(b, quicTpMaxIdleTimeout, maxIdleTimeout);
    }
    final token = statelessResetToken;
    if (token != null) {
      _bytes(b, quicTpStatelessResetToken, token);
    }
    final udp = maxUdpPayloadSize;
    if (udp != null) _varint(b, quicTpMaxUdpPayloadSize, udp);
    _varint(b, quicTpInitialMaxData, initialMaxData);
    _varint(
      b,
      quicTpInitialMaxStreamDataBidiLocal,
      initialMaxStreamDataBidiLocal,
    );
    _varint(
      b,
      quicTpInitialMaxStreamDataBidiRemote,
      initialMaxStreamDataBidiRemote,
    );
    _varint(b, quicTpInitialMaxStreamDataUni, initialMaxStreamDataUni);
    _varint(b, quicTpInitialMaxStreamsBidi, initialMaxStreamsBidi);
    _varint(b, quicTpInitialMaxStreamsUni, initialMaxStreamsUni);
    if (ackDelayExponent != quicAckDelayExponentDefault) {
      _varint(b, quicTpAckDelayExponent, ackDelayExponent);
    }
    if (maxAckDelay != quicMaxAckDelayMsDefault) {
      _varint(b, quicTpMaxAckDelay, maxAckDelay);
    }
    if (disableActiveMigration) {
      _bytes(b, quicTpDisableActiveMigration, Uint8List(0));
    }
    if (activeConnectionIdLimit != quicActiveConnectionIdLimitDefault) {
      _varint(b, quicTpActiveConnectionIdLimit, activeConnectionIdLimit);
    }
    final scid = initialSourceConnectionId;
    if (scid != null) {
      _bytes(b, quicTpInitialSourceConnectionId, scid);
    }
    final rcid = retrySourceConnectionId;
    if (rcid != null) {
      _bytes(b, quicTpRetrySourceConnectionId, rcid);
    }
    if (maxDatagramFrameSize > 0) {
      _varint(b, quicTpMaxDatagramFrameSize, maxDatagramFrameSize);
    }
    final pathId = initialMaxPathId;
    if (pathId != null) {
      _varint(b, quicTpInitialMaxPathId, pathId);
    }
    return b.takeBytes();
  }

  static Result<QuicTransportParameters, PqTransportError> decode(
    Uint8List wire,
  ) {
    final r = ByteReader(wire);
    final seen = <int>{};
    Uint8List? odcid;
    var idle = 0;
    Uint8List? reset;
    int? udp;
    var maxData = 0;
    var bidiLocal = 0;
    var bidiRemote = 0;
    var uni = 0;
    var streamsBidi = 0;
    var streamsUni = 0;
    var ackExp = quicAckDelayExponentDefault;
    var ackDelay = quicMaxAckDelayMsDefault;
    var disableMigration = false;
    var active = quicActiveConnectionIdLimitDefault;
    Uint8List? scid;
    Uint8List? rcid;
    var datagram = 0;
    int? pathId;
    while (r.remaining > 0) {
      final id = readVarint(r);
      final len = readVarint(r);
      if (id < 0 || len < 0 || r.remaining < len) {
        return Result.failure(
          PqTransportError.decodeFailure('transport parameter'),
        );
      }
      if (!seen.add(id)) {
        return Result.failure(
          PqTransportError.decodeFailure('duplicate transport parameter'),
        );
      }
      final value = r.take(len, PqLengthLabel.tlsExtension);
      if (value.isFailure) return Result.failure(value.errorOrNull!);
      final bytes = value.valueOrNull!;
      switch (id) {
        case quicTpOriginalDestinationConnectionId:
          odcid = bytes;
        case quicTpMaxIdleTimeout:
          idle = _readVarintBytes(bytes);
        case quicTpStatelessResetToken:
          if (bytes.length != quicStatelessResetTokenBytes) {
            return Result.failure(
              PqTransportError.decodeFailure('stateless_reset_token'),
            );
          }
          reset = bytes;
        case quicTpMaxUdpPayloadSize:
          udp = _readVarintBytes(bytes);
        case quicTpInitialMaxData:
          maxData = _readVarintBytes(bytes);
        case quicTpInitialMaxStreamDataBidiLocal:
          bidiLocal = _readVarintBytes(bytes);
        case quicTpInitialMaxStreamDataBidiRemote:
          bidiRemote = _readVarintBytes(bytes);
        case quicTpInitialMaxStreamDataUni:
          uni = _readVarintBytes(bytes);
        case quicTpInitialMaxStreamsBidi:
          streamsBidi = _readVarintBytes(bytes);
        case quicTpInitialMaxStreamsUni:
          streamsUni = _readVarintBytes(bytes);
        case quicTpAckDelayExponent:
          ackExp = _readVarintBytes(bytes);
        case quicTpMaxAckDelay:
          ackDelay = _readVarintBytes(bytes);
        case quicTpDisableActiveMigration:
          if (bytes.isNotEmpty) {
            return Result.failure(
              PqTransportError.decodeFailure('disable_active_migration'),
            );
          }
          disableMigration = true;
        case quicTpActiveConnectionIdLimit:
          active = _readVarintBytes(bytes);
          if (active < 2) {
            return Result.failure(
              PqTransportError.decodeFailure('active_connection_id_limit'),
            );
          }
        case quicTpInitialSourceConnectionId:
          scid = bytes;
        case quicTpRetrySourceConnectionId:
          rcid = bytes;
        case quicTpMaxDatagramFrameSize:
          datagram = _readVarintBytes(bytes);
        case quicTpInitialMaxPathId:
          pathId = _readVarintBytes(bytes);
          if (pathId < 0 || pathId > 0xffffffff) {
            return Result.failure(
              PqTransportError.decodeFailure('initial_max_path_id'),
            );
          }
        default:
          break;
      }
      if (idle < 0 ||
          (udp != null && udp < 0) ||
          maxData < 0 ||
          bidiLocal < 0 ||
          bidiRemote < 0 ||
          uni < 0 ||
          streamsBidi < 0 ||
          streamsUni < 0 ||
          ackExp < 0 ||
          ackDelay < 0 ||
          datagram < 0) {
        return Result.failure(
          PqTransportError.decodeFailure('transport parameter varint'),
        );
      }
    }
    return Result.success(
      QuicTransportParameters(
        originalDestinationConnectionId: odcid,
        maxIdleTimeout: idle,
        statelessResetToken: reset,
        maxUdpPayloadSize: udp,
        initialMaxData: maxData,
        initialMaxStreamDataBidiLocal: bidiLocal,
        initialMaxStreamDataBidiRemote: bidiRemote,
        initialMaxStreamDataUni: uni,
        initialMaxStreamsBidi: streamsBidi,
        initialMaxStreamsUni: streamsUni,
        ackDelayExponent: ackExp,
        maxAckDelay: ackDelay,
        disableActiveMigration: disableMigration,
        activeConnectionIdLimit: active,
        initialSourceConnectionId: scid,
        retrySourceConnectionId: rcid,
        maxDatagramFrameSize: datagram,
        initialMaxPathId: pathId,
      ),
    );
  }

  /// Required connection IDs (RFC 9000 §18.2). [peerIsServer] is the role
  /// of the endpoint that sent [this].
  Result<void, PqTransportError> check({
    required bool peerIsServer,
    required Uint8List expectedInitialSource,
    Uint8List? expectedOriginalDestination,
    Uint8List? expectedRetrySource,
  }) {
    final source = initialSourceConnectionId;
    if (source == null || !_same(source, expectedInitialSource)) {
      return Result.failure(
        PqTransportError.decodeFailure('initial_source_connection_id'),
      );
    }
    if (peerIsServer) {
      final odcid = originalDestinationConnectionId;
      if (expectedOriginalDestination == null ||
          odcid == null ||
          !_same(odcid, expectedOriginalDestination)) {
        return Result.failure(
          PqTransportError.decodeFailure('original_destination_connection_id'),
        );
      }
      final retry = retrySourceConnectionId;
      if (expectedRetrySource == null) {
        if (retry != null) {
          return Result.failure(
            PqTransportError.decodeFailure('retry_source_connection_id'),
          );
        }
      } else if (retry == null || !_same(retry, expectedRetrySource)) {
        return Result.failure(
          PqTransportError.decodeFailure('retry_source_connection_id'),
        );
      }
    } else if (originalDestinationConnectionId != null ||
        retrySourceConnectionId != null ||
        statelessResetToken != null) {
      return Result.failure(
        PqTransportError.decodeFailure('client transport parameter'),
      );
    }
    return const Result.success(null);
  }

  static void _varint(BytesBuilder b, int id, int value) {
    final body = BytesBuilder(copy: false);
    writeQuicVarint(body, value);
    _bytes(b, id, body.takeBytes());
  }

  static void _bytes(BytesBuilder b, int id, Uint8List value) {
    writeQuicVarint(b, id);
    writeQuicVarint(b, value.length);
    b.add(value);
  }

  static int _readVarintBytes(Uint8List bytes) {
    final r = ByteReader(bytes);
    final value = readVarint(r);
    if (!r.isDone) return -1;
    return value;
  }

  static bool _same(Uint8List a, Uint8List b) {
    if (a.length != b.length) return false;
    for (var i = 0; i < a.length; i++) {
      if (a[i] != b[i]) return false;
    }
    return true;
  }
}

/// Parameters this endpoint sends. A server's original destination CID is
/// the DCID on the client's first Initial. It is not the server's source CID
/// unless the client chose that value, which only the in-memory pair does.
Uint8List quicEndpointParameters({
  required bool server,
  required Uint8List localCid,
  required int maxData,
  required int maxStreamData,
  Uint8List? statelessResetToken,
  int maxIdleTimeoutMs = 0,
  int? initialMaxPathId,
}) {
  return QuicTransportParameters(
    originalDestinationConnectionId: server ? localCid : null,
    statelessResetToken: server ? statelessResetToken : null,
    maxIdleTimeout: maxIdleTimeoutMs,
    initialMaxData: maxData,
    initialMaxStreamDataBidiLocal: maxStreamData,
    initialMaxStreamDataBidiRemote: maxStreamData,
    initialMaxStreamDataUni: maxStreamData,
    initialMaxStreamsBidi: quicInitialMaxStreams,
    initialMaxStreamsUni: quicInitialMaxStreams,
    activeConnectionIdLimit: 4,
    initialSourceConnectionId: localCid,
    maxDatagramFrameSize: quicLocalMaxDatagramFrameSize,
    initialMaxPathId: initialMaxPathId,
  ).encode();
}
