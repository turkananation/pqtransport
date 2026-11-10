import 'dart:typed_data';

import 'package:swissarmyknife/swissarmyknife.dart';

import '../core/bytes.dart';
import '../core/errors.dart';
import '../quic/packet.dart';
import 'capsule.dart';
import 'connect_udp.dart';
import 'http3.dart';
import 'pq_http_client.dart';

/// RFC 9484 §4.7. One assigned or requested prefix.
final class IpPrefix {
  const IpPrefix({
    required this.version,
    required this.address,
    required this.prefixLength,
  });

  final int version;
  final Uint8List address;
  final int prefixLength;

  int get _bits => version == 4 ? 32 : 128;

  bool get valid {
    if (version != 4 && version != 6) return false;
    if (address.length != _bits ~/ 8) return false;
    if (prefixLength < 0 || prefixLength > _bits) return false;
    return _lowerBitsZero(address, prefixLength);
  }
}

/// RFC 9484 §4.7.3. Inclusive range. Protocol 0 is every protocol.
/// ICMP is always allowed by the receiver even when protocol is not 0.
final class IpRange {
  const IpRange({
    required this.version,
    required this.start,
    required this.end,
    required this.protocol,
  });

  final int version;
  final Uint8List start;
  final Uint8List end;
  final int protocol;
}

final class AssignedAddress {
  const AssignedAddress({required this.requestId, required this.prefix});

  final int requestId;
  final IpPrefix prefix;
}

final class RequestedAddress {
  const RequestedAddress({required this.requestId, required this.prefix});

  /// Request ID 0 is forbidden on ADDRESS_REQUEST.
  final int requestId;
  final IpPrefix prefix;
}

bool _lowerBitsZero(Uint8List address, int prefixLength) {
  var left = prefixLength;
  for (final byte in address) {
    if (left >= 8) {
      left -= 8;
      continue;
    }
    final mask = left <= 0 ? 0xff : (0xff >> left);
    if ((byte & mask) != 0) return false;
    left = 0;
  }
  return true;
}

int _cmpAddr(Uint8List a, Uint8List b) {
  final n = a.length < b.length ? a.length : b.length;
  for (var i = 0; i < n; i++) {
    if (a[i] != b[i]) return a[i] - b[i];
  }
  return a.length - b.length;
}

bool _prefixMatch(Uint8List address, IpPrefix prefix) {
  if (!prefix.valid || address.length != prefix.address.length) return false;
  var left = prefix.prefixLength;
  for (var i = 0; i < address.length; i++) {
    if (left <= 0) return true;
    final n = left >= 8 ? 8 : left;
    final mask = n == 8 ? 0xff : ((0xff << (8 - n)) & 0xff);
    if ((address[i] & mask) != (prefix.address[i] & mask)) return false;
    left -= n;
  }
  return true;
}

Uint8List _encodeAddress(int requestId, IpPrefix prefix) {
  final b = BytesBuilder(copy: false);
  writeQuicVarint(b, requestId);
  b.addByte(prefix.version);
  b.add(prefix.address);
  b.addByte(prefix.prefixLength);
  return b.takeBytes();
}

({int requestId, IpPrefix prefix, int consumed})? _readAddress(
  Uint8List wire,
  int offset, {
  required bool request,
}) {
  final reader = ByteReader(slice(wire, offset, wire.length));
  final requestId = readVarint(reader);
  if (requestId < 0 || reader.remaining < 2) return null;
  if (request && requestId == 0) return null;
  final version = wire[offset + reader.offset];
  reader.offset++;
  final len = version == 4 ? 4 : (version == 6 ? 16 : -1);
  if (len < 0 || reader.remaining < len + 1) return null;
  final address = slice(
    wire,
    offset + reader.offset,
    offset + reader.offset + len,
  );
  reader.offset += len;
  final prefixLength = wire[offset + reader.offset];
  reader.offset++;
  final prefix = IpPrefix(
    version: version,
    address: address,
    prefixLength: prefixLength,
  );
  if (!prefix.valid) return null;
  return (
    requestId: requestId,
    prefix: prefix,
    consumed: offset + reader.offset,
  );
}

/// ADDRESS_ASSIGN capsule value. An empty list removes every address.
Result<Uint8List, PqTransportError> encodeAddressAssign(
  List<AssignedAddress> addresses,
) {
  final b = BytesBuilder(copy: false);
  for (final address in addresses) {
    if (!address.prefix.valid || address.requestId < 0) {
      return Result.failure(PqTransportError.decodeFailure('ADDRESS_ASSIGN'));
    }
    b.add(_encodeAddress(address.requestId, address.prefix));
  }
  return Result.success(b.takeBytes());
}

Result<List<AssignedAddress>, PqTransportError> decodeAddressAssign(
  Uint8List value,
) {
  final out = <AssignedAddress>[];
  var offset = 0;
  while (offset < value.length) {
    final one = _readAddress(value, offset, request: false);
    if (one == null) {
      return Result.failure(PqTransportError.decodeFailure('ADDRESS_ASSIGN'));
    }
    out.add(AssignedAddress(requestId: one.requestId, prefix: one.prefix));
    offset = one.consumed;
  }
  return Result.success(out);
}

/// ADDRESS_REQUEST. Zero addresses abort the stream.
Result<Uint8List, PqTransportError> encodeAddressRequest(
  List<RequestedAddress> addresses,
) {
  if (addresses.isEmpty) {
    return Result.failure(PqTransportError.decodeFailure('ADDRESS_REQUEST'));
  }
  final seen = <int>{};
  final b = BytesBuilder(copy: false);
  for (final address in addresses) {
    if (!address.prefix.valid ||
        address.requestId == 0 ||
        !seen.add(address.requestId)) {
      return Result.failure(PqTransportError.decodeFailure('ADDRESS_REQUEST'));
    }
    b.add(_encodeAddress(address.requestId, address.prefix));
  }
  return Result.success(b.takeBytes());
}

Result<List<RequestedAddress>, PqTransportError> decodeAddressRequest(
  Uint8List value,
) {
  if (value.isEmpty) {
    return Result.failure(PqTransportError.decodeFailure('ADDRESS_REQUEST'));
  }
  final out = <RequestedAddress>[];
  final seen = <int>{};
  var offset = 0;
  while (offset < value.length) {
    final one = _readAddress(value, offset, request: true);
    if (one == null || !seen.add(one.requestId)) {
      return Result.failure(PqTransportError.decodeFailure('ADDRESS_REQUEST'));
    }
    out.add(RequestedAddress(requestId: one.requestId, prefix: one.prefix));
    offset = one.consumed;
  }
  return Result.success(out);
}

Result<Uint8List, PqTransportError> encodeRouteAdvertisement(
  List<IpRange> ranges,
) {
  final checked = _ordered(ranges);
  if (checked.isFailure) return Result.failure(checked.errorOrNull!);
  final b = BytesBuilder(copy: false);
  for (final range in ranges) {
    b.addByte(range.version);
    b.add(range.start);
    b.add(range.end);
    b.addByte(range.protocol);
  }
  return Result.success(b.takeBytes());
}

Result<List<IpRange>, PqTransportError> decodeRouteAdvertisement(
  Uint8List value,
) {
  final out = <IpRange>[];
  var offset = 0;
  while (offset < value.length) {
    if (offset >= value.length) break;
    final version = value[offset];
    final len = version == 4 ? 4 : (version == 6 ? 16 : -1);
    if (len < 0 || value.length < offset + 1 + len + len + 1) {
      return Result.failure(
        PqTransportError.decodeFailure('ROUTE_ADVERTISEMENT'),
      );
    }
    final start = slice(value, offset + 1, offset + 1 + len);
    final end = slice(value, offset + 1 + len, offset + 1 + len + len);
    final protocol = value[offset + 1 + len + len];
    if (_cmpAddr(start, end) > 0) {
      return Result.failure(
        PqTransportError.decodeFailure('ROUTE_ADVERTISEMENT'),
      );
    }
    out.add(
      IpRange(version: version, start: start, end: end, protocol: protocol),
    );
    offset += 1 + len + len + 1;
  }
  return _ordered(out);
}

Result<List<IpRange>, PqTransportError> _ordered(List<IpRange> ranges) {
  int? version;
  Uint8List? end;
  int? protocol;
  for (final range in ranges) {
    final len = range.version == 4 ? 4 : (range.version == 6 ? 16 : -1);
    if (len < 0 ||
        range.start.length != len ||
        range.end.length != len ||
        _cmpAddr(range.start, range.end) > 0) {
      return Result.failure(
        PqTransportError.decodeFailure('ROUTE_ADVERTISEMENT'),
      );
    }
    if (version != null) {
      if (range.version < version) {
        return Result.failure(
          PqTransportError.decodeFailure('ROUTE_ADVERTISEMENT'),
        );
      }
      if (range.version == version &&
          range.protocol == protocol &&
          end != null &&
          _cmpAddr(end, range.start) >= 0) {
        return Result.failure(
          PqTransportError.decodeFailure('ROUTE_ADVERTISEMENT'),
        );
      }
    }
    version = range.version;
    end = range.end;
    protocol = range.protocol;
  }
  return Result.success(ranges);
}

/// Source must be assigned. Destination must be advertised.
/// ICMP (1) and ICMPv6 (58) are forwarded even when the route names
/// another protocol. An unknown context ID is not an IP packet.
final class IpProxyPolicy {
  List<AssignedAddress> assigned = const [];
  List<IpRange> routes = const [];

  Result<void, PqTransportError> assign(Uint8List capsuleValue) {
    final decoded = decodeAddressAssign(capsuleValue);
    if (decoded.isFailure) return Result.failure(decoded.errorOrNull!);
    assigned = decoded.valueOrNull!;
    return const Result.success(null);
  }

  Result<void, PqTransportError> advertise(Uint8List capsuleValue) {
    final decoded = decodeRouteAdvertisement(capsuleValue);
    if (decoded.isFailure) return Result.failure(decoded.errorOrNull!);
    routes = decoded.valueOrNull!;
    return const Result.success(null);
  }

  bool allow(Uint8List packet) {
    if (packet.isEmpty) return false;
    final version = packet[0] >> 4;
    late final Uint8List source;
    late final Uint8List destination;
    late final int protocol;
    if (version == 4) {
      if (packet.length < 20) return false;
      source = slice(packet, 12, 16);
      destination = slice(packet, 16, 20);
      protocol = packet[9];
    } else if (version == 6) {
      if (packet.length < 40) return false;
      source = slice(packet, 8, 24);
      destination = slice(packet, 24, 40);
      protocol = packet[6];
    } else {
      return false;
    }
    if (!_assigned(version, source)) return false;
    if (protocol == 1 || protocol == 58) return true;
    return _routed(version, destination, protocol);
  }

  bool _assigned(int version, Uint8List source) {
    for (final address in assigned) {
      if (address.prefix.version == version &&
          _prefixMatch(source, address.prefix)) {
        return true;
      }
    }
    return false;
  }

  bool _routed(int version, Uint8List destination, int protocol) {
    for (final route in routes) {
      if (route.version != version) continue;
      if (route.protocol != 0 && route.protocol != protocol) continue;
      if (_cmpAddr(destination, route.start) >= 0 &&
          _cmpAddr(destination, route.end) <= 0) {
        return true;
      }
    }
    return false;
  }
}

/// RFC 9484. `target` is `*`, a host, or an address. `ipproto` is `*`
/// or 0–255. IPv6 colons are percent-encoded. A prefix uses `%2F`.
Result<String, PqTransportError> connectIpPath({
  required String target,
  required String ipProtocol,
}) {
  if (target.isEmpty || target.contains(' ') || target.contains('%')) {
    return Result.failure(PqTransportError.decodeFailure('connect-ip target'));
  }
  if (ipProtocol != '*') {
    final proto = int.tryParse(ipProtocol);
    if (proto == null || proto < 0 || proto > 255) {
      return Result.failure(
        PqTransportError.decodeFailure('connect-ip protocol'),
      );
    }
  }
  final encoded = target == '*'
      ? '*'
      : target.contains(':')
      ? Uri.encodeComponent(target)
      : target;
  return Result.success('/.well-known/masque/ip/$encoded/$ipProtocol/');
}

Result<PqHttpRequest, PqTransportError> connectIpRequest({
  required String proxyHost,
  required String target,
  String ipProtocol = '*',
  int? proxyPort,
  String scheme = 'https',
}) {
  final path = connectIpPath(target: target, ipProtocol: ipProtocol);
  if (path.isFailure) return Result.failure(path.errorOrNull!);
  return Result.success(
    PqHttpRequest(
      method: 'CONNECT',
      uri: Uri(
        scheme: scheme,
        host: proxyHost,
        port: proxyPort,
        path: path.valueOrNull,
      ),
      protocol: 'connect-ip',
      headers: const {'capsule-protocol': '?1'},
    ),
  );
}

HttpCapsule addressAssignCapsule(List<AssignedAddress> addresses) {
  final value = encodeAddressAssign(addresses);
  if (value.isFailure) {
    throw StateError('ADDRESS_ASSIGN');
  }
  return HttpCapsule(type: 0x01, value: value.valueOrNull!);
}

HttpCapsule addressRequestCapsule(List<RequestedAddress> addresses) {
  final value = encodeAddressRequest(addresses);
  if (value.isFailure) {
    throw StateError('ADDRESS_REQUEST');
  }
  return HttpCapsule(type: 0x02, value: value.valueOrNull!);
}

HttpCapsule routeAdvertisementCapsule(List<IpRange> ranges) {
  final value = encodeRouteAdvertisement(ranges);
  if (value.isFailure) {
    throw StateError('ROUTE_ADVERTISEMENT');
  }
  return HttpCapsule(type: 0x03, value: value.valueOrNull!);
}

/// ICMP used when an IP packet does not fit in a QUIC DATAGRAM.
/// ICMPv4 type 3 code 4, or ICMPv6 type 2 code 0. The result is an
/// IP packet the tunnel can send back. It is not a silent capsule.
Uint8List icmpPacketTooBig(Uint8List original, int mtu) {
  if (original.isEmpty) return Uint8List(0);
  final version = original[0] >> 4;
  if (version == 6) return _icmp6TooBig(original, mtu);
  return _icmp4TooBig(original, mtu);
}

Uint8List _icmp4TooBig(Uint8List original, int mtu) {
  final quoted = original.length < 28 ? original : slice(original, 0, 28);
  final icmp = BytesBuilder(copy: false)
    ..addByte(3)
    ..addByte(4)
    ..addByte(0)
    ..addByte(0)
    ..addByte(0)
    ..addByte(0)
    ..addByte((mtu >> 8) & 0xff)
    ..addByte(mtu & 0xff)
    ..add(quoted);
  final icmpBytes = icmp.takeBytes();
  _writeChecksum(icmpBytes, 2);
  final total = 20 + icmpBytes.length;
  final header = Uint8List(20);
  header[0] = 0x45;
  header[2] = (total >> 8) & 0xff;
  header[3] = total & 0xff;
  header[8] = 64;
  header[9] = 1;
  if (original.length >= 20) {
    header.setRange(12, 16, original.sublist(16, 20));
    header.setRange(16, 20, original.sublist(12, 16));
  }
  _writeChecksum(header, 10);
  return concatBytes([header, icmpBytes]);
}

Uint8List _icmp6TooBig(Uint8List original, int mtu) {
  final quoted = original.length < 1232 ? original : slice(original, 0, 1232);
  final body = BytesBuilder(copy: false)
    ..addByte(2)
    ..addByte(0)
    ..addByte(0)
    ..addByte(0)
    ..addByte((mtu >> 24) & 0xff)
    ..addByte((mtu >> 16) & 0xff)
    ..addByte((mtu >> 8) & 0xff)
    ..addByte(mtu & 0xff)
    ..add(quoted);
  final icmp = body.takeBytes();
  final payloadLength = icmp.length;
  final header = Uint8List(40);
  header[0] = 0x60;
  header[4] = (payloadLength >> 8) & 0xff;
  header[5] = payloadLength & 0xff;
  header[6] = 58;
  header[7] = 64;
  if (original.length >= 40) {
    header.setRange(8, 24, original.sublist(24, 40));
    header.setRange(24, 40, original.sublist(8, 24));
  }
  _icmp6Checksum(header, icmp);
  return concatBytes([header, icmp]);
}

void _writeChecksum(Uint8List bytes, int offset) {
  var sum = 0;
  for (var i = 0; i < bytes.length; i += 2) {
    final hi = bytes[i];
    final lo = i + 1 < bytes.length ? bytes[i + 1] : 0;
    sum += (hi << 8) | lo;
  }
  while ((sum >> 16) != 0) {
    sum = (sum & 0xffff) + (sum >> 16);
  }
  final checksum = ~sum & 0xffff;
  bytes[offset] = (checksum >> 8) & 0xff;
  bytes[offset + 1] = checksum & 0xff;
}

void _icmp6Checksum(Uint8List header, Uint8List icmp) {
  var sum = 0;
  void add(int value) {
    sum += value;
  }

  for (var i = 8; i < 40; i += 2) {
    add((header[i] << 8) | header[i + 1]);
  }
  add(icmp.length);
  add(58);
  for (var i = 0; i < icmp.length; i += 2) {
    final hi = icmp[i];
    final lo = i + 1 < icmp.length ? icmp[i + 1] : 0;
    add((hi << 8) | lo);
  }
  while ((sum >> 16) != 0) {
    sum = (sum & 0xffff) + (sum >> 16);
  }
  final checksum = ~sum & 0xffff;
  icmp[2] = (checksum >> 8) & 0xff;
  icmp[3] = checksum & 0xff;
}

/// One CONNECT-IP tunnel. Context ID 0 carries one IP packet.
/// Packets that fail [policy] are dropped, not reset.
final class PqConnectIpTunnel {
  PqConnectIpTunnel(this.session, this.streamId);

  final PqHttp3Session session;
  final int streamId;
  final IpProxyPolicy policy = IpProxyPolicy();

  Future<Result<void, PqTransportError>> sendCapsule(HttpCapsule capsule) {
    return session.sendCapsule(streamId, capsule);
  }

  Future<Result<void, PqTransportError>> sendIp(
    Uint8List packet, {
    int maxDatagram = 65535,
  }) async {
    if (!policy.allow(packet)) {
      return Result.failure(PqTransportError.decodeFailure('connect-ip drop'));
    }
    if (packet.length > maxDatagram) {
      return Result.failure(PqTransportError.decodeFailure('connect-ip mtu'));
    }
    final body = encodeProxyDatagram(0, packet);
    if (session.quicHttpDatagrams) {
      return session.sendHttpDatagram(streamId, body);
    }
    return session.sendDatagramCapsule(streamId, body);
  }

  List<Uint8List> take() {
    final out = <Uint8List>[];
    for (final payload in session.takeStreamDatagrams(streamId)) {
      final parsed = decodeProxyDatagram(payload);
      if (parsed == null || parsed.contextId != 0) continue;
      if (!policy.allow(parsed.payload)) continue;
      out.add(parsed.payload);
    }
    return out;
  }
}
