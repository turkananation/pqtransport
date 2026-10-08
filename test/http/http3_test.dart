import 'dart:typed_data';

import 'package:pqtransport/pqtransport.dart';
import 'package:test/test.dart';

void main() {
  final crypto = PqTransportCrypto();

  Uint8List hex(String s) {
    final compact = s.replaceAll(RegExp(r'\s'), '');
    final out = Uint8List(compact.length ~/ 2);
    for (var i = 0; i < out.length; i++) {
      out[i] = int.parse(compact.substring(i * 2, i * 2 + 2), radix: 16);
    }
    return out;
  }

  group('QUIC STREAM', () {
    test('all type bits round-trip, including no-OFF and no-LEN', () {
      final full = QuicStreamFrame(
        id: 4,
        offset: 9,
        data: Uint8List.fromList([7, 8]),
        fin: true,
      );
      final dec = QuicStreamFrame.decode(full.encode());
      expect(dec.isSuccess, isTrue, reason: '${dec.errorOrNull}');
      expect(dec.valueOrNull!.id, 4);
      expect(dec.valueOrNull!.offset, 9);
      expect(dec.valueOrNull!.fin, isTrue);

      final noOff = QuicStreamFrame(
        id: 8,
        offset: 0,
        data: Uint8List.fromList([1, 2, 3]),
        hasOffset: false,
      );
      final d2 = QuicStreamFrame.decode(noOff.encode());
      expect(d2.valueOrNull!.offset, 0);
      expect(d2.valueOrNull!.hasOffset, isFalse);

      final noLen = QuicStreamFrame(
        id: 0,
        offset: 0,
        data: Uint8List.fromList([9, 9]),
        hasLength: false,
        fin: true,
      );
      final payload = noLen.encode();
      final parsed = decodeQuicPayload(payload);
      expect(parsed.isSuccess, isTrue, reason: '${parsed.errorOrNull}');
      expect(parsed.valueOrNull!.streams.single.data, [9, 9]);
      expect(parsed.valueOrNull!.streams.single.fin, isTrue);
    });

    test('reassembler fills gaps then FIN', () {
      final s = QuicStreamReassembler(0);
      expect(
        s
            .add(
              QuicStreamFrame(
                id: 0,
                offset: 3,
                data: Uint8List.fromList([3, 4]),
              ),
            )
            .isSuccess,
        isTrue,
      );
      expect(s.takeAvailable(), isEmpty);
      expect(
        s
            .add(
              QuicStreamFrame(
                id: 0,
                offset: 0,
                data: Uint8List.fromList([0, 1, 2]),
                fin: false,
              ),
            )
            .isSuccess,
        isTrue,
      );
      expect(s.takeAvailable(), [0, 1, 2, 3, 4]);
      expect(
        s
            .add(
              QuicStreamFrame(id: 0, offset: 5, data: Uint8List(0), fin: true),
            )
            .isSuccess,
        isTrue,
      );
      expect(s.isFin, isTrue);
    });

    test('conflicting FIN offsets fail closed', () {
      final s = QuicStreamReassembler(0);
      s.add(
        QuicStreamFrame(
          id: 0,
          offset: 0,
          data: Uint8List.fromList([1]),
          fin: true,
        ),
      );
      expect(
        s
            .add(
              QuicStreamFrame(
                id: 0,
                offset: 0,
                data: Uint8List.fromList([1, 2]),
                fin: true,
              ),
            )
            .isFailure,
        isTrue,
      );
    });
  });

  group('QPACK RFC 9204', () {
    test('static table has 99 entries and GET/200 pins', () {
      expect(qpackStaticTable, hasLength(qpackStaticTableLength));
      expect(qpackStaticTable[17], const HpackHeader(':method', 'GET'));
      expect(qpackStaticTable[25], const HpackHeader(':status', '200'));
      expect(qpackStaticTable[0].name, ':authority');
      expect(
        qpackStaticTable[98],
        const HpackHeader('x-frame-options', 'sameorigin'),
      );
    });

    test('Appendix B.1 literal field line with name reference', () {
      final dec = QpackCodec();
      final r = dec.decodeFieldSection(
        hex('0000 510b 2f69 6e64 6578 2e68 746d 6c'),
      );
      expect(r.isSuccess, isTrue, reason: '${r.errorOrNull}');
      expect(r.valueOrNull, [const HpackHeader(':path', '/index.html')]);
    });

    test('Appendix B.2–B.5 dynamic table, post-base, duplicate, eviction', () {
      final dec = QpackCodec(maxTableCapacity: 220);
      expect(
        dec
            .ingestEncoderStream(
              hex(
                '3fbd01'
                'c00f7777772e6578616d706c652e636f6d'
                'c10c2f73616d706c652f70617468',
              ),
            )
            .isSuccess,
        isTrue,
      );
      expect(dec.remoteInsertCount, 2);
      final b2 = dec.decodeFieldSection(hex('03811011'));
      expect(b2.isSuccess, isTrue, reason: '${b2.errorOrNull}');
      expect(b2.valueOrNull, [
        const HpackHeader(':authority', 'www.example.com'),
        const HpackHeader(':path', '/sample/path'),
      ]);

      expect(
        dec
            .ingestEncoderStream(
              hex('4a637573746f6d2d6b65790c637573746f6d2d76616c7565'),
            )
            .isSuccess,
        isTrue,
      );
      expect(dec.remoteInsertCount, 3);

      expect(dec.ingestEncoderStream(hex('02')).isSuccess, isTrue);
      expect(dec.remoteInsertCount, 4);
      final b4 = dec.decodeFieldSection(hex('050080c181'));
      expect(b4.isSuccess, isTrue, reason: '${b4.errorOrNull}');
      expect(b4.valueOrNull, [
        const HpackHeader(':authority', 'www.example.com'),
        const HpackHeader(':path', '/'),
        const HpackHeader('custom-key', 'custom-value'),
      ]);

      expect(
        dec
            .ingestEncoderStream(hex('810d637573746f6d2d76616c756532'))
            .isSuccess,
        isTrue,
      );
      expect(dec.remoteInsertCount, 5);
    });

    test('encoder/decoder stream ack and cancel round-trip', () {
      final c = QpackCodec(maxTableCapacity: 220);
      c.ackSection(4);
      c.cancelStream(8);
      c.incrementInsertCount(1);
      final wire = c.takeDecoderStream();
      expect(wire, hex('844801'));
      final peer = QpackCodec(maxTableCapacity: 220);
      expect(peer.ingestDecoderStream(wire).isSuccess, isTrue);
    });

    test('self-interop static GET/200 and Huffman literal', () {
      final enc = QpackCodec();
      final dec = QpackCodec();
      final req = enc.encodeFieldSection(const [
        HpackHeader(':method', 'GET'),
        HpackHeader(':scheme', 'https'),
        HpackHeader(':authority', 'example.test'),
        HpackHeader(':path', '/dns-query'),
      ]);
      final got = dec.decodeFieldSection(req);
      expect(got.isSuccess, isTrue, reason: '${got.errorOrNull}');
      expect(got.valueOrNull!.map((h) => '${h.name}:${h.value}').toList(), [
        ':method:GET',
        ':scheme:https',
        ':authority:example.test',
        ':path:/dns-query',
      ]);
      final huff = enc.encodeFieldSection(const [
        HpackHeader(':status', '200'),
        HpackHeader('content-type', 'text/plain'),
      ], huffman: true);
      final resp = dec.decodeFieldSection(huff);
      expect(resp.isSuccess, isTrue, reason: '${resp.errorOrNull}');
      expect(resp.valueOrNull!.first, const HpackHeader(':status', '200'));
    });

    test('blocked RIC fail-closed; oversized capacity fail-closed', () {
      final dec = QpackCodec(maxTableCapacity: 32);
      expect(dec.decodeFieldSection(hex('038110')).isFailure, isTrue);
      expect(dec.ingestEncoderStream(hex('3fe107')).isFailure, isTrue);
    });

    test('dynamic-table encode then decode on a peer codec', () {
      final enc = QpackCodec(maxTableCapacity: 4096);
      final dec = QpackCodec(maxTableCapacity: 4096);
      final block = enc.encodeFieldSection(const [
        HpackHeader(':method', 'GET'),
        HpackHeader(':path', '/dyn'),
        HpackHeader('x-custom', 'v1'),
      ], useDynamic: true);
      final inst = enc.takeEncoderStream();
      expect(dec.ingestEncoderStream(inst).isSuccess, isTrue);
      final got = dec.decodeFieldSection(block);
      expect(got.isSuccess, isTrue, reason: '${got.errorOrNull}');
      expect(
        got.valueOrNull!.any((h) => h.name == 'x-custom' && h.value == 'v1'),
        isTrue,
      );
    });
  });

  group('HTTP/3 frames', () {
    test('SETTINGS and HEADERS/DATA varint round-trip', () {
      final settings = encodeHttp3Settings(http3ClientSettings);
      final f = Http3Frame.decode(settings);
      expect(f.isSuccess, isTrue, reason: '${f.errorOrNull}');
      expect(f.valueOrNull!.type, http3FrameSettings);
      final decoded = decodeHttp3Settings(f.valueOrNull!.payload);
      expect(
        decoded.valueOrNull![http3SettingsQpackMaxTableCapacity],
        http3DefaultQpackMaxTableCapacity,
      );

      final data = Http3Frame(
        type: http3FrameData,
        payload: Uint8List.fromList([1, 2, 3]),
      );
      expect(Http3Frame.decode(data.encode()).valueOrNull!.payload, [1, 2, 3]);
    });

    test('duplicate SETTINGS identifier fail-closed', () {
      final b = BytesBuilder(copy: false);
      writeQuicVarint(b, http3SettingsQpackMaxTableCapacity);
      writeQuicVarint(b, 1);
      writeQuicVarint(b, http3SettingsQpackMaxTableCapacity);
      writeQuicVarint(b, 2);
      expect(decodeHttp3Settings(b.takeBytes()).isFailure, isTrue);
    });

    test('HEADERS + QPACK GET peels without QUIC', () {
      final q = QpackCodec(maxTableCapacity: http3DefaultQpackMaxTableCapacity);
      final block = q.encodeFieldSection(
        http3RequestHeaders(
          PqHttpRequest(
            method: 'GET',
            uri: Uri.parse('https://example.test/dns-query'),
          ),
        ),
      );
      final frame = Http3Frame(type: http3FrameHeaders, payload: block);
      final peeled = Http3Frame.tryDecode(frame.encode());
      expect(peeled.isSuccess, isTrue, reason: '${peeled.errorOrNull}');
      final dec = QpackCodec(
        maxTableCapacity: http3DefaultQpackMaxTableCapacity,
      ).decodeFieldSection(peeled.valueOrNull!.$1.payload);
      expect(dec.isSuccess, isTrue, reason: '${dec.errorOrNull}');
      expect(dec.valueOrNull!.first, const HpackHeader(':method', 'GET'));
    });
  });

  group('HTTP/3 over QUIC', () {
    test('PqQuicConn pair completes TLS-in-QUIC with ALPN h3', () async {
      final (client, server) = PqQuicConn.pair(
        crypto: crypto,
        alpnProtocols: const [httpAlpnH3],
      );
      final hs = await Future.wait([client.handshake(), server.handshake()]);
      expect(hs[0].isSuccess, isTrue, reason: '${hs[0].errorOrNull}');
      expect(hs[1].isSuccess, isTrue, reason: '${hs[1].errorOrNull}');
      expect(client.isComplete, isTrue);
      expect(server.isComplete, isTrue);
      expect(client.alpn, httpAlpnH3);
      expect(server.alpn, httpAlpnH3);
    }, timeout: const Timeout(Duration(seconds: 40)));

    test('STREAM GET/POST over 1-RTT after handshake', () async {
      final (client, server) = PqQuicConn.pair(
        crypto: crypto,
        alpnProtocols: const [httpAlpnH3],
      );
      final hs = await Future.wait([client.handshake(), server.handshake()]);
      expect(hs[0].isSuccess && hs[1].isSuccess, isTrue);

      final id = client.openBidi();
      expect(id, quicStreamIdClientBidi);
      final sent = await client.writeStream(
        id,
        Uint8List.fromList('ping'.codeUnits),
        fin: true,
      );
      expect(sent.isSuccess, isTrue, reason: '${sent.errorOrNull}');
      await Future<void>.delayed(const Duration(milliseconds: 50));
      expect(String.fromCharCodes(server.readStream(id)), 'ping');
      expect(server.streamFin(id), isTrue);
    }, timeout: const Timeout(Duration(seconds: 40)));

    test('HTTP/3 session start exchanges SETTINGS', () async {
      final (client, server) = PqQuicConn.pair(
        crypto: crypto,
        alpnProtocols: const [httpAlpnH3],
      );
      await Future.wait([client.handshake(), server.handshake()]);
      final h3c = PqHttp3Session.client(client);
      final h3s = PqHttp3Session.server(server);
      final starts = await Future.wait([h3c.start(), h3s.start()]);
      expect(starts[0].isSuccess, isTrue, reason: '${starts[0].errorOrNull}');
      expect(starts[1].isSuccess, isTrue, reason: '${starts[1].errorOrNull}');
      expect(h3c.isStarted, isTrue);
      expect(h3s.isStarted, isTrue);
    }, timeout: const Timeout(Duration(seconds: 40)));

    test('HTTP/3 GET over PqQuicConn ALPN h3', () async {
      final (client, server) = PqQuicConn.pair(
        crypto: crypto,
        alpnProtocols: const [httpAlpnH3],
      );
      final hs = await Future.wait([client.handshake(), server.handshake()]);
      expect(hs[0].isSuccess, isTrue, reason: '${hs[0].errorOrNull}');
      expect(hs[1].isSuccess, isTrue, reason: '${hs[1].errorOrNull}');

      final h3s = PqHttp3Session.server(server);
      final serverTask = () async {
        final accepted = await h3s.accept();
        expect(accepted.isSuccess, isTrue, reason: '${accepted.errorOrNull}');
        final (id, req) = accepted.valueOrNull!;
        expect(req.method, 'GET');
        expect(req.uri.path, '/dns-query');
        return h3s.respond(
          id,
          PqHttpResponse(
            status: 200,
            headers: const {'content-type': 'text/plain'},
            body: Uint8List.fromList('pq-h3'.codeUnits),
            version: HttpVersion.h3,
          ),
        );
      }();

      final resp = await PqHttpClient(prefer: HttpVersion.h3).roundTripH3(
        conn: client,
        request: PqHttpRequest(
          method: 'GET',
          uri: Uri.parse('https://example.test/dns-query'),
        ),
      );
      expect(resp.isSuccess, isTrue, reason: '${resp.errorOrNull}');
      expect(resp.valueOrNull!.status, 200);
      expect(resp.valueOrNull!.version, HttpVersion.h3);
      expect(String.fromCharCodes(resp.valueOrNull!.body), 'pq-h3');
      final served = await serverTask;
      expect(served.isSuccess, isTrue, reason: '${served.errorOrNull}');
    }, timeout: const Timeout(Duration(seconds: 40)));

    test('HTTP/3 POST carries DATA', () async {
      final (client, server) = PqQuicConn.pair(
        crypto: crypto,
        alpnProtocols: const [httpAlpnH3],
      );
      await Future.wait([client.handshake(), server.handshake()]);
      final h3c = PqHttp3Session.client(client);
      final h3s = PqHttp3Session.server(server);
      final serverTask = () async {
        final accepted = await h3s.accept();
        expect(accepted.isSuccess, isTrue, reason: '${accepted.errorOrNull}');
        final (id, req) = accepted.valueOrNull!;
        expect(req.method, 'POST');
        expect(String.fromCharCodes(req.body), 'body');
        return h3s.respond(
          id,
          PqHttpResponse(
            status: 200,
            headers: const {},
            body: Uint8List.fromList('ok'.codeUnits),
            version: HttpVersion.h3,
          ),
        );
      }();
      final started = await h3c.start();
      expect(started.isSuccess, isTrue, reason: '${started.errorOrNull}');
      final resp = await h3c.request(
        PqHttpRequest(
          method: 'POST',
          uri: Uri.parse('https://example.test/x'),
          body: 'body'.codeUnits,
        ),
      );
      expect(resp.isSuccess, isTrue, reason: '${resp.errorOrNull}');
      expect(String.fromCharCodes(resp.valueOrNull!.body), 'ok');
      await serverTask;
    }, timeout: const Timeout(Duration(seconds: 40)));

    test('roundTripH3 refuses incomplete QUIC and non-h3 ALPN', () async {
      final (client, _) = PqQuicConn.pair(crypto: crypto);
      final incomplete = await PqHttpClient().roundTripH3(
        conn: client,
        request: PqHttpRequest(
          method: 'GET',
          uri: Uri.parse('https://example.test/'),
        ),
      );
      expect(incomplete.isFailure, isTrue);
      expect(
        incomplete.errorOrNull!.code,
        PqTransportErrorCode.handshakeFailure,
      );

      final (c2, s2) = PqQuicConn.pair(
        crypto: crypto,
        alpnProtocols: const [httpAlpnH1],
      );
      await Future.wait([c2.handshake(), s2.handshake()]);
      final wrong = await PqHttpClient().roundTripH3(
        conn: c2,
        request: PqHttpRequest(
          method: 'GET',
          uri: Uri.parse('https://example.test/'),
        ),
      );
      expect(wrong.isFailure, isTrue);
    }, timeout: const Timeout(Duration(seconds: 40)));
  });
}
