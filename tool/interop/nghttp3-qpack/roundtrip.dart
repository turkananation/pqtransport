import 'dart:io';

import 'package:pqtransport/pqtransport.dart';

/// Encode a static-table DoH field section, or decode one produced by
/// libnghttp3 after ingesting its encoder stream.
///
/// `encode <section.bin>`
/// `decode <section.bin> <encoder.bin>`
/// `headers` writes the expected `name\tvalue` lines.
void main(List<String> args) {
  const headers = <HpackHeader>[
    HpackHeader(':method', 'POST'),
    HpackHeader(':scheme', 'https'),
    HpackHeader(':authority', 'dns.example'),
    HpackHeader(':path', '/dns-query'),
    HpackHeader('content-type', dnsMessageMediaType),
    HpackHeader('accept', dnsMessageMediaType),
  ];
  switch (args.first) {
    case 'headers':
      for (final h in headers) {
        stdout.writeln('${h.name}\t${h.value}');
      }
    case 'encode':
      final codec = QpackCodec(maxTableCapacity: 0);
      final section = codec.encodeFieldSection(headers, useDynamic: false);
      File(args[1]).writeAsBytesSync(section);
    case 'decode':
      final codec = QpackCodec(maxTableCapacity: 0);
      final enc = File(args[2]).readAsBytesSync();
      if (enc.isNotEmpty) {
        final ingested = codec.ingestEncoderStream(enc);
        if (ingested.isFailure) {
          stderr.writeln('ingest ${ingested.errorOrNull}');
          exitCode = 1;
          return;
        }
      }
      final decoded = codec.decodeFieldSection(File(args[1]).readAsBytesSync());
      if (decoded.isFailure) {
        stderr.writeln('decode ${decoded.errorOrNull}');
        exitCode = 1;
        return;
      }
      for (final h in decoded.valueOrNull!) {
        stdout.writeln('${h.name}\t${h.value}');
      }
    case 'encode-dynamic':
      final codec = QpackCodec(maxTableCapacity: 4096);
      codec.applyPeerLimits(maxTableCapacity: 4096, blockedStreams: 1);
      final section = codec.encodeFieldSection(headers, useDynamic: true);
      final enc = codec.takeEncoderStream();
      if (enc.isEmpty || codec.insertCount == 0) {
        stderr.writeln(
          'section did not use the dynamic table '
          'inserts=${codec.insertCount} encoder=${enc.length}',
        );
        exitCode = 1;
        return;
      }
      File(args[1]).writeAsBytesSync(section);
      File(args[2]).writeAsBytesSync(enc);
    case 'decode-dynamic':
      final codec = QpackCodec(maxTableCapacity: 4096);
      final section = File(args[1]).readAsBytesSync();
      final enc = File(args[2]).readAsBytesSync();
      if (enc.isEmpty) {
        stderr.writeln('peer encoder stream was empty');
        exitCode = 1;
        return;
      }
      final ingested = codec.ingestEncoderStream(enc);
      if (ingested.isFailure) {
        stderr.writeln('ingest ${ingested.errorOrNull}');
        exitCode = 1;
        return;
      }
      if (!codec.sectionUsesDynamic(section)) {
        stderr.writeln('peer section did not use the dynamic table');
        exitCode = 1;
        return;
      }
      final decoded = codec.decodeFieldSection(section);
      if (decoded.isFailure) {
        stderr.writeln('decode ${decoded.errorOrNull}');
        exitCode = 1;
        return;
      }
      for (final h in decoded.valueOrNull!) {
        stdout.writeln('${h.name}\t${h.value}');
      }
    default:
      stderr.writeln('usage: roundtrip.dart headers|encode|decode');
      exitCode = 2;
  }
}
