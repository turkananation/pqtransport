---
title: Architecture
description: Module layout, barrels, hybrid concat, and the swissarmyknife / pqforge mapping for pqtransport.
---

pqtransport is a **protocol layer**. It does not implement ML-KEM, ML-DSA,
X25519, AES-GCM, or HKDF. Those come from `package:pqforge`. It does not
hand-roll state machines, Result, caches, or breakers. Those come from
`package:swissarmyknife`.

```text
  application (HTTP/1.1, DNS, mDNS, QUIC frames)
           │
           ▼
  pqtransport  ── StateMachine / Result / Cache / CircuitBreaker / Throttler
           │        (swissarmyknife)
           ▼
  pqforge      ── ML-KEM / ML-DSA / X25519 / AES-256-GCM / HKDF-SHA-256
           │
           ▼
  pqcrypto     ── FIPS 203/204/205 primitives + KAT evidence
```

## Package layout

```text
lib/
  pqtransport.dart          # web-safe public barrel (no dart:io, no dart:ffi)
  pqtransport_io.dart       # re-exports barrel + IoDatagramChannel
  src/
    core/                   # lengths, errors, bytes, hybrid, transcript, zeroize, crypto facade
    socket/                 # PqTransportSocket, memory pair, IO UDP
    udp/                    # datagram AEAD, replay, encrypted session
    tls/                    # machines, records, handshake, client/server/socket, key schedule
    dns/                    # records, wire, client, DoH/DoT helpers
    mdns/                   # probe/announce/browse, signed TXT
    quic/                   # packet protect, frames, flow control, machines
    http/                   # HTTP/1.1 codec, HTTP/3 frames, PqHttpClient
```

All protocol sizes live in `lib/src/core/lengths.dart`. A numeric literal
for a protocol size anywhere else is a defect.

## Barrels

| Import | Contains | Must not contain |
| --- | --- | --- |
| `package:pqtransport/pqtransport.dart` | Codecs, machines, hybrid, TLS, DNS, HTTP, memory sockets | `dart:io`, `dart:ffi`, `SecureSocket` |
| `package:pqtransport/pqtransport_io.dart` | Everything above plus `IoDatagramChannel` | Crypto of its own |

Callers on web supply a byte channel (`MemoryByteSocket` or their own
`PqTransportSocket`) and run TLS over it. Raw UDP / multicast require the
IO barrel on VM/mobile/desktop.

## Hybrid concat (normative)

```text
X25519MLKEM768
  client = ek_mlkem (1184) || pk_x25519 (32)     = 1216
  server = ct_mlkem (1088) || pk_x25519 (32)     = 1120
  ss     = ss_mlkem (32)   || ss_x25519 (32)     = 64

SecP256r1MLKEM768
  client = pk_p256 (65) || ek_mlkem (1184)       = 1249
  server = pk_p256 (65) || ct_mlkem (1088)       = 1153
  ss     = ss_ecdhe (32) || ss_mlkem (32)        = 64

SecP384r1MLKEM1024
  client = pk_p384 (97) || ek_mlkem1024 (1568)   = 1665
  server = pk_p384 (97) || ct_mlkem1024 (1568)   = 1665
  ss     = ss_ecdhe (48) || ss_mlkem (32)        = 80
```

Implemented in `lib/src/core/hybrid.dart`. See [Hybrid Groups](hybrid).

## TLS 1.3 (0.1.0 shape)

RFC 8446-shaped ClientHello / ServerHello (`legacy_version` 0x0303,
`supported_versions`, `key_share`, SNI, ALPN). Cipher suite is
private-use `0xFF00` (AES-256-GCM + HKDF-SHA-256), **not** IANA `0x1302`.
Handshake vs application epochs reset the record sequence. Finished is
HMAC-SHA-256 over the transcript. Certificate is a raw ML-DSA-65 public
key (OPEN-04).

Wording stays "RFC 10024-aligned hybrid share encoding with unit-tested
concatenation," not "OpenSSL interop."
