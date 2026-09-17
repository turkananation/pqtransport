---
title: Pure-Dart post-quantum transport
description: Hybrid TLS 1.3 (RFC 10024), encrypted UDP, DNS/DoH/DoT, mDNS, QUIC, and HTTP/1.1–3. Cryptography is pqforge. Infrastructure is swissarmyknife. Zero FFI.
keywords:
  - post-quantum TLS
  - RFC 10024
  - ML-KEM
  - Dart transport
  - hybrid KEM
image: images/hero-hybrid.svg
imageAlt: RFC 10024 hybrid concatenation for X25519MLKEM768
---

pqtransport is the protocol layer of the TurkanaNation post-quantum stack.
It speaks UDP, TLS 1.3 hybrid key exchange, DNS / DoH / DoT, mDNS, QUIC
frames, and HTTP/1.1–3. Cryptography is exclusively
[`package:pqforge`](https://turkananation.github.io/pqforge/).
Infrastructure is exclusively
[`package:swissarmyknife`](https://turkananation.github.io/swissarmyknife/).
There is no `dart:ffi` and no platform TLS (`SecureSocket`) on the PQ path.

<Info>
  v0.1.0 is a self-interop vertical slice. 93 tests pass, 90.5% line coverage
  of `lib/`, `dart analyze` clean. Live handshake is **X25519MLKEM768 only**.
  Compact TLS encoding — not RFC 8446 ClientHello. Not OpenSSL interop.
  Not a FIPS 140 module.
</Info>

```dart
import 'package:pqtransport/pqtransport.dart';

final crypto = PqTransportCrypto();
final identity = PqTlsServerIdentity.generate(crypto);
final (a, b) = MemoryByteSocket.pair();
final client = PqTlsSocket.client(a, crypto: crypto);
final server = PqTlsSocket.server(b, crypto: crypto, identity: identity);
await Future.wait([server.handshake(), client.handshake()]);
final key = client.exporter('app', Uint8List(0), 32);
```

## Signal

| Gate | Value |
| --- | --- |
| Version | 0.1.0 |
| SDK | `>=3.12.0 <4.0.0` |
| Tests | 93 passed |
| Line coverage | 90.5% of `lib/` |
| Hybrid groups | 3 RFC 10024 codecs |
| Live KEX | X25519MLKEM768 |
| FFI | none |
| Platform TLS on PQ path | none |

## Hybrid groups (RFC 10024)

Concatenation order is **group-dependent**. X25519MLKEM768 does **not**
follow RFC 9954 naming order. ML-KEM is first on the wire. NIST-curve
groups put ECDHE first. `PqForgeCombiner` (always classical then PQ) is
not on this path.

| Group | Codepoint | Client | Server | SS | Order | Live |
| --- | --- | --- | --- | --- | --- | --- |
| X25519MLKEM768 | 0x11EC | 1216 | 1120 | 64 | ML-KEM then X25519 | Yes |
| SecP256r1MLKEM768 | 0x11EB | 1249 | 1153 | 64 | ECDHE then ML-KEM | Fail-closed |
| SecP384r1MLKEM1024 | 0x11ED | 1665 | 1665 | 80 | ECDHE then ML-KEM | Fail-closed |

P-256 / P-384 ECDH is not exported by pqforge 0.4.3. Those handshakes
fail closed rather than silently dropping to classical. See
[Hybrid Groups](hybrid) and [Claim Boundary](claim-boundary).

## The shape

| Layer | What it gives you |
| --- | --- |
| Core | `HybridGroup`, `requireLength`, `Transcript`, `PqTransportCrypto`, every protocol size in `lengths.dart` |
| UDP | AES-256-GCM datagrams, replay **before** AEAD, Throttler, encrypted X25519MLKEM768 session |
| TLS 1.3 | swissarmyknife `StateMachine`, compact hello, ML-DSA-65 CertificateVerify, exporter |
| DNS | A/AAAA/CNAME/MX/TXT/SRV/CAA/HTTPS/SVCB/OPT/PTR/NS, CircuitBreaker, TTL Cache |
| mDNS | Probe / announce / browse, optional ML-DSA-65 TXT |
| QUIC / HTTP | 1-RTT packet protect, CRYPTO/STREAM frames, HTTP/1.1 over `PqTlsSocket` |

## Family

```text
application  (HTTP, DNS, mDNS, QUIC frames)
     │
pqtransport  — this package. Protocol. No primitives.
     │
pqforge      — ML-KEM, ML-DSA, X25519, AES-256-GCM, HKDF
     │
pqcrypto     — FIPS 203/204/205 primitives + KAT evidence
```

swissarmyknife supplies `Result`, `StateMachine`, `Cache`,
`CircuitBreaker`, and `Throttler`. Read [Sister packages](family).

## Do not overclaim

This layer may not invent a stronger claim than pqcrypto / pqforge.

- Not a FIPS 140 module. No CMVP listing.
- Best-effort side-channel posture in Dart. Best-effort zeroization.
- RFC 10024-aligned hybrid encoding with unit-tested concatenation —
  **not** "interoperable with OpenSSL."
- Live KEX in 0.1.0 is X25519MLKEM768 only.
- TLS schedule is HKDF-SHA-256, not IANA `TLS_AES_256_GCM_SHA384` (0x1302).

Full wording: [Claim Boundary](claim-boundary).

## Start

```yaml
dependencies:
  pqtransport: ^0.1.0
  pqforge: ^0.4.3
  swissarmyknife: ^0.1.0
```

Then read [Getting Started](getting-started), the [API Guide](api), and
keep the [Cookbook](cookbook) nearby. Canonical markdown lives in
[`doc/INDEX.md`](https://github.com/turkananation/pqtransport/blob/main/doc/INDEX.md).
