---
title: Protocols
description: UDP, TLS 1.3, DNS/DoH/DoT, mDNS, QUIC, and HTTP surfaces in pqtransport 0.1.0 — what is done, partial, or fail-closed.
---

Status vocabulary matches [`doc/FEATURES.md`](https://github.com/turkananation/pqtransport/blob/main/doc/FEATURES.md):
**Done** (tested), **Partial**, **Fail-closed**, **Not started**.

## UDP

Versioned datagram envelope: `version || hdrLen || header || nonce || ct||tag`.
AES-256-GCM with AAD-bound sequence. Replay peeks the sequence **before**
AEAD open. Send path uses swissarmyknife `Throttler`. Encrypted session
is X25519MLKEM768, SecP256r1MLKEM768, or SecP384r1MLKEM1024 with
identical HKDF extra on both roles.

Reliability states exist; they are not a full ACK/retransmit protocol.

## TLS 1.3

Client and server `StateMachine`s from swissarmyknife. Illegal event →
`failed` + `Result.failure`. RFC 8446-shaped ClientHello / ServerHello
(OPEN-01). EncryptedExtensions + Certificate + CertificateVerify +
Finished. RFC 7250 RawPublicKey is negotiated; certificate payload is
still a raw ML-DSA-65 public key. AES-256-GCM (`0x1302`) or
ChaCha20-Poly1305 (`0x1303`) records; handshake vs application epochs
reset sequence. TLS exporter is deterministic on a fixture. Schedule
follows the suite: HKDF-SHA-384 for IANA `0x1302` (default), HKDF-SHA-256
for IANA `0x1303`. Private-use `0xFF00` is retired.

HelloRetryRequest is on the wire with cookie extension 44 and
`selected_group` (OPEN-05). Once-only; a second HRR fails closed. X.509
chains and OpenSSL interop are not started. ChaCha records are Done
(`0x1303`) on VM, dart2wasm, and dart2js (pqforge 0.4.5 Dart engine).

## DNS / DoH / DoT

Wire codec for A, AAAA, CNAME, MX, TXT, SRV, CAA, HTTPS, SVCB, OPT, PTR,
NS. Compression pointer cycles are rejected. TTL cache uses an injected
clock. `CircuitBreaker` wraps exchange and opens after
`failureThreshold`. Resolver failover DoH → DoT → UDP is Partial
(independent clients; skip-on-open). DNSSEC verify is not started.

## mDNS

Probe / announce / browse on 5353 against an in-memory multicast flood.
Optional ML-DSA-65 TXT (`pqsig=`). EventBus announcements per client.
`IoDatagramChannel` does not yet `joinMulticast` (OPEN-09) — real LAN
discovery is unicast-only. SLH-DSA signed records are not the interactive
default.

## QUIC / HTTP

1-RTT packet protect, no header protection. CRYPTO / STREAM frames
encode; no ACK processor. Flow control `consume` exists. TLS-in-QUIC
(RFC 9001) is not started. QUIC 0-RTT is an explicit non-goal.

HTTP/1.1 request/response is Done, including GET over a completed
`PqTlsSocket`. HTTP/2 is not started. HTTP/3 is frames without QPACK.
Silent h3→h1 downgrade is refused (`allowDowngrade: false`).
