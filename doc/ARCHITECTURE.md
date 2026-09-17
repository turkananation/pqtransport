# Architecture

Last updated: 2026-09-17

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

All protocol sizes live in [`lib/src/core/lengths.dart`](../lib/src/core/lengths.dart).
A numeric literal for a protocol size anywhere else is a defect.

## Barrels

| Import | Contains | Must not contain |
|---|---|---|
| `package:pqtransport/pqtransport.dart` | Codecs, machines, hybrid, TLS, DNS, HTTP, memory sockets | `dart:io`, `dart:ffi`, `SecureSocket` |
| `package:pqtransport/pqtransport_io.dart` | Everything above plus `IoDatagramChannel` | Crypto of its own |

Callers on web supply a byte channel (`MemoryByteSocket` or their own
`PqTransportSocket`) and run TLS over it. Raw UDP / multicast require the IO
barrel on VM/mobile/desktop. See [PLATFORM_SUPPORT.md](PLATFORM_SUPPORT.md).

## Hybrid concat (normative)

X25519MLKEM768 does **not** follow RFC 9954 naming order.

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

Implemented in [`lib/src/core/hybrid.dart`](../lib/src/core/hybrid.dart).
`PqForgeCombiner` (always `classical || PQ`) is **not** on this path.

## TLS 1.3 (0.1.0 shape)

Coarse public states (from the original spec names) plus RFC 8446 internals:

```text
client: uninitialized
      → clientHelloSent
      → serverHelloProcessed
      → waitCertificate
      → waitCertVerify
      → waitFinished
      → handshakeCompleted
      ↛ failed | closed

server: waitClientHello
      → serverHelloSent
      → handshakeCompleted
```

Illegal `StateMachine.trigger` is converted to `failed` via `driveTls`.

Key schedule (RFC 8446 structure, SHA-256 only):

```text
early_secret     = HKDF-Extract(0, 0)
handshake_secret = HKDF-Extract(derived, hybrid_ss)   # hybrid_ss is 64 bytes
{c,s}_hs_traffic = DeriveSecret(handshake, "{c,s} hs traffic", Hash(CH||SH))
master_secret    = HKDF-Extract(derived_hs, 0)
{c,s}_ap_traffic = DeriveSecret(master, "{c,s} ap traffic", Hash(full transcript))
exporter_master  = DeriveSecret(master, "exp master", Hash(full transcript))
```

`deriveHandshake` installs handshake traffic keys (and a placeholder
application secret that `deriveApplication` overwrites). Traffic keys are
32-byte AES-256-GCM keys. IANA `TLS_AES_256_GCM_SHA384` is **not** offered.

Handshake messages on the wire in 0.1.0 are **compact**:

```text
ClientHello  = HS(1) || random(32) || group(u16) || share_len(u16) || share
ServerHello  = HS(2) || random(32) || group(u16) || share_len(u16) || share
Certificate  = HS(11) || pk_len(u16) || ml-dsa-65 public key
CertVerify   = HS(15) || sig_len(u16) || ml-dsa-65 signature
Finished     = HS(20) || verify_data(32)
```

This is enough for self-interop. It is not enough for OpenSSL.

Record protection: `TLSInnerPlaintext` = `payload || content_type`, sealed
with AES-256-GCM, outer type application_data. Handshake and application
epochs have independent sequence counters.

## Encrypted UDP

```text
initiator: encapsulate(peer_ek) + X25519 keygen
           flight = pk_x || ct_mlkem
responder: decapsulate + X25519 keygen
           reply  = pk_x
both:      ss = ss_mlkem || ss_x25519
           key = HKDF-SHA-256(ikm=ss, salt=deploymentSalt||SHA256(ct||initX||respX),
                              info="pqtransport udp-session v1|udp")
```

Role strings are **not** mixed into the HKDF extra (that would desynchronise
the two sides). Datagram sequence is in the clear header and bound as AAD;
duplicates are dropped before `aeadOpen`.

## DNS / mDNS

`PqDnsClient.lookup` is: cache hit → else encode query → `CircuitBreaker.execute(exchange)`
→ decode → `cache.put(..., ttl: msg.minTtl())`.

`PqDnsResolver` tries DoH, then DoT, then UDP, skipping transports whose
breaker is open.

mDNS uses a separate `StateMachine` (`idle → probing → announcing → registered`)
and an instance `EventBus` for `MdnsServiceEvent`. In-memory networks flood
every mailbox on the same port when the destination host is `224.0.0.251` or
`ff02::fb`.

## QUIC / HTTP

QUIC 0.1.0 is a packet + frame sketch so HTTP/3 work has a place to land.
It is **not** a connection: no header protection, no ACK processing, no
RFC 9001 TLS-in-QUIC.

HTTP/1.1 is a real codec used by `PqHttpClient.roundTripH1` over a completed
`PqTlsSocket`. HTTP/3 is frame encode/decode only.

## Error model

Every parse and every expected protocol failure returns
`Result<T, PqTransportError>`. `PqTransportError.toString` never embeds
secret bytes. Codes: `illegalParameter`, `decodeFailure`, `unexpectedMessage`,
`handshakeFailure`, `decryptError`, `circuitOpen`, `replay`, `throttled`,
`closed`, `unsupported`.

## Laws (non-negotiable)

1. Zero native crypto. Zero FFI.
2. Do not reimplement ML-KEM / ML-DSA / X25519 / AES-GCM / HKDF.
3. Hybrid is mandatory. No classical-only fallback after a PQ hello.
4. Concatenation order is group-dependent.
5. Length-filter before deserialize-to-crypto.
6. `Result` for expected failures; illegal machine events → `failed`.
7. Best-effort `zeroize` in `finally`. Never claim hard erasure.
8. Replay and cheap checks before expensive crypto.
9. Fail secure: unknown group, failed verify, open circuit → teardown.
10. No CMVP / FIPS 140 / constant-time-Dart claims.

## Profile footgun

`PqTransportCrypto` defaults to `PqForgeProfile.balanced` (ML-KEM-768 +
ML-DSA-65). `PqForgeProfile.maximum` is ML-KEM-1024 + ML-DSA-87. The live
TLS path is written for 768/65 sizes. Mixing `maximum` with
`HybridGroup.x25519MlKem768` is inconsistent; the P-384 group fail-closes
on ECDH. Tracked as [BUGS.md](BUGS.md) `OPEN-03`.
