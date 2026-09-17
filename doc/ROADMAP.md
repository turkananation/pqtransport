# Roadmap

Last updated: 2026-09-17

Direction for `package:pqtransport` after **0.1.0**. Order is not optional:
inverting a slice produces fake HTTP clients on unimplemented QUIC, DoT
without TLS, or OpenSSL claims on a compact private encoding.

0.1.0 is the self-interop vertical slice. It is shipped in this tree
(unpublished on pub.dev until the owner cuts a release). See
[ACHIEVEMENTS.md](ACHIEVEMENTS.md) and [TRACKER.md](TRACKER.md).

## Non-goals that stay non-goals

These do not get a version number:

| Item | Why |
|---|---|
| CMVP / FIPS 140 module | Portable Dart library. [CLAIM_BOUNDARY.md](CLAIM_BOUNDARY.md) |
| Hard constant-time execution / hard erasure | VM, dart2js, dart2wasm cannot guarantee either |
| Browser raw UDP / mDNS / QUIC sockets | Browsers do not expose them. [PLATFORM_SUPPORT.md](PLATFORM_SUPPORT.md) |
| QUIC 0-RTT | Explicit non-goal (LIM-05) |
| Classical-only fallback after a PQ hello | Law 3 / law 9 |
| Direct `pqcrypto` dependency | Crypto stays one stack (`pqforge`) unless a documented exception lands |
| `dart:ffi` / `SecureSocket` on the PQ path | Law 1 |

## Slice 0.2 — RFC 8446-shaped wire (this package)

Unblock OpenSSL parsing **without** waiting on pqforge ECDH.

| # | Work | Closes |
|---|---|---|
| 0.2.1 | Real ClientHello / ServerHello: `legacy_version`, `cipher_suites`, `supported_versions`, `supported_groups`, `key_share`, SNI, ALPN | OPEN-01 |
| 0.2.2 | EncryptedExtensions as a real message; Certificate as X.509 or an explicit raw-public-key extension (not a silent raw key) | OPEN-04 |
| 0.2.3 | HelloRetryRequest on the wire with cookie; keep the existing once-only machine edge | OPEN-05 |
| 0.2.4 | Refuse `PqForgeProfile.maximum` with ML-KEM-768 groups (constructor or `startHandshake`) | OPEN-03 |
| 0.2.5 | Drop unused UDP `role` named args (breaking, still 0.x) | OPEN-11 |
| 0.2.6 | Coverage of leftover DNS/UDP/TLS error paths | OPEN-12 |

Still SHA-256 schedule. Still **do not** put IANA `0x1302` on the wire.
Self-interop must keep working: add a compatibility test that the compact
0.1 encoding is either still accepted behind a flag or is deliberately
retired in the same PR.

Exit gate: a recorded ClientHello from this package is structurally an
RFC 8446 handshake message (legacy_version `0x0303`, extensions present).
OpenSSL still may reject cipher/group until 0.3.

## Slice 0.3 — live NIST groups + honest cipher suite (pqforge then here)

Blocked on [PQFORGE_EXPORTS.md](PQFORGE_EXPORTS.md).

| # | Work | Closes | Depends |
|---|---|---|---|
| 0.3.1 | Consume `p256SharedSecret` / `p384SharedSecret` | BLK-01 | pqforge export |
| 0.3.2 | Live SecP256r1MLKEM768 handshake + encrypted UDP | BLK-01 | 0.3.1 |
| 0.3.3 | Live SecP384r1MLKEM1024 handshake (ML-KEM-1024 + P-384) | BLK-01 | 0.3.1, profile.maximum **with this group only** |
| 0.3.4 | Replace local HKDF-Expand with pqforge `hkdfExpandSha256` | BLK-02 | pqforge export |
| 0.3.5 | SHA-384 Extract/Expand → IANA `TLS_AES_256_GCM_SHA384` (0x1302) **only after** the schedule is SHA-384 | OPEN-02, BLK-02 | pqforge SHA-384 |
| 0.3.6 | Optional sync ChaCha → `TLS_CHACHA20_POLY1305_SHA256` (0x1303) | BLK-03 | pqforge export |
| 0.3.7 | Optional `checkEncapsulationKey` → `illegal_parameter` without catch | BLK-05 | pqforge export |

Fail-closed remains the rule until 0.3.1 is wired and tested. Do not
silently skip the classical share.

Exit gate: live handshake tests for **all three** RFC 10024 groups; cipher
suite bytes on the wire match the transcript hash in use.

## Slice 0.4 — OpenSSL 3.5+ / BoringSSL fixture

| # | Work | Closes |
|---|---|---|
| 0.4.1 | Recorded X25519MLKEM768 transcript against OpenSSL 3.5+ s_server/s_client | LIM-01 |
| 0.4.2 | Same for SecP256r1MLKEM768 once 0.3.2 is live | BLK-01 follow-on |
| 0.4.3 | Documented failure modes (wrong concat, SHA-256 vs SHA-384, missing key_share) | [OPENSSL_INTEROP.md](OPENSSL_INTEROP.md) |

Wording until 0.4.1 is green: "RFC 10024-aligned hybrid share encoding
with unit-tested concatenation," **not** "interoperable with OpenSSL."

Exit gate: a checked-in fixture (or CI job) that completes a handshake
with a known-good peer. See [OPENSSL_INTEROP.md](OPENSSL_INTEROP.md).

## Slice 0.5 — datagram / HTTP production

Only after 0.2 TLS is on the wire. QUIC still needs the TLS exporter
(already present) and RFC 9001.

| # | Work | Closes |
|---|---|---|
| 0.5.1 | `IoDatagramChannel.joinMulticast` on 224.0.0.251 / ff02::fb | OPEN-09 |
| 0.5.2 | QUIC header protection, ACK processing, RFC 9001 TLS-in-QUIC | OPEN-06 |
| 0.5.3 | HTTP/2 on `PqTlsSocket` (ALPN `h2`) | OPEN-07 |
| 0.5.4 | HTTP/3 + QPACK on a real QUIC stream | OPEN-07 |
| 0.5.5 | Production DoH (`application/dns-message` POST, URI template) and DoT (ALPN `dot`) | OPEN-10 |
| 0.5.6 | DNS rdata name-pointer resolution into the outer message | OPEN-08 |

HTTP/3 must not silently downgrade to HTTP/1.1 (`allowDowngrade: false`
stays the default).

## Parallelism (safe vs forbidden)

Safe after 0.1 constants exist:

- DNS rdata pointer work ∥ UDP API cleanup
- mDNS multicast join ∥ HTTP/1.1 ALPN (not HTTP/3)
- Coverage holes ∥ documentation

Never parallelize:

- OpenSSL fixture with compact 0.1 hellos still the only encoder
- HTTP/3 with QUIC still a packet sketch
- Live P-256 handshake with a local ECDH vendor
- Two changes both editing `lengths.dart` / `hybrid.dart`

## Suggested next coding turn (when directed)

1. OPEN-03 (profile/group refuse) — small, fail-closed, no new crypto.
2. OPEN-01 (RFC 8446 hello) — load-bearing for every later interop claim.
3. Then stop and wait for pqforge BLK-01 / BLK-02, **or** continue 0.2.2–0.2.6.

Do not start QUIC header protection before OPEN-01 is designed; the
CRYPTO frame has to carry a real TLS handshake, not a compact private one.
