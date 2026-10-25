# Roadmap

Last updated: 2026-09-17

Direction for `package:pqtransport` after **0.1.0**. Order is not optional:
inverting a slice produces fake HTTP clients on unimplemented QUIC, DoT
without TLS, or OpenSSL claims on a compact private encoding.

0.1.0 is the self-interop vertical slice **plus live NIST groups**
(pqforge 0.4.4). It is shipped in this tree (unpublished on pub.dev until
the owner cuts a release). See [ACHIEVEMENTS.md](ACHIEVEMENTS.md) and
[TRACKER.md](TRACKER.md).

## Non-goals that stay non-goals

These do not get a version number:

| Item | Why |
| --- | --- |
| CMVP / FIPS 140 module | Portable Dart library. [CLAIM_BOUNDARY.md](CLAIM_BOUNDARY.md) |
| Hard constant-time execution / hard erasure | VM, dart2js, dart2wasm cannot guarantee either |
| Browser raw UDP / mDNS / QUIC sockets | Browsers do not expose them. [PLATFORM_SUPPORT.md](PLATFORM_SUPPORT.md) |
| QUIC 0-RTT | Permanent non-goal (LIM-05, issue 55). Not a fourth packet number space. |
| Classical-only fallback after a PQ hello | Law 3 / law 9 |
| Direct `pqcrypto` dependency | Crypto stays one stack (`pqforge`) unless a documented exception lands |
| `dart:ffi` / `SecureSocket` on the PQ path | Law 1 |

## Slice 0.2 — RFC 8446-shaped wire (this package)

Unblock OpenSSL parsing **without** waiting on pqforge ECDH.

| # | Work | Closes |
| --- | --- | --- |
| 0.2.1 | ~~Real ClientHello / ServerHello: `legacy_version`, `cipher_suites`, `supported_versions`, `supported_groups`, `key_share`, SNI, ALPN~~ | **Done** (OPEN-01). Compact 0.1 body retired. |
| 0.2.2 | ~~EncryptedExtensions as a real message; Certificate as X.509 or an explicit raw-public-key extension~~ | **Done** (OPEN-04). RFC 7250 RawPublicKey negotiated. Payload is still raw ML-DSA-65, not X.509. |
| 0.2.3 | ~~HelloRetryRequest on the wire with cookie; keep the existing once-only machine edge~~ | **Done** (OPEN-05) |
| 0.2.4 | ~~Refuse `PqForgeProfile.maximum` with ML-KEM-768 groups~~ | **Done** (OPEN-03 / `requireGroup`) |
| 0.2.5 | ~~Drop unused UDP `role` named args~~ | **Done** (OPEN-11) |
| 0.2.6 | ~~Coverage of leftover DNS/UDP/TLS error paths~~ | **Done** (OPEN-12) |

Compact 0.1 hello body is **retired** (OPEN-01). Private-use `0xFF00` is
**retired** (OPEN-02). Exit gate for 0.2.1 is met: a recorded ClientHello is
structurally RFC 8446 (`legacy_version` `0x0303`, extensions present).
Cipher suite bytes match the transcript hash (`0x1302` SHA-384, `0x1303`
SHA-256). Handshake interop with OpenSSL 3.5.9 on X25519MLKEM768,
SecP256r1MLKEM768, and SecP384r1MLKEM1024 (2026-10-20, auth mode
raw-pk) is slice 0.4. X.509 paths and BoringSSL are not that fixture.

## Slice 0.3 — live NIST groups + honest cipher suite

pqforge 0.4.4 unblocked this slice. Live KEX is **done**. IANA
cipher-suite honesty (OPEN-02, OPEN-13) is **done**.

| # | Work | Closes | Status |
| --- | --- | --- | --- |
| 0.3.1 | Consume `p256SharedSecret` / `p384SharedSecret` | BLK-01 | **Done** |
| 0.3.2 | Live SecP256r1MLKEM768 handshake + encrypted UDP | BLK-01 | **Done** |
| 0.3.3 | Live SecP384r1MLKEM1024 handshake | BLK-01, OPEN-03 | **Done** (`maximum` only) |
| 0.3.4 | Replace local HKDF-Expand with pqforge `hkdfExpandSha256` | BLK-02 | **Done** |
| 0.3.5 | SHA-384 Extract/Expand → IANA `TLS_AES_256_GCM_SHA384` (0x1302) **only after** the schedule is SHA-384 | OPEN-02 | **Done** |
| 0.3.6 | Sync ChaCha → `TLS_CHACHA20_POLY1305_SHA256` (0x1303) | OPEN-13 | **Done** |
| 0.3.7 | `checkEncapsulationKey` → `illegal_parameter` without catch | BLK-05 | **Done** |

Fail-closed remains the rule for a **profile/group mismatch**. Do not
silently skip the classical share.

Exit gate: live handshake tests for **all three** RFC 10024 groups —
**met**. Cipher suite bytes on the wire matching the transcript hash —
**met** (0.3.5 / 0.3.6).

## Slice 0.4 — OpenSSL 3.5+ / BoringSSL fixture

| # | Work | Closes | Status |
| --- | --- | --- | --- |
| 0.4.1 | X25519MLKEM768 against OpenSSL 3.5.9 `s_server`, auth mode raw-pk | LIM-01 | **Done** — `tool/interop/openssl` |
| 0.4.2 | SecP256r1MLKEM768 and SecP384r1MLKEM1024 against the same peer | LIM-01 | **Done** — same driver. P-384 uses `maximum`. |
| 0.4.3 | Documented failure modes (wrong concat, 1183-byte ek, SHA-256 vs SHA-384) | [OPENSSL_INTEROP.md](OPENSSL_INTEROP.md) | **Done** — local tests named in that doc |

The only allowed OpenSSL sentence is: Handshake interop with OpenSSL
3.5.9 on X25519MLKEM768, SecP256r1MLKEM768, and SecP384r1MLKEM1024
(2026-10-20, auth mode raw-pk). Not X.509. Not BoringSSL.

## Slice 0.5 — datagram / HTTP production

Only after 0.2 TLS is on the wire. QUIC still needs the TLS exporter
(already present) and RFC 9001.

| # | Work | Closes |
| --- | --- | --- |
| 0.5.1 | `IoDatagramChannel.joinMulticast` on 224.0.0.251 / ff02::fb | OPEN-09 **Done** |
| 0.5.2 | QUIC header protection, ACK processing, RFC 9001 TLS-in-QUIC | OPEN-06 **Done** |
| 0.5.3 | HTTP/2 on `PqTlsSocket` (ALPN `h2`) | OPEN-07 **Done** |
| 0.5.4 | HTTP/3 + QPACK on a real QUIC stream | OPEN-07 **Done** |
| 0.5.5 | Production DoH (`application/dns-message` POST and GET, URI template) and DoT (ALPN `dot`) | OPEN-10 **Done** |
| 0.5.6 | DNS rdata name-pointer resolution into the outer message | OPEN-08 **Done** |

HTTP/3 must not silently downgrade to HTTP/1.1 (`allowDowngrade: false`
stays the default).

## Slice 0.6 — certificates, loss recovery, DNSSEC

| # | Work | Closes |
| --- | --- | --- |
| 0.6.1 | RFC 9002 loss detection, PTO, and NewReno | OPEN-15 **Done** |
| 0.6.2 | One X.509 certificate when RawPublicKey was not negotiated | OPEN-14 **Proposed.** [ADR-0014](adr/ADR-0014-x509-certificate.md), [plan](plans/OPEN-14-x509-certificate.md). Not started. |

0.6.2 does not include chain building, AIA, OCSP, CT, the system trust
store, Merkle Tree Certificates, ChaCha header protection, QUIC
flow-control frames, or DNSSEC. 0-RTT stays LIM-05. The raw-pk OpenSSL
flight is not edited to produce 0.6.2.

## Parallelism (safe vs forbidden)

Safe after 0.1 constants exist:

- DNS rdata pointer work ∥ UDP API cleanup
- mDNS multicast join ∥ HTTP/1.1 ALPN (not HTTP/3)
- Coverage holes ∥ documentation

Never parallelize:

- Live P-256 handshake with a local ECDH vendor
- Two changes both editing `lengths.dart` / `hybrid.dart`

## Suggested next coding turn (when directed)

1. Do not implement OPEN-14 until ADR-0014 is accepted. The contract is
   [plans/OPEN-14-x509-certificate.md](plans/OPEN-14-x509-certificate.md).

Do not start HTTP/3 QPACK without a QUIC stream mapping. CRYPTO frames
carry a real TLS handshake (OPEN-06). HTTP/2 on `PqTlsSocket` is Done.
HTTP/3 on `PqQuicConn` is Done. DoH/DoT (OPEN-10) is Done.
