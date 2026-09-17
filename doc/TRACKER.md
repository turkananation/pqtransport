# Tracker

Last updated: 2026-09-17

Canonical project tracker for `package:pqtransport` **0.1.0**.

- Defects live in [BUGS.md](BUGS.md). This file does not duplicate the
  write-up; it indexes IDs and ownership.
- Direction lives in [ROADMAP.md](ROADMAP.md). Order there is not optional.
- Sister-package alias: [PROGRESS_TRACKER.md](PROGRESS_TRACKER.md) points here.

Status vocabulary matches [BUGS.md](BUGS.md): **Open**, **Blocked**,
**Fixed**, **Won't fix in 0.1**. Work that is not a defect is **Done**,
**Partial**, **Fail-closed**, or **Not started** ([FEATURES.md](FEATURES.md)).

## Snapshot

| Item | Value |
|---|---|
| Package | `pqtransport 0.1.0` (unpublished on pub.dev until the owner cuts a release) |
| SDK | `>=3.12.0 <4.0.0` |
| Crypto | `pqforge ^0.4.3` |
| Infra | `swissarmyknife ^0.1.0` |
| Analyzer | clean |
| Tests | 93 passed |
| Coverage | 90.5% of `lib/` (`1854/2049`) |
| Live handshake | X25519MLKEM768 self-interop only |
| OpenSSL interop | Not started |
| CMVP / FIPS 140 | Not claimed |

## What 0.1.0 closed

| Area | Result | Evidence |
|---|---|---|
| Core lengths + hybrid concat (3 groups) | Done | `test/core/` |
| Socket abstraction + in-memory drivers | Done | `test/io/`, `test/extra_coverage_test.dart` |
| Encrypted UDP (X25519MLKEM768) | Done | `test/udp/datagram_test.dart` |
| TLS machines + compact handshake + records | Done | `test/tls/` |
| HTTP/1.1 GET over `PqTlsSocket` | Done | `test/tls/socket_http_test.dart` |
| DNS wire + cache + breaker | Done | `test/dns/wire_test.dart` |
| mDNS probe/announce/browse + ML-DSA TXT | Done | `test/mdns/mdns_test.dart` |
| QUIC packet protect + CRYPTO/STREAM size gate | Partial | `test/quic/quic_test.dart` |
| Web-safe barrel / IO barrel split | Done | `lib/pqtransport.dart`, `lib/pqtransport_io.dart` |
| FIX-01 … FIX-12 | Fixed | [BUGS.md](BUGS.md) |

## Test gates (skill `09-test-gates.md`)

| ID | Gate | Status |
|---|---|---|
| GATE-01 | `requireLength` exact / n-1 / n+1 | Done |
| GATE-02 | Combiner order differs X25519 vs P-256 | Done |
| GATE-03 | `zeroize` overwrites the buffer | Done |
| GATE-04 | AEAD round trip; bit-flip fails | Done |
| GATE-05 | Replay window drops duplicates | Done |
| GATE-06 | Throttler blocks extra send | Done |
| GATE-07 | Client 1216 / server 1120 / ss 64, ML-KEM first | Done |
| GATE-08 | P-256 1249 / 1153, ECDHE first, leading `0x04` | Done |
| GATE-09 | Happy path `handshakeCompleted` | Done |
| GATE-10 | Illegal event → `failed` + `Result.failure` | Done |
| GATE-11 | HRR once; second HRR fails | Partial — state-machine API, not a wire HRR (OPEN-05) |
| GATE-12 | Wrong-length ek → `illegal_parameter` | Done |
| GATE-13 | Two IKMs → two application keys; exporter deterministic | Done |
| GATE-14 | DNS RR round-trip; pointer cycle rejected | Done |
| GATE-15 | CircuitBreaker opens; cache expires at TTL | Done |
| GATE-16 | mDNS probe/announce/browse; ML-DSA TXT verify / mutate-fail | Done |
| GATE-17 | CRYPTO frame carries 1216-byte share | Partial — size gate, body is zeros (OPEN-06) |
| GATE-18 | Packet protect round trip; bit-flip fails | Done |
| GATE-19 | Flow control violation is an error | Done |
| GATE-20 | HTTP/1.1 GET over mock TLS | Done |
| GATE-21 | OpenSSL interop fixture | Not started (LIM-01) |

Universal gates (analyze, no `dart:ffi`, no stray size literals, claim
language) are green as of this pass. See [INDEX.md](INDEX.md).

## Open work indexed from BUGS.md

### Transport defects (this package)

| ID | Sev | Owner | Blocks | Next action |
|---|---|---|---|---|
| OPEN-01 | P1 | pqtransport | 0.2 OpenSSL hello | RFC 8446 ClientHello / ServerHello / extensions |
| OPEN-02 | P1 | pqtransport + pqforge | IANA 0x1302 | Keep SHA-256 schedule until BLK-02 lands; never put 0x1302 on the wire |
| OPEN-03 | P1 | pqtransport | Footgun | Refuse `PqForgeProfile.maximum` with ML-KEM-768 groups |
| OPEN-04 | P1 | pqtransport | Cert interop | X.509 `Certificate` (or an explicit raw-pk flag) |
| OPEN-05 | P2 | pqtransport | HRR interop | Cookie + actual HRR flight |
| OPEN-06 | P2 | pqtransport | HTTP/3 | Header protection, ACK, RFC 9001 |
| OPEN-07 | P2 | pqtransport | h2 / h3 | HTTP/2; HTTP/3+QPACK after OPEN-06 |
| OPEN-08 | P2 | pqtransport | Foreign DNS | Resolve rdata name pointers into the outer message |
| OPEN-09 | P2 | pqtransport | LAN mDNS | `joinMulticast` on `IoDatagramChannel` |
| OPEN-10 | P2 | pqtransport | Production DoH/DoT | ALPN `dot`/`h2`, URI template |
| OPEN-11 | P3 | pqtransport | API noise | Drop unused `role` named args |
| OPEN-12 | P3 | pqtransport | Coverage | Hit leftover DNS/UDP/TLS error paths (~9.5%) |

### Blocked on pqforge (do not vendor)

| ID | Sev | Needed from pqforge | Unblocks |
|---|---|---|---|
| BLK-01 | P0 for NIST groups | P-256 / P-384 ECDH (x-coordinate, uncompressed `0x04\|\|X\|\|Y`) | Live SecP256r1MLKEM768 / SecP384r1MLKEM1024 |
| BLK-02 | P1 | `hkdfExpandSha256`; SHA-384 Extract/Expand | Drop local Expand; IANA 0x1302 (with SHA-384) |
| BLK-03 | P2 | Sync ChaCha20-Poly1305 primitive | `TLS_CHACHA20_POLY1305_SHA256` (0x1303) |
| BLK-04 | P2 | Group-aware combiner **or** leave concat here | Avoids reversing X25519MLKEM768 |
| BLK-05 | P3 | `checkEncapsulationKey` before encapsulate | `illegal_parameter` without catching pqcrypto |

Exact signatures: [PQFORGE_EXPORTS.md](PQFORGE_EXPORTS.md).

### Honest 0.1 limits (not defects)

| ID | Summary | Roadmap slice |
|---|---|---|
| LIM-01 | OpenSSL / BoringSSL handshake | 0.3, after OPEN-01 + BLK-01/02 |
| LIM-02 | CMVP / FIPS 140 module | Never this package |
| LIM-03 | Hard constant-time / hard erasure | Never this language runtime |
| LIM-04 | Browser raw UDP / mDNS | Never (browser platform) |
| LIM-05 | QUIC 0-RTT | Explicit non-goal |

## Roadmap slices (ownership)

| Slice | Theme | Depends on | Primary IDs |
|---|---|---|---|
| 0.1.0 | Self-interop vertical slice | — | Shipped |
| 0.2 | RFC 8446-shaped hellos + profile guard | none of BLK-* strictly | OPEN-01, OPEN-03, OPEN-04, OPEN-05, OPEN-11 |
| 0.3 | Live NIST groups + IANA cipher | pqforge BLK-01, BLK-02 | BLK-01, BLK-02, OPEN-02 |
| 0.4 | OpenSSL 3.5+ fixture | 0.2 + 0.3 | LIM-01, [OPENSSL_INTEROP.md](OPENSSL_INTEROP.md) |
| 0.5 | QUIC/HTTP/DoH production | 0.2 TLS wire | OPEN-06, OPEN-07, OPEN-09, OPEN-10 |

Do not start 0.4 before 0.2 hellos parse. Do not start 0.5 HTTP/3 before
OPEN-06. Do not vendor P-256 ECDH to jump 0.3.

## Verification commands

```bash
export PATH="/opt/dart-sdk/bin:$PATH"
cd pqtransport
dart pub get
dart analyze
dart test
bash ../.grok/skills/pqtransport-distinguished-engineer/scripts/check_invariants.sh .
dart pub global run coverage:test_with_coverage
# then: python3 -c to filter SF:lib/ from coverage/lcov.info
```

A change is not done until the universal gates and the module gates it
touches stay green. See [ENGINEERING_GUIDE.md](ENGINEERING_GUIDE.md).
