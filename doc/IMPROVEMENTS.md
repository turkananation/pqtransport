# Improvements

Last updated: 2026-09-17

Prioritized engineering work after 0.1.0. Defects stay in
[BUGS.md](BUGS.md). Version order stays in [ROADMAP.md](ROADMAP.md).
This file is the "what would I do in the next coding turns" list.

Priority: **P0** stop-ship for a *future* claim we are about to make,
**P1** correctness / fail-closed, **P2** protocol completeness, **P3**
hygiene.

## Do next (this package)

| ID | Pri | Item | Why |
|---|---|---|---|
| IMP-04 | P2 | HelloRetryRequest flight + cookie | OPEN-05; machine edge already exists |
| IMP-06 | P3 | Cover leftover DNS/UDP/TLS error paths | OPEN-12 |

IMP-04 is the remaining 0.2 load-bearing slice. Do not start IMP-06 as a
dedicated "coverage sprint" until IMP-04 is designed.

## pqforge 0.4.4 consumption (done this turn)

| ID | Pri | Item | Status |
|---|---|---|---|
| IMP-01 | P1 | Refuse profile/group mismatch | **Done** (OPEN-03 / `requireGroup`) |
| IMP-07 | P0 | Live SecP256r1MLKEM768 + SecP384r1MLKEM1024 | **Done** (BLK-01) |
| IMP-08 | P1 | Replace local `hkdfExpand` with pqforge Expand | **Done** (BLK-02 SHA-256) |
| IMP-11 | P3 | `checkEncapsulationKey` without catch | **Done** (BLK-05) |
| IMP-02 | P1 | RFC 8446 ClientHello / ServerHello / extensions | **Done** (OPEN-01) |
| IMP-03 | P1 | Certificate as X.509 or explicit raw-pk | **Done** (OPEN-04, RFC 7250 RawPublicKey) |
| IMP-05 | P3 | Delete unused UDP `role` named args | **Done** (OPEN-11) |

## Still this package (exports exist)

| ID | Pri | Item | Tracks |
|---|---|---|---|
| IMP-09 | P1 | SHA-384 schedule, then and only then IANA 0x1302 | OPEN-02 |
| IMP-10 | P2 | Sync ChaCha records (IANA 0x1303) | OPEN-13 |

Do not vendor these. Exact signatures: [PQFORGE_EXPORTS.md](PQFORGE_EXPORTS.md).

## Do after 0.2 hellos exist

| ID | Pri | Item | Why |
|---|---|---|---|
| IMP-12 | P1 | OpenSSL 3.5+ fixture | LIM-01; wording stays honest until green |
| IMP-13 | P2 | `joinMulticast` on `IoDatagramChannel` | OPEN-09; real LAN mDNS |
| IMP-14 | P2 | QUIC header protection + ACK + RFC 9001 | OPEN-06 |
| IMP-15 | P2 | HTTP/2; then HTTP/3+QPACK | OPEN-07 |
| IMP-16 | P2 | Production DoH/DoT (ALPN, URI template) | OPEN-10 |
| IMP-17 | P2 | DNS rdata name pointers into the outer message | OPEN-08 |

## Process / repo hygiene

| ID | Pri | Item | Notes |
|---|---|---|---|
| IMP-18 | P3 | `dart format` + `dart compile js` + `dart pub publish --dry-run` as a release gate | Needed before first pub.dev cut |
| IMP-19 | P3 | CI workflow (analyze, test, invariants, coverage floor) | Not in this sandbox tree |
| IMP-20 | P3 | pub.dev release of 0.1.0 | Owner decision; package is unpublished |
| IMP-21 | P3 | Example that does **not** look like an OpenSSL peer | Current examples are in-memory; keep them honest |
| IMP-22 | P3 | Optional `allowUnauthenticated` lint / dartdoc warning | Easy to copy-paste into production |

## Explicitly not improvements

| Idea | Why not |
|---|---|
| Lower SDK to `>=3.8.0` | Both foundations are `^3.12.0` (FIX-01) |
| Use `PqForgeCombiner.combine()` as the TLS combiner | Reverses X25519MLKEM768 (FIX-02, BLK-04) |
| `SecureSocket` "just for HTTP" | Abandons the package |
| Direct `pqcrypto` / `pointycastle` dependency | Splits the crypto story |
| QUIC 0-RTT | LIM-05 |
| Browser raw UDP | LIM-04 |
| Coverage of `test/` in the quoted percentage | Quote `lib/` only |

## Suggested first PR (when directed)

OPEN-05 (HRR cookie). OPEN-01, OPEN-04, and OPEN-11 are done. OpenSSL
interop (IMP-12) is still forbidden until a recorded fixture exists.
Do not mix with QUIC work.
