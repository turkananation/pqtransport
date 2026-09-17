# Improvements

Last updated: 2026-09-17

Prioritized engineering work after 0.1.0. Defects stay in
[BUGS.md](BUGS.md). Version order stays in [ROADMAP.md](ROADMAP.md).
This file is the "what would I do in the next coding turns" list.

Priority: **P0** stop-ship for a *future* claim we are about to make,
**P1** correctness / fail-closed, **P2** protocol completeness, **P3**
hygiene.

## Do next (this package, no pqforge wait)

| ID | Pri | Item | Why |
|---|---|---|---|
| IMP-01 | P1 | Refuse `PqForgeProfile.maximum` with ML-KEM-768 groups | OPEN-03; one constructor guard, fail-closed |
| IMP-02 | P1 | RFC 8446 ClientHello / ServerHello / extensions | OPEN-01; unblocks every interop claim |
| IMP-03 | P1 | Certificate as X.509 or explicit raw-pk | OPEN-04; auth story is currently a raw key |
| IMP-04 | P2 | HelloRetryRequest flight + cookie | OPEN-05; machine edge already exists |
| IMP-05 | P3 | Delete unused UDP `role` named args | OPEN-11 |
| IMP-06 | P3 | Cover leftover DNS/UDP/TLS error paths | OPEN-12; 90.5% → closer to 95% of `lib/` |

IMP-01 is the smallest fail-closed win. IMP-02 is the load-bearing
one. Do not start IMP-06 as a dedicated "coverage sprint" until IMP-01
and IMP-02 are designed.

## Do when pqforge exports land

| ID | Pri | Item | Blocked on |
|---|---|---|---|
| IMP-07 | P0 for NIST groups | Live SecP256r1MLKEM768 + SecP384r1MLKEM1024 | BLK-01 |
| IMP-08 | P1 | Replace local `hkdfExpand` with pqforge Expand | BLK-02 |
| IMP-09 | P1 | SHA-384 schedule, then and only then IANA 0x1302 | BLK-02 |
| IMP-10 | P2 | Sync ChaCha records (IANA 0x1303) | BLK-03 |
| IMP-11 | P3 | `checkEncapsulationKey` without catch | BLK-05 |

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
| Use `PqForgeCombiner` as the TLS combiner | Reverses X25519MLKEM768 (FIX-02, BLK-04) |
| `SecureSocket` "just for HTTP" | Abandons the package |
| Direct `pqcrypto` / `pointycastle` dependency | Splits the crypto story |
| QUIC 0-RTT | LIM-05 |
| Browser raw UDP | LIM-04 |
| Coverage of `test/` in the quoted percentage | Quote `lib/` only |

## Suggested first PR (when directed)

Single-purpose: IMP-01 (profile/group refuse) + a test that
`PqTlsClient(crypto: PqTransportCrypto(profile: PqForgeProfile.maximum))`
with `HybridGroup.x25519MlKem768` returns `unsupported` (or a dedicated
error) **before** keygen.

Second PR: IMP-02 design note (byte layout of a real ClientHello) before
code. Do not mix IMP-02 with QUIC work.
