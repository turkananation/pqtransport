# Security audit (transport layer)

Last updated: 2026-09-17

This is a risk register for **pqtransport 0.1.0**, not a primitive KAT
review. ML-KEM / ML-DSA evidence lives in `package:pqcrypto`. Hybrid
recipes and AEAD engines live in `package:pqforge`.

Scope: protocol state, hybrid concat, records, replay, auth story,
claim language. Out of scope: CMVP, side-channel labs, OpenSSL
production hardening.

## Summary

| Rating | Count | Notes |
|---|---|---|
| P0 stop-ship for the *claimed* 0.1.0 surface | 0 | Self-interop, all three RFC 10024 groups |
| P1 wrong-on-the-wire or fail-open | 1 | OPEN-02 |
| P2 incomplete protocol | 6 | OPEN-06 … OPEN-10, OPEN-13 |
| P3 hygiene | 1 | OPEN-12 |
| Blocked on pqforge | 0 | BLK-01 … BLK-05 consumed in 0.4.4 |
| Honest limits | 5 | LIM-01 … LIM-05 |

No P0 against the documented 0.1.0 claim. Several P1s against an
OpenSSL / IANA / profile-footgun reading of the same code. Read
[CLAIM_BOUNDARY.md](CLAIM_BOUNDARY.md) before quoting this file.

## What was reviewed (evidence)

- Live X25519MLKEM768, SecP256r1MLKEM768, and SecP384r1MLKEM1024
  handshakes (`test/tls/handshake_test.dart`) — client, server, exporters match.
- Hybrid concat for all three RFC 10024 groups
  (`test/core/hybrid_share_test.dart`) — the two 64-byte combiners
  differ for the same `(ssKem, ssEcdh)` pair.
- AEAD round-trip and bit-flip (`test/udp/`, `test/tls/record_test.dart`).
- Replay peek **before** AEAD (`FIX-06`).
- Illegal TLS / QUIC events → `failed`.
- DNS pointer-cycle rejection; CircuitBreaker open; cache TTL.
- mDNS ML-DSA-65 TXT mutate-fail.
- `dart analyze` clean; invariant script green; no `dart:ffi`.

## Findings (open)

### S1 — Compact TLS is not RFC 8446 (OPEN-01, P1)

Handshake messages omit `legacy_version`, `cipher_suites`, and every
extension (`supported_versions`, `key_share`, SNI, ALPN). A middlebox
or OpenSSL peer will not parse them. **Mitigation:** document as
self-interop; do not put this on the public internet as "TLS 1.3".
**Fix:** slice 0.2.

### S2 — SHA-256 schedule is not IANA 0x1302 (OPEN-02, P1)

Traffic keys are AES-256-GCM from HKDF-SHA-256. Advertising
`TLS_AES_256_GCM_SHA384` would desynchronise the transcript hash with
any SHA-384 peer. **Mitigation:** no IANA codepoint on the 0.1 wire.
**Fix:** SHA-384 schedule (OPEN-02 / 0.3.5). pqforge already exports
SHA-384 Extract/Expand.

### S3 — Profile / group mismatch refused (OPEN-03, closed)

`PqTransportCrypto.requireGroup` refuses `maximum` with ML-KEM-768
groups and `balanced`/`compact` with SecP384r1MLKEM1024 **before**
keygen. Evidence: `test/tls/handshake_test.dart`,
`test/core/crypto_facade_test.dart`.

### S4 — Certificate is a raw ML-DSA-65 key (OPEN-04, P1)

No X.509, no chain, no name constraints. `allowUnauthenticated` exists
on `PqTlsClient` and must stay opt-in. Default path still verifies
CertificateVerify over that raw key. **Mitigation:** tests use generated
identity; do not ship `allowUnauthenticated: true` as the example
default. **Fix:** slice 0.2.2.

### S5 — Replay was after AEAD; now before (FIX-06, closed)

Duplicates are dropped using `peekDatagramSequence` then
`ReplayWindow.isDuplicate` **before** `aeadOpen`. Keep this order.
Re-introducing decrypt-then-check is a regression.

### S6 — Record sequences mixed epochs; now split (FIX-04, closed)

Handshake and application epochs have independent counters
(`TlsRecordEpoch`). Mixing them again would reuse nonces under the
same key.

### S7 — QUIC sketch has no header protection (OPEN-06, P2)

1-RTT packet protect only. Connection IDs and packet numbers are not
header-protected. Do not treat this as RFC 9000 confidentiality for
the header. CRYPTO-frame test uses a 1216-byte **zero** share (size
gate).

### S8 — UDP HKDF extra is shared (by design)

Both roles mix `ct || initiatorX || responderX` and the same info
string `"pqtransport udp-session v1|udp"`. Putting a role string in
the extra desynchronises peers (OPEN-11 closed: unused `role` args
removed). Do not "fix" that by hashing the role.

### S9 — Best-effort zeroize / no constant-time guarantee (LIM-03)

`zeroize` overwrites the buffer we still hold. The VM may have copies.
Do not document this as erasure. Side-channel posture is best-effort
in Dart.

### S10 — Authentication story is local

ML-KEM is not authenticated transport. 0.1.0 authenticates the TLS
server with ML-DSA-65 over the transcript, and mDNS TXT with the same.
There is no CT log, no WebPKI, no raw-pk negotiation. Callers who need
a PKI must wait for OPEN-04 or supply their own verify hook later.

## Positive controls (keep)

| Control | Where |
|---|---|
| Length filter before crypto | `requireLength` / `PqLengthLabel` |
| Group-dependent concat, not `PqForgeCombiner` | `hybrid.dart` |
| All-zero classical ss rejected | hybrid combine |
| Fail-closed NIST groups | `PqTlsClient.startHandshake`, encrypted UDP |
| Illegal machine event → `failed` | `driveTls` / QUIC machines |
| Secrets not in `PqTransportError.toString` | `errors.dart` |
| No `dart:ffi`, no `SecureSocket` on PQ path | barrels |
| CircuitBreaker around DNS exchange | `PqDnsClient` |
| `allowDowngrade: false` default for HTTP | `PqHttpClient` |
| Hybrid mandatory (no classical-only after PQ hello) | law 3 |

## Threats we do not currently mitigate

| Threat | Status |
|---|---|
| Cross-implementation TLS interop confusion | Accepted until 0.4 |
| Downgrade to TLS 1.2 / classical-only | Compact encoding has no 1.2 path; still add `supported_versions` in 0.2 |
| HRR cookie binding | Done (OPEN-05; cookie required on HRR, echoed on CH2, mismatch fails closed) |
| DNS cache poisoning from compressed rdata names | OPEN-08 (our encoder emits uncompressed names) |
| mDNS spoofing on a real LAN | OPEN-09 (no multicast join); TXT sig helps when used |
| QUIC injection via unprotected headers | OPEN-06 |
| Supply-chain of pqforge / pqcrypto | Inherited; pin `^0.4.4` / transitive 0.4.1 |

## Audit extras that are **not** claimed

- No pentest report.
- No side-channel measurement.
- No FIPS 140 module boundary.
- No OpenSSL handshake.

Re-audit triggers: any change to `hybrid.dart`, `key_schedule.dart`,
`record.dart`, datagram replay, or a new pqforge major/minor that
touches AEAD or X25519.
