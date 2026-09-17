# OpenSSL / BoringSSL interop

Last updated: 2026-09-17

**Status: not started. Do not claim it.**

0.1.0 wording, copied from the test-gate skill:

> RFC 10024-aligned hybrid share encoding with unit-tested concatenation,
> **not** "interoperable with OpenSSL."

Tracked as LIM-01. Slice 0.4 in [ROADMAP.md](ROADMAP.md).

## Why a 0.1.0 peer will not handshake

| Layer | What we send | What OpenSSL 3.5+ expects |
|---|---|---|
| Record | Compact length-prefixed handshake bytes inside AES-256-GCM | RFC 8446 TLSPlaintext / TLSCiphertext |
| ClientHello | RFC 8446-shaped (`legacy_version` 0x0303, extensions, `key_share`). IANA `0x1302` / `0x1303` | Same shape; typically `TLS_AES_256_GCM_SHA384` (0x1302) |
| ServerHello | RFC 8446-shaped + `key_share` + `supported_versions` | RFC 8446 ServerHello + `key_share` |
| Certificate | Raw ML-DSA-65 public key (RFC 7250 RawPublicKey negotiated) | X.509 `Certificate` message (or raw-pk, which we negotiate) |
| Cipher suite | `0x1302` SHA-384 AES-GCM (default); `0x1303` ChaCha | Typically `TLS_AES_256_GCM_SHA384` (0x1302) for this AEAD |
| Groups | All three RFC 10024 groups **live** | OpenSSL 3.5+ implements RFC 10024 groups when built with the hybrid KEM |

Self-interop (client and server both `package:pqtransport`) is tested and
green for X25519MLKEM768, SecP256r1MLKEM768, and SecP384r1MLKEM1024
(`maximum` profile). That is a different claim.

Live NIST KEX is **not** the OpenSSL blocker. Remaining: raw ML-DSA
payload (not X.509), no recorded fixture (LIM-01). Hellos, IANA suites,
raw-pk, and HRR are on the wire.

## Concatenation is already the RFC join

This is **not** the blocker. Unit tests pin:

```text
X25519MLKEM768 ss     = ss_mlkem (32) || ss_x25519 (32)
SecP256r1MLKEM768 ss  = ss_ecdhe (32) || ss_mlkem (32)
SecP384r1MLKEM1024 ss = ss_ecdhe (48) || ss_mlkem (32)
```

If OpenSSL later rejects us, first suspect hello shape and transcript
hash, not concat order — unless someone "fixed" X25519 to match the
group name (that would be a stop-ship).

## Milestone sequence (do not skip)

1. **0.2** — RFC 8446-shaped ClientHello/ServerHello/Certificate
   (**done**: OPEN-01, OPEN-04, OPEN-05).
2. **0.3 remaining** — SHA-384 schedule + IANA `0x1302` (**done**, OPEN-02).
   ChaCha `0x1303` (**done**, OPEN-13).
3. **0.4.1** — recorded transcript against OpenSSL 3.5+
   (`openssl s_server` / `s_client` with X25519MLKEM768).
4. Only then may README say "handshakes with OpenSSL 3.5+ on fixture X."

A Wireshark screenshot is not a fixture. The fixture is bytes + a test
that either drives `Process` against a pinned OpenSSL or replays a
checked-in flight.

Do not start this fixture claiming success before a recorded peer flight
exists. Parsing is unblocked; completion is LIM-01.

## Suggested fixture (when directed)

```text
peer:    OpenSSL 3.5.x (or current 3.5+), built with ML-KEM
group:   X25519MLKEM768 (0x11EC) first
suite:   whatever OpenSSL selects that we can honestly implement
auth:    ML-DSA or a classical cert with an explicit verify hook
negative:
  - swap concat order → peer aborts
  - truncate ek to 1183 → illegal_parameter
  - SHA-256 Hash with a `0x1302` hello → abort
```

BoringSSL is a second peer, not a substitute. One green OpenSSL fixture
is the 0.4 exit; BoringSSL is extra coverage.

## Claim language after a green fixture

Allowed: "Handshake interop with OpenSSL 3.5.x on the checked-in
X25519MLKEM768 fixture (date, commit, openssl version)."

Still forbidden: "production-ready post-quantum TLS", any FIPS 140
module claim, "all RFC 10024 groups" unless the NIST groups are in the
same fixture set.
