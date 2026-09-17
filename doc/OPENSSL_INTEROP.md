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
| ClientHello | `HS(1) \|\| random(32) \|\| group(u16) \|\| share_len(u16) \|\| share` | `legacy_version`, `random`, `legacy_session_id`, `cipher_suites`, `legacy_compression`, extensions (`supported_versions`, `supported_groups`, `key_share`, SNI, ALPN, signature_algorithms) |
| ServerHello | Same compact shape | RFC 8446 ServerHello + `key_share` |
| Certificate | Raw ML-DSA-65 public key | X.509 `Certificate` message (or raw-pk extension, negotiated) |
| Cipher suite | AES-256-GCM keys from HKDF-**SHA-256** | Typically `TLS_AES_256_GCM_SHA384` (0x1302) for this AEAD |
| Groups | All three RFC 10024 groups **live** (self-interop). Compact hello still will not parse | OpenSSL 3.5+ implements RFC 10024 groups when built with the hybrid KEM |

Self-interop (client and server both `package:pqtransport`) is tested and
green for X25519MLKEM768, SecP256r1MLKEM768, and SecP384r1MLKEM1024
(`maximum` profile). That is a different claim.

Live NIST KEX is **not** the OpenSSL blocker. OPEN-01 hellos are.

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

1. **0.2** — RFC 8446-shaped ClientHello/ServerHello/Certificate in
   pqtransport (OPEN-01, OPEN-04). Still SHA-256 schedule. Still no
   0x1302 on the wire. Unblocks OpenSSL **parsing**.
2. **0.3 remaining** — SHA-384 schedule (OPEN-02) then and only then
   IANA `0x1302` if the fixture peer offers it. ChaCha records (OPEN-13)
   if the peer offers `0x1303`. Live NIST groups are **already done**
   (BLK-01 consumed in pqforge 0.4.4).
3. **0.4.1** — recorded transcript against OpenSSL 3.5+
   (`openssl s_server` / `s_client` with X25519MLKEM768).
4. Only then may README say "handshakes with OpenSSL 3.5+ on fixture X."

A Wireshark screenshot is not a fixture. The fixture is bytes + a test
that either drives `Process` against a pinned OpenSSL or replays a
checked-in flight.

Do not start this fixture before OPEN-01 hellos parse.

## Suggested fixture (when directed)

```text
peer:    OpenSSL 3.5.x (or current 3.5+), built with ML-KEM
group:   X25519MLKEM768 (0x11EC) first
suite:   whatever OpenSSL selects that we can honestly implement
auth:    ML-DSA or a classical cert with an explicit verify hook
negative:
  - swap concat order → peer aborts
  - truncate ek to 1183 → illegal_parameter
  - SHA-256 schedule vs SHA-384 suite → abort (documents OPEN-02)
```

BoringSSL is a second peer, not a substitute. One green OpenSSL fixture
is the 0.4 exit; BoringSSL is extra coverage.

## Claim language after a green fixture

Allowed: "Handshake interop with OpenSSL 3.5.x on the checked-in
X25519MLKEM768 fixture (date, commit, openssl version)."

Still forbidden: "production-ready post-quantum TLS", any FIPS 140
module claim, "all RFC 10024 groups" unless the NIST groups are in the
same fixture set.
