# Security policy

`pqtransport` is a pure-Dart post-quantum **transport** library. Cryptographic
primitives come from [`package:pqforge`](https://pub.dev/packages/pqforge)
(itself backed by [`package:pqcrypto`](https://pub.dev/packages/pqcrypto)).
Because this package moves key shares, records, and application data, we take
disclosure seriously.

## Supported versions

| Version | Supported |
| ------- | --------- |
| 0.1.x   | Yes — security fixes |
| < 0.1.0 | n/a — first public line |

Fixes land on `main` first.

## Reporting a vulnerability

Report suspected vulnerabilities **privately**. Do not open a public issue
for an unfixed security bug.

1. Preferred: open a private [GitHub Security Advisory](https://github.com/turkananation/pqtransport/security/advisories/new).
2. Alternative: email **turkananation@gmail.com** with the subject
   `pqtransport security report`.

Please include, where possible:

- affected version(s) and platform (VM, dart2js, dart2wasm, Flutter);
- hybrid group and protocol (TLS / UDP / DNS / mDNS / QUIC / HTTP);
- a description of the issue and its impact;
- a minimal reproduction (transcript, seed, or test);
- whether the issue is already public.

### What to expect

- Acknowledgement within **5 business days**.
- A triage assessment (severity, affected versions) and a remediation plan.
- Coordinated disclosure: we agree a timeline before any public advisory, and
  we credit reporters who wish to be named.

## Scope and cryptographic caveats

`pqtransport` provides **implementation evidence** (unit tests, live
RFC 10024 handshakes against pqforge, RFC 10024 length/concat tests).
It is **not** a validated cryptographic module. See
[doc/CLAIM_BOUNDARY.md](doc/CLAIM_BOUNDARY.md).

In particular:

- **No FIPS 140 / CMVP module status.** Do not deploy this library where a
  validated module is contractually or legally required without your own
  validation.
- **TLS hellos are RFC 8446-shaped** (`legacy_version`, `key_share`,
  `supported_versions`, SNI, ALPN). Certificate is still a raw ML-DSA-65
  public key. Cipher suite is IANA `0x1302` (SHA-384 AES-GCM) by default,
  `0x1303` (ChaCha) if offered. OpenSSL will not complete a handshake until
  a recorded fixture exists. See
  [doc/OPENSSL_INTEROP.md](doc/OPENSSL_INTEROP.md).
- **Record protection follows the suite.** `0x1302` is AES-256-GCM with
  HKDF-SHA-384. `0x1303` is ChaCha20-Poly1305 with HKDF-SHA-256.
- **Best-effort side-channel resistance.** Pure Dart compiled to the VM,
  dart2js, or dart2wasm cannot guarantee constant-time execution (JIT, GC,
  and per-iteration branch directions are out of our control).
- **Best-effort zeroization.** Secret buffers are overwritten where the
  code can see them, but Dart's garbage collector may have already copied
  or retained values.
- **P-256 / P-384 ECDH is live** via pqforge 0.4.4 for all three RFC 10024
  groups. Profile/group mismatches still fail closed (`requireGroup`). Do
  not vendor ECDH here.

These are documented design boundaries, not vulnerabilities. Reports that
*demonstrate* a concrete, exploitable weakening (for example, a parse that
accepts a truncated share, a replay that opens before the window check, or
a Finished MAC forgery) are in scope and welcome.

Primitive KATs (ML-KEM / ML-DSA / SLH-DSA) belong in
[pqcrypto](https://github.com/turkananation/pqcrypto), not here.

## Out of scope

- Requests for CMVP / FIPS 140 certification (a separate, formal process).
- Theoretical side-channel concerns already documented in
  [doc/SECURITY_AUDIT.md](doc/SECURITY_AUDIT.md) without a concrete exploit.
- Missing OpenSSL interop (tracked as LIM-01 / milestone 0.4; blocked on
  OPEN-01 hellos, not on ECDH).
- Vendoring cryptographic primitives inside this package. Consume pqforge.
