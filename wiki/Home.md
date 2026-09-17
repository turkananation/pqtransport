# pqtransport wiki

Pure-Dart post-quantum transport. Canonical docs live in the repository
under [`doc/INDEX.md`](https://github.com/turkananation/pqtransport/blob/main/doc/INDEX.md).

This wiki is a mirror of the high-traffic pages so GitHub Wiki search works.

| Page | Source |
|---|---|
| [Claim boundary](Claim-Boundary) | `doc/CLAIM_BOUNDARY.md` |
| [Architecture](Architecture) | `doc/ARCHITECTURE.md` |
| [Roadmap](Roadmap) | `doc/ROADMAP.md` |
| [Bugs](Bugs) | `doc/BUGS.md` |

## 0.1.0 snapshot

- Live handshake: **X25519MLKEM768** only
- Compact TLS encoding (not RFC 8446 ClientHello)
- HKDF-SHA-256 schedule (not IANA 0x1302)
- Not a FIPS 140 module
- No `dart:ffi`, no platform TLS on the PQ path

Crypto: [`pqforge`](https://github.com/turkananation/pqforge).
Infra: [`swissarmyknife`](https://github.com/turkananation/swissarmyknife).
Primitives evidence: [`pqcrypto`](https://github.com/turkananation/pqcrypto).
