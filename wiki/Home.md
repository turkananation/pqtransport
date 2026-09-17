# pqtransport wiki

Pure-Dart post-quantum transport. Canonical docs live in the repository
under [`doc/INDEX.md`](https://github.com/turkananation/pqtransport/blob/main/doc/INDEX.md).

This wiki is a mirror of the high-traffic pages so GitHub Wiki search works.

## Project signals

[![pub.dev](https://img.shields.io/badge/pub.dev-pqtransport-0175c2?style=for-the-badge&logo=dart&logoColor=white)](https://pub.dev/packages/pqtransport)
[![version](https://img.shields.io/badge/version-0.1.0-0175c2?style=for-the-badge&logo=dart&logoColor=white)](https://github.com/turkananation/pqtransport/blob/main/pubspec.yaml)
[![GitHub Pages](https://img.shields.io/badge/Pages-jaspr_site-4ee0d4?style=for-the-badge&logo=githubpages&logoColor=0b1220)](https://turkananation.github.io/pqtransport/)
[![Wiki](https://img.shields.io/badge/Wiki-this_page-f5c35b?style=for-the-badge&logo=wikipedia&logoColor=0b1220)](https://github.com/turkananation/pqtransport/wiki)
[![license](https://img.shields.io/github/license/turkananation/pqtransport?style=for-the-badge&label=license&color=2ea043)](https://github.com/turkananation/pqtransport/blob/main/LICENSE)
[![Dart SDK](https://img.shields.io/badge/Dart-%3E%3D3.12.0-0175c2?style=for-the-badge&logo=dart&logoColor=white)](https://github.com/turkananation/pqtransport/blob/main/pubspec.yaml)

## Protocol surface

[![RFC 10024](https://img.shields.io/badge/RFC_10024-3_hybrid_groups-b6f25c?style=for-the-badge)](https://github.com/turkananation/pqtransport/blob/main/doc/ARCHITECTURE.md)
[![X25519MLKEM768](https://img.shields.io/badge/Live_KEX-X25519MLKEM768-2f855a?style=for-the-badge)](https://github.com/turkananation/pqtransport/blob/main/doc/FEATURES.md)
[![NIST groups](https://img.shields.io/badge/NIST_P--256%2FP--384-live_KEX-2f855a?style=for-the-badge)](https://github.com/turkananation/pqtransport/blob/main/doc/FEATURES.md)
[![runtime](https://img.shields.io/badge/runtime-pure_Dart_%7C_0_FFI-0175c2?style=for-the-badge&logo=dart&logoColor=white)](https://github.com/turkananation/pqtransport/blob/main/doc/PLATFORM_SUPPORT.md)
[![tests](https://img.shields.io/badge/tests-104_pass_%7C_90.5%25_lib-2ea043?style=for-the-badge)](https://github.com/turkananation/pqtransport/blob/main/doc/ACHIEVEMENTS.md)

## Automation

[![CI](https://img.shields.io/github/actions/workflow/status/turkananation/pqtransport/ci.yml?branch=main&style=for-the-badge&label=CI&logo=githubactions&logoColor=white)](https://github.com/turkananation/pqtransport/actions/workflows/ci.yml)
[![Publish](https://img.shields.io/github/actions/workflow/status/turkananation/pqtransport/publish.yml?style=for-the-badge&label=pub.dev&logo=dart&logoColor=white)](https://github.com/turkananation/pqtransport/actions/workflows/publish.yml)
[![Release](https://img.shields.io/github/actions/workflow/status/turkananation/pqtransport/release.yml?style=for-the-badge&label=Release&logo=github&logoColor=white)](https://github.com/turkananation/pqtransport/actions/workflows/release.yml)
[![CodeQL](https://img.shields.io/github/actions/workflow/status/turkananation/pqtransport/codeql.yml?branch=main&style=for-the-badge&label=CodeQL&logo=github)](https://github.com/turkananation/pqtransport/actions/workflows/codeql.yml)
[![Pages workflow](https://img.shields.io/github/actions/workflow/status/turkananation/pqtransport/pages.yml?branch=main&style=for-the-badge&label=Pages&logo=githubactions&logoColor=white)](https://github.com/turkananation/pqtransport/actions/workflows/pages.yml)
[![Wiki sync](https://img.shields.io/github/actions/workflow/status/turkananation/pqtransport/sync-wiki.yml?branch=main&style=for-the-badge&label=Wiki&logo=githubactions&logoColor=white)](https://github.com/turkananation/pqtransport/actions/workflows/sync-wiki.yml)
[![OpenSSF Scorecard](https://img.shields.io/ossf-scorecard/github.com/turkananation/pqtransport?style=for-the-badge&label=Scorecard)](https://github.com/turkananation/pqtransport/actions/workflows/scorecard.yml)

## Claim boundary

[![CMVP](https://img.shields.io/badge/CMVP_%2F_FIPS_140-not_validated-bf8700?style=for-the-badge)](Claim-Boundary)
[![OpenSSL](https://img.shields.io/badge/OpenSSL_interop-not_started-bf8700?style=for-the-badge)](https://github.com/turkananation/pqtransport/blob/main/doc/OPENSSL_INTEROP.md)
[![encoding](https://img.shields.io/badge/TLS_wire-RFC_8446_hellos-bf8700?style=for-the-badge)](Roadmap)
[![pqforge](https://img.shields.io/badge/crypto-pqforge-4ee0d4?style=for-the-badge)](https://github.com/turkananation/pqforge)
[![swissarmyknife](https://img.shields.io/badge/infra-swissarmyknife-b6f25c?style=for-the-badge)](https://github.com/turkananation/swissarmyknife)
[![pqcrypto](https://img.shields.io/badge/evidence-pqcrypto-2f855a?style=for-the-badge)](https://github.com/turkananation/pqcrypto)

| Page | Source |
|---|---|
| [Claim boundary](Claim-Boundary) | `doc/CLAIM_BOUNDARY.md` |
| [Architecture](Architecture) | `doc/ARCHITECTURE.md` |
| [Roadmap](Roadmap) | `doc/ROADMAP.md` |
| [Bugs](Bugs) | `doc/BUGS.md` |

## 0.1.0 snapshot

- Live handshake: **all three RFC 10024 groups** (X25519, P-256, P-384)
- RFC 8446-shaped TLS hellos (cipher `0xFF00`, raw cert) — OPEN-01 done
- HKDF-SHA-256 schedule (not IANA 0x1302) — OPEN-02
- Not a FIPS 140 module
- No `dart:ffi`, no platform TLS on the PQ path

Crypto: [`pqforge`](https://github.com/turkananation/pqforge).
Infra: [`swissarmyknife`](https://github.com/turkananation/swissarmyknife).
Primitives evidence: [`pqcrypto`](https://github.com/turkananation/pqcrypto).
