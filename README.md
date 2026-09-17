# pqtransport

Pure-Dart post-quantum transport: UDP, TLS 1.3 hybrid key exchange
(RFC 10024), DNS/DoH/DoT, mDNS, QUIC, and HTTP/1.1–3.

## Project signals

[![pub.dev](https://img.shields.io/badge/pub.dev-pqtransport-0175c2?style=for-the-badge&logo=dart&logoColor=white)](https://pub.dev/packages/pqtransport)
[![version](https://img.shields.io/badge/version-0.1.0-0175c2?style=for-the-badge&logo=dart&logoColor=white)](pubspec.yaml)
[![API](https://img.shields.io/badge/API-doc%2FAPI.md-0ea5e9?style=for-the-badge&logo=dart&logoColor=white)](doc/API.md)
[![GitHub Pages](https://img.shields.io/badge/Pages-jaspr_site-4ee0d4?style=for-the-badge&logo=githubpages&logoColor=0b1220)](https://turkananation.github.io/pqtransport/)
[![Wiki](https://img.shields.io/badge/Wiki-claim_%26_roadmap-f5c35b?style=for-the-badge&logo=wikipedia&logoColor=0b1220)](https://github.com/turkananation/pqtransport/wiki)
[![license](https://img.shields.io/github/license/turkananation/pqtransport?style=for-the-badge&label=license&color=2ea043)](LICENSE)
[![Dart SDK](https://img.shields.io/badge/Dart-%3E%3D3.12.0-0175c2?style=for-the-badge&logo=dart&logoColor=white)](pubspec.yaml)
[![stars](https://img.shields.io/github/stars/turkananation/pqtransport?style=for-the-badge&logo=github&label=stars&color=181717)](https://github.com/turkananation/pqtransport/stargazers)

## Protocol surface

[![RFC 10024](https://img.shields.io/badge/RFC_10024-3_hybrid_groups-b6f25c?style=for-the-badge&logoColor=0b1220)](doc/ARCHITECTURE.md)
[![X25519MLKEM768](https://img.shields.io/badge/Live_KEX-X25519MLKEM768-2f855a?style=for-the-badge)](doc/FEATURES.md)
[![NIST groups](https://img.shields.io/badge/NIST_P--256%2FP--384-live_KEX-2f855a?style=for-the-badge)](doc/FEATURES.md)
[![AEAD](https://img.shields.io/badge/AEAD-AES--256--GCM_%2B_ChaCha-7c3aed?style=for-the-badge)](doc/API.md)
[![schedule](https://img.shields.io/badge/IANA-0x1302_SHA--384_%2B_0x1303-7c3aed?style=for-the-badge)](doc/CLAIM_BOUNDARY.md)
[![runtime](https://img.shields.io/badge/runtime-pure_Dart_%7C_0_FFI_%7C_VM_%2B_Flutter_%2B_Web-0175c2?style=for-the-badge&logo=dart&logoColor=white)](doc/PLATFORM_SUPPORT.md)
[![tests](https://img.shields.io/badge/tests-140_pass_%7C_90.7%25_lib-2ea043?style=for-the-badge)](doc/ACHIEVEMENTS.md)

## Automation and discovery

[![CI](https://img.shields.io/github/actions/workflow/status/turkananation/pqtransport/ci.yml?branch=main&style=for-the-badge&label=CI&logo=githubactions&logoColor=white)](https://github.com/turkananation/pqtransport/actions/workflows/ci.yml)
[![Publish](https://img.shields.io/github/actions/workflow/status/turkananation/pqtransport/publish.yml?style=for-the-badge&label=pub.dev&logo=dart&logoColor=white)](https://github.com/turkananation/pqtransport/actions/workflows/publish.yml)
[![Release](https://img.shields.io/github/actions/workflow/status/turkananation/pqtransport/release.yml?style=for-the-badge&label=Release&logo=github&logoColor=white)](https://github.com/turkananation/pqtransport/actions/workflows/release.yml)
[![CodeQL](https://img.shields.io/github/actions/workflow/status/turkananation/pqtransport/codeql.yml?branch=main&style=for-the-badge&label=CodeQL&logo=github&logoColor=white)](https://github.com/turkananation/pqtransport/actions/workflows/codeql.yml)
[![Pages workflow](https://img.shields.io/github/actions/workflow/status/turkananation/pqtransport/pages.yml?branch=main&style=for-the-badge&label=Pages&logo=githubactions&logoColor=white)](https://github.com/turkananation/pqtransport/actions/workflows/pages.yml)
[![Wiki sync](https://img.shields.io/github/actions/workflow/status/turkananation/pqtransport/sync-wiki.yml?branch=main&style=for-the-badge&label=Wiki&logo=githubactions&logoColor=white)](https://github.com/turkananation/pqtransport/actions/workflows/sync-wiki.yml)
[![OpenSSF Scorecard](https://img.shields.io/ossf-scorecard/github.com/turkananation/pqtransport?style=for-the-badge&label=Scorecard)](https://github.com/turkananation/pqtransport/actions/workflows/scorecard.yml)
[![llms.txt](https://img.shields.io/badge/AI-llms.txt-7c3aed?style=for-the-badge)](llms.txt)

## Claim boundary

[![CMVP](https://img.shields.io/badge/CMVP_%2F_FIPS_140-not_validated-bf8700?style=for-the-badge)](doc/CLAIM_BOUNDARY.md)
[![OpenSSL](https://img.shields.io/badge/OpenSSL_interop-not_started-bf8700?style=for-the-badge)](doc/OPENSSL_INTEROP.md)
[![encoding](https://img.shields.io/badge/TLS_wire-RFC_8446_hellos_(not_OpenSSL)-bf8700?style=for-the-badge)](doc/ROADMAP.md)
[![pqforge](https://img.shields.io/badge/crypto-pqforge-4ee0d4?style=for-the-badge)](https://github.com/turkananation/pqforge)
[![swissarmyknife](https://img.shields.io/badge/infra-swissarmyknife-b6f25c?style=for-the-badge)](https://github.com/turkananation/swissarmyknife)
[![pqcrypto](https://img.shields.io/badge/evidence-pqcrypto-2f855a?style=for-the-badge)](https://github.com/turkananation/pqcrypto)

Cryptography is exclusively [`package:pqforge`](https://pub.dev/packages/pqforge).
Infrastructure is exclusively [`package:swissarmyknife`](https://pub.dev/packages/swissarmyknife).
There is no `dart:ffi` and no platform TLS (`SecureSocket`) on the PQ path.

This is **not** a FIPS 140 module. Side-channel resistance and
zeroization in Dart are best-effort. ML-KEM/ML-DSA evidence lives in
`package:pqcrypto` (via pqforge).

Documentation (architecture, features, bugs, tracker, roadmap):
[`doc/INDEX.md`](doc/INDEX.md).
Site (Jaspr, same engine as swissarmyknife):
[turkananation.github.io/pqtransport](https://turkananation.github.io/pqtransport/).
Wiki: [github.com/turkananation/pqtransport/wiki](https://github.com/turkananation/pqtransport/wiki).
How the site is built: [`doc/SITE.md`](doc/SITE.md).

## Hybrid groups (RFC 10024)

| Group | Codepoint | Client | Server | Shared secret | Order |
|---|---|---|---|---|---|
| X25519MLKEM768 | 0x11EC | 1216 | 1120 | 64 | **ML-KEM then X25519** |
| SecP256r1MLKEM768 | 0x11EB | 1249 | 1153 | 64 | ECDHE then ML-KEM |
| SecP384r1MLKEM1024 | 0x11ED | 1665 | 1665 | 80 | ECDHE then ML-KEM |

Live handshake (KEM + classical ECDH + ML-DSA + AES-256-GCM records) is
implemented for **all three RFC 10024 groups**. SecP384r1MLKEM1024 requires
`PqForgeProfile.maximum`. Profile/group mismatches are refused (`requireGroup`)
rather than silently dropping the classical share.

TLS record protection defaults to AES-256-GCM with HKDF-SHA-384
(IANA `TLS_AES_256_GCM_SHA384`, `0x1302`). The client also offers
`TLS_CHACHA20_POLY1305_SHA256` (`0x1303`), which completes on VM,
dart2wasm, and dart2js via pqforge 0.4.5. Private-use `0xFF00` is retired.
Concatenation is RFC 10024-aligned and unit-tested — this release does **not**
claim OpenSSL interop.

## Install

```yaml
dependencies:
  pqtransport: ^0.1.0
  pqforge: ^0.4.5
  swissarmyknife: ^0.1.0
```

```dart
import 'package:pqtransport/pqtransport.dart';
```

IO datagrams / multicast: `import 'package:pqtransport/pqtransport_io.dart';`

## Consume

In-memory TLS 1.3 hybrid handshake (the same path the tests use):

```dart
final crypto = PqTransportCrypto();
final identity = PqTlsServerIdentity.generate(crypto);
final (a, b) = MemoryByteSocket.pair();
final client = PqTlsSocket.client(a, crypto: crypto);
final server = PqTlsSocket.server(b, crypto: crypto, identity: identity);
await Future.wait([server.handshake(), client.handshake()]);
final key = client.exporter('app', Uint8List(0), 32);
```

Encrypted UDP session:

```dart
final net = MemoryDatagramNetwork();
final kem = crypto.kemKeyGen();
final salt = crypto.randomBytes(16);
final a = PqEncryptedUdpSocket(
  raw: PqUdpSocket(channel: net.bind(epA), throttleWindow: Duration.zero),
  crypto: crypto,
);
final flight = await a.initiate(
  peerKemPublicKey: kem.publicKey,
  deploymentSalt: salt,
);
```

## Tests

```bash
dart test
bash tool/check_invariants.sh .
```

`dart analyze` is clean. **140 tests**, **90.7% line coverage** of `lib/`.
Gates: hybrid concat (all three groups), AEAD round-trip, replay-before-open,
TLS state machines, live RFC 10024 handshakes (X25519, P-256, P-384),
IANA `0x1302` / `0x1303` suites, `requireGroup` refuse,
`checkEncapsulationKey` on a bad modulus, HTTP/1.1 GET over `PqTlsSocket`,
DNS circuit-breaker + TTL cache, mDNS probe/announce/browse, ML-DSA-65 TXT,
QUIC CRYPTO frames carrying the 1216-byte share, `dart:io` UDP.

## Documentation

Canonical root: [`doc/INDEX.md`](doc/INDEX.md).

| Document | Purpose |
|---|---|
| [doc/ACHIEVEMENTS.md](doc/ACHIEVEMENTS.md) | What 0.1.0 shipped, with evidence |
| [doc/ARCHITECTURE.md](doc/ARCHITECTURE.md) | Layout, concat, TLS/UDP data flow |
| [doc/FEATURES.md](doc/FEATURES.md) | Done / partial / fail-closed / not started |
| [doc/API.md](doc/API.md) | Public types and consume examples |
| [doc/BUGS.md](doc/BUGS.md) | OPEN / BLK / LIM / FIX |
| [doc/TRACKER.md](doc/TRACKER.md) | Canonical tracker |
| [doc/ROADMAP.md](doc/ROADMAP.md) | 0.2 → 0.5, order is not optional |
| [doc/PQFORGE_EXPORTS.md](doc/PQFORGE_EXPORTS.md) | Consumed vs not-wired pqforge 0.4.5 APIs |
| [doc/CLAIM_BOUNDARY.md](doc/CLAIM_BOUNDARY.md) | Allowed vs forbidden wording |

## Sister packages

| Package | Role |
|---|---|
| [pqcrypto](https://github.com/turkananation/pqcrypto) | ML-KEM / ML-DSA / SLH-DSA primitives and KATs |
| [pqforge](https://github.com/turkananation/pqforge) | Hybrid crypto workflows this package consumes |
| [swissarmyknife](https://github.com/turkananation/swissarmyknife) | `Result`, `StateMachine`, `CircuitBreaker`, `Cache` |

## License

MIT. See [LICENSE](LICENSE).
