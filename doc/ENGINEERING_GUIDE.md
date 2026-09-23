# Engineering Guide

Last updated: 2026-09-17

How to work in this tree without violating the Distinguished Engineer
laws. Public consume examples live in [API.md](API.md). Claim limits live
in [CLAIM_BOUNDARY.md](CLAIM_BOUNDARY.md).

## Layout

```text
pqtransport/
  lib/pqtransport.dart       # web-safe barrel
  lib/pqtransport_io.dart    # + IoDatagramChannel
  lib/src/{core,socket,udp,tls,dns,mdns,quic,http}/
  test/                      # mirrors lib/src plus extra_coverage_test.dart
  example/                   # in-memory demos, not OpenSSL peers
  doc/                       # this folder
  site/                      # workspace member (Jaspr). Analyzed, not excluded.
  tool/agent_framework/      # machine-readable twin of the skill YAML
```

Skill (doctrine, not runtime):
`.grok/skills/pqtransport-distinguished-engineer/`.

## Setup

SDK floor is `>=3.12.0 <4.0.0`. In this sandbox the SDK is
`/opt/dart-sdk` (3.13.4). Put it on `PATH` before every command:

```bash
export PATH="/opt/dart-sdk/bin:$PATH"
cd pqtransport
dart pub get
```

Dependencies: `pqforge ^0.4.5`, `swissarmyknife ^0.1.0`. Do not add
`pqcrypto`, `pointycastle`, or `cryptography` as direct dependencies
to grab a missing helper — that splits the crypto story. Report the
gap in [PQFORGE_EXPORTS.md](PQFORGE_EXPORTS.md) instead.

## Commands

```bash
dart pub get
dart analyze --fatal-infos . site
dart test
dart test test/core
dart test test/tls/handshake_test.dart
dart format --set-exit-if-changed lib test example site
```

Invariant script (no `dart:ffi` import, no stray size literals, claim
language):

```bash
bash ../.grok/skills/pqtransport-distinguished-engineer/scripts/check_invariants.sh .
```

Coverage (line coverage of `lib/` is **90.7%**, `2466/2720`):

```bash
dart pub global activate coverage
dart pub global run coverage:test_with_coverage
```

Filter `SF:lib/` when quoting a number. Do not quote the whole-repo
percentage (that includes `test/`).

## Execution loop (every module)

```text
CONTRACT → LENGTHS → STATE MACHINE → RESULT CODECS → CRYPTO CALLS → TESTS → GATES
```

1. Name the RFC and the types. Do not invent a parallel API.
2. Add or reuse named constants in `lib/src/core/lengths.dart`. A raw
   numeric literal for a protocol size anywhere else is a defect.
3. `StateMachine<State, Event>` from swissarmyknife. Illegal
   `trigger` → `failed` + `Result.failure`.
4. Encode/decode as `Result<T, PqTransportError>`. No `!`, no bare
   `as`, no catching `Exception` to swallow corruption.
5. Crypto through `PqTransportCrypto` only, after length filters.
6. Tests in the same turn as the production code they pin.
7. Module gates in the skill `references/09-test-gates.md` / this
   folder's [TRACKER.md](TRACKER.md).

Build order:

```text
core lengths/errors → socket → udp → tls → dns → mdns → quic → http
```

Never HTTP/3 before QUIC. Never QUIC before the TLS exporter. Never
DoT before TLS.

## Laws (short form)

1. Zero native crypto. Zero FFI. No `SecureSocket` on the PQ path.
2. Do not reimplement ML-KEM / ML-DSA / X25519 / AES-GCM / HKDF.
3. Hybrid is mandatory. No classical-only fallback after a PQ hello.
4. Concatenation order is group-dependent (X25519: ML-KEM first).
5. Length-filter before deserialize-to-crypto.
6. `Result` for expected failures.
7. Best-effort `zeroize` in `finally`. Never claim hard erasure.
8. Replay and cheap checks before expensive crypto.
9. Fail secure: unknown group, failed verify, open circuit → teardown.
10. No FIPS 140 / CMVP / hard-constant-time claims.

Full list: [ARCHITECTURE.md](ARCHITECTURE.md) and the skill `SKILL.md`.

## Barrels

| Import | Allowed | Forbidden |
|---|---|---|
| `package:pqtransport/pqtransport.dart` | Codecs, machines, hybrid, TLS, DNS, HTTP, memory sockets | `dart:io`, `dart:ffi`, `SecureSocket` |
| `package:pqtransport/pqtransport_io.dart` | Everything above + `IoDatagramChannel` | Crypto of its own |

A new symbol on the web barrel needs a test that imports **only**
`package:pqtransport/pqtransport.dart` (`test/core/barrel_test.dart`).

## Coding defaults in this package

- Analyzer: `package:lints/recommended.yaml` plus `strict-casts`,
  `strict-inference`, `strict-raw-types`.
- `unawaited_futures`, `only_throw_errors`, `avoid_dynamic_calls`,
  `cancel_subscriptions`, `close_sinks`, `prefer_final_locals`.
- `public_member_api_docs` is off; do not spray doc comments on code
  you did not change.
- Hide pqforge's `requireLength` when both would be in scope
  (`import 'package:pqforge/pqforge.dart' hide requireLength`).
- `PqForgeCombiner` is not the TLS combiner.
- Application traffic secrets on `TlsKeySchedule` are `late`, not
  `late final` (`deriveApplication` reassigns them).
- Handshake vs application records use `TlsRecordEpoch` (independent
  sequences).
- Datagram replay peeks the sequence **before** AEAD open.
- `MemoryByteSocket` buffers until `onListen`. Do not "fix" that.
- `MemoryDatagramNetwork` delivers multicast only to sockets that joined
  `224.0.0.251` / `ff02::fb`.

## Agent checklist (print before a coding turn)

```text
[ ] Which phase / slice am I in?          (ROADMAP.md)
[ ] Which reference / doc did I re-read?
[ ] Which lengths will I touch?
[ ] Which StateMachine edges will I add?
[ ] Which pqforge type will I call (dartdoc-verified)?
[ ] Which tests ship in this turn?
[ ] What claim am I not allowed to make?  (CLAIM_BOUNDARY.md)
```

If you cannot fill that card, you are not ready to edit.

## Failure handling

- Analyzer error: fix before new features.
- Hybrid share test fail: **stop-ship**. Diff against RFC 10024 quoted
  concatenations in [ARCHITECTURE.md](ARCHITECTURE.md).
- Temptation to stub pqforge: refuse. Stub **peers**, never the crypto
  library.
- Temptation to use `SecureSocket` "just to get HTTP working": refuse.
- Temptation to vendor P-256 ECDH: refuse. Call `PqTransportCrypto.p256Agree`.

## Examples

| File | What it shows |
|---|---|
| `example/pq_tls_client.dart` | Compact in-memory handshake + exporter |
| `example/encrypted_udp_peer.dart` | X25519MLKEM768 UDP session |
| `example/mdns_discovery.dart` | Probe/announce/browse on the memory network |

These are not OpenSSL peers.

## Releasing

Tag `v<version>` on `main`. That tag runs
`.github/workflows/release.yml` (verify + GitHub Release) and
`.github/workflows/publish.yml` (pub.dev via OIDC, environment `pub.dev`).
Checklist: [ci/RELEASE_CHECKLIST.md](ci/RELEASE_CHECKLIST.md).
