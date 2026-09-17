# Report: dart2js ChaCha (IANA 0x1303)

Last updated: 2026-09-17

**Status:** protocol guard in this tree. Crypto fix is **not** in this
package.

**Audience:** review of [PR #32](https://github.com/turkananation/pqtransport/pull/32).
**Scope:** Chrome CI failure on OPEN-13, what landed, what a professional
fix actually is. Not a FIPS 140 / CMVP document.

## 1. Incident

Chrome job `Web-portable tests (Chrome)` on PR #32:
`133 tests passed, 2 failed.`

| Test | Failure |
|---|---|
| `ChaCha-only offer selects 0x1303 and exporters match` | `PqTransportError(handshakeFailure: handshake_failure: kex PlatformException)` at `pq_tls_server.dart` server ingest of ClientHello |
| `ChaCha AEAD round-trip; bit-flip fails (OPEN-13)` | `full width integer not supported on this platform` from `pointycastle` `Platform.assertFullWidthInteger` → `Poly1305()` → `PqSymmetricPrimitives._chacha20Poly1305` |

Default IANA `0x1302` (AES-256-GCM, SHA-384) was already green on
dart2js. VM `dart test` was 138/138 before the follow-up.

## 2. Root cause

OPEN-13 wired TLS records to pqforge's **sync** helper:

`PqSymmetricPrimitives.chacha20Poly1305Encrypt` /
`chacha20Poly1305Decrypt`

That helper constructs PointyCastle `ChaCha20Poly1305(ChaCha7539Engine(),
Poly1305())`. `Poly1305()` calls
`Platform.instance.assertFullWidthInteger()`. The check is:

```text
9007199254740992 + 1 != 9007199254740992   // 2^53 + 1 ≠ 2^53
```

On dart2js integers are IEEE-754 doubles. `2^53 + 1 == 2^53`. PointyCastle
throws `PlatformException`. pqtransport's handshake `catch (e)` then
returned `handshake_failure: kex ${e.runtimeType}`.

That is two defects:

1. **Primitive:** sync ChaCha cannot run on dart2js.
2. **Protocol:** a record-AEAD platform limit was mislabeled as a KEX
   failure. That is fail-open in meaning even though the handshake
   stopped.

AES-GCM on the same path does not hit this check. UDP stays AES-GCM.
dart2wasm and the VM have 64-bit integers; ChaCha works there.

## 3. What this tree implemented (protocol guard)

Commit `6638cbd` on `slice-0.2.6-0.3.5-0.3.6`. Not a test skip.

| Change | Why |
|---|---|
| `transportHasFullWidthInteger` (runtime, same 2^53 expression as PointyCastle) | Detect the runtime that cannot run Poly1305 |
| `PqTransportCrypto.supportsChaCha20Poly1305` | Facade, not a protocol file |
| `aeadSeal` / `aeadOpen` throw `PqTransportError.unsupported` **before** calling pqforge | Do not leak `PlatformException` |
| Server `TlsCipherSuite.select(..., chachaOk:)` | Do not select `0x1303` then blow up mid-flight |
| ChaCha-only ClientHello on dart2js → `unsupported` (not `kex`) | Fail closed, honest code |
| Default `PqTlsClient` offer on dart2js is `[0x1302]` only | RFC 8446: do not advertise a suite you cannot finish |
| Client `_bindSuite` refuses a peer-selected `0x1303` it cannot run | Mixed VM-server / dart2js-client |
| `on PqTransportError` is not rewritten as `kex` | Stop the mislabel |
| Tests branch on `supportsChaCha20Poly1305` | VM still live-handshakes ChaCha. dart2js asserts `unsupported` and `64-bit`, and asserts the message is **not** `kex` / `PlatformException`. No `@TestOn('vm')`. |

140 tests pass on the VM. AES-GCM `0x1302` remains the web suite.

This is the correct **protocol** response: do not offer, select, or
complete IANA `0x1303` on a runtime that cannot run the AEAD, and do not
lie about why.

## 4. What this is not

It is **not** the professional **crypto** fix.

OPEN-13's job was "wire pqforge sync ChaCha." That export exists and is
wired. The export's engine is PointyCastle. Making ChaCha work on dart2js
is a primitive-engine change. This package does not vendor ChaCha,
Poly1305, or a second AEAD. Law: crypto stays in pqforge.

A copied `2^53` check is PointyCastle leaking into pqtransport. If pqforge
later ships a dart2js-safe **sync** helper, this tree would still refuse
`0x1303` on dart2js until the check is deleted. That coupling is
technical debt, recorded here on purpose.

Rejected as "fixes":

| Move | Why not |
|---|---|
| `@TestOn('vm')` / skip Chrome | Hides a real limit |
| Catch `PlatformException` and keep going | Fail-open |
| Vendor ChaCha / Poly1305 here | Splits the crypto story; forbidden |
| Depend on `pointycastle` or `cryptography` directly | Same split. Call pqforge only |
| Drop `0x1303` from the IANA list | VM/dart2wasm can run it. OPEN-13 stays Fixed |

## 5. Proper professional fix (pqforge)

pqforge 0.4.4 already has **two** ChaCha engines.

| Engine | API | dart2js |
|---|---|---|
| PointyCastle, **sync** | `PqSymmetricPrimitives.chacha20Poly1305Encrypt` | **No** (this incident) |
| `package:cryptography`, async session | `PqForgeAeadEngine` / `pq_cryptography_aead_engine.dart` | **Yes** — Dart Poly1305 is 32-bit; browsers can also use Web Crypto |

`package:cryptography` is already a pqforge dependency. The TLS record
path needs a **sync, caller-supplied-nonce** helper (`ciphertext \|\|
tag`, 12-byte nonce). The session object generates its own nonce and is
async — it is not a TLS record primitive (already noted in
[PQFORGE_EXPORTS.md](PQFORGE_EXPORTS.md)).

Professional sequence, in order:

1. **pqforge** — make the **sync** ChaCha helper dart2js-safe. Use the
   cryptography Dart engine (or a 32-bit Poly1305) under the same
   `chacha20Poly1305Encrypt` / `Decrypt` signatures. Do not change the
   wire layout. Pin a dart2js round-trip + bit-flip test in pqforge.
2. **pqforge** — export a capability (`supportsSyncChaCha` or equivalent)
   so callers do not copy PointyCastle's mantissa check.
3. **pqtransport** — consume the bumped pqforge. Drive
   `supportsChaCha20Poly1305` from that export (delete
   `transportHasFullWidthInteger`). Restore default offer
   `[0x1302, 0x1303]` on dart2js. Keep fail-closed for a true
   `unsupported` from the helper.
4. **Evidence here** — Chrome CI green on the existing ChaCha-only live
   handshake and AEAD tests, without a platform branch.

Until (1) lands, dart2js TLS is IANA `0x1302` only. That is honest. It
is not "ChaCha on the web."

## 6. Claim boundary

Allowed:

- "IANA `0x1303` is wired on VM / dart2wasm via pqforge sync ChaCha."
- "dart2js refuses `0x1303` with `unsupported` (PointyCastle Poly1305
  needs 64-bit integers)."
- "AES-GCM `0x1302` is the dart2js suite."

Forbidden:

- "ChaCha works on web" / "works on dart2js."
- Relabeling a Poly1305 platform throw as a KEX failure.
- Claiming this report, or this package, is a FIPS 140 / CMVP module.

## 7. Verdict

| Question | Answer |
|---|---|
| Was Chrome CI a flake? | No |
| Is the protocol guard correct? | Yes. Fail closed, honest code, tests not skipped |
| Is OPEN-13 still Fixed? | Yes — wired on runtimes that can run the export |
| Is ChaCha-on-dart2js done? | No. That is a pqforge engine slice |
| Next coding in **this** package? | No. Wait for the pqforge export. Do not vendor |
| Next coding in **pqforge**? | Sync ChaCha dart2js-safe + capability flag |

Evidence: `lib/src/core/crypto.dart`, `lib/src/tls/cipher_suite.dart`,
`lib/src/tls/pq_tls_client.dart`, `lib/src/tls/pq_tls_server.dart`,
`test/tls/cipher_suite_test.dart`, `test/core/crypto_facade_test.dart`.
pqforge engines: `pq_primitives.dart` (`_chacha20Poly1305`),
`pq_cryptography_aead_engine.dart`.
