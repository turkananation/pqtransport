# Report: dart2js ChaCha (IANA 0x1303)

Last updated: 2026-09-17

**Status:** resolved. pqforge **0.4.5** ships a dart2js-safe sync helper.
This tree consumes it (`pqforge: ^0.4.5`). Chrome CI must complete the
ChaCha-only live handshake and the AEAD round-trip **without** a
platform branch.

**Audience:** review of [PR #32](https://github.com/turkananation/pqtransport/pull/32).
**Scope:** Chrome CI failure on OPEN-13, the protocol guard that followed,
and the pqforge engine fix that retired the guard. Not a FIPS 140 / CMVP
document.

## 1. Incident

Chrome job `Web-portable tests (Chrome)` on PR #32 originally:

`133 tests passed, 2 failed.`

| Test | Failure |
|---|---|
| `ChaCha-only offer selects 0x1303 and exporters match` | `PqTransportError(handshakeFailure: handshake_failure: kex PlatformException)` at `pq_tls_server.dart` server ingest of ClientHello |
| `ChaCha AEAD round-trip; bit-flip fails (OPEN-13)` | `full width integer not supported on this platform` from `pointycastle` `Platform.assertFullWidthInteger` → `Poly1305()` → pqforge 0.4.4 `PqSymmetricPrimitives._chacha20Poly1305` |

Default IANA `0x1302` (AES-256-GCM, SHA-384) was already green on
dart2js.

## 2. Root cause

OPEN-13 wired TLS records to pqforge's **sync** helper:

`PqSymmetricPrimitives.chacha20Poly1305Encrypt` /
`chacha20Poly1305Decrypt`

In **0.4.4** that helper constructed PointyCastle
`ChaCha20Poly1305(ChaCha7539Engine(), Poly1305())`. `Poly1305()` calls
`Platform.instance.assertFullWidthInteger()`:

```text
9007199254740992 + 1 != 9007199254740992   // 2^53 + 1 ≠ 2^53
```

On dart2js integers are IEEE-754 doubles. `2^53 + 1 == 2^53`. PointyCastle
throws `PlatformException`. pqtransport's handshake `catch (e)` then
returned `handshake_failure: kex ${e.runtimeType}`.

That was two defects:

1. **Primitive:** sync ChaCha could not run on dart2js.
2. **Protocol:** a record-AEAD platform limit was mislabeled as a KEX
   failure.

AES-GCM on the same path does not hit this check. UDP stays AES-GCM.

## 3. What this tree did first (protocol guard)

A copied `2^53` check, `supportsChaCha20Poly1305` driven from it, dart2js
ClientHello offering `[0x1302]` only, and `unsupported` (not `kex`) on a
ChaCha-only offer. Tests were not skipped.

That was the correct **protocol** response while the primitive was
broken. It was **not** the crypto fix. Crypto stays in pqforge.

## 4. Professional fix (landed)

| Step | Where | What |
|---|---|---|
| 1 | pqforge 0.4.5 | Sync helper uses `package:cryptography`'s Dart engine (`DartChacha20.poly1305Aead`, 32-bit Poly1305). Same signatures, same RFC 8439 `ciphertext \|\| tag` layout, caller nonce. Chrome pin in pqforge. |
| 2 | pqforge 0.4.5 | `PqSymmetricPrimitives.supportsChaCha20Poly1305` — always `true`. |
| 3 | this package | Floor `pqforge: ^0.4.5`. Drive `PqTransportCrypto.supportsChaCha20Poly1305` from that export. Delete `transportHasFullWidthInteger`, `chachaUnavailableMessage`, `select(chachaOk:)`, `tlsOfferedCipherSuitesForRuntime`. Default offer `[0x1302, 0x1303]` on every runtime. |
| 4 | this package | Chrome CI: ChaCha-only live handshake + AEAD round-trip + RFC 8439 §2.8.2 through the facade. No platform branch. |

pqforge session ChaCha (`PqForgeSecureSession`) is still not a TLS record
primitive (async, nonce-prepended). Do not use it here.

## 5. Claim boundary

Allowed:

- "IANA `0x1303` is wired on VM, dart2wasm, **and dart2js** via pqforge
  0.4.5 sync ChaCha (Dart engine)."
- "Default ClientHello offers `0x1302` then `0x1303`. Server prefers
  `0x1302`."
- "UDP stays AES-256-GCM."

Forbidden:

- Relabeling a Poly1305 platform throw as a KEX failure.
- Claiming this package, or pqforge, is a FIPS 140 / CMVP module.
- Vendoring ChaCha / Poly1305 / `package:cryptography` in this tree.

## 6. Verdict

| Question | Answer |
|---|---|
| Was Chrome CI a flake? | No |
| Was the protocol guard correct at the time? | Yes. Fail closed, honest, tests not skipped |
| Is OPEN-13 still Fixed? | Yes — now on every runtime this package targets |
| Is ChaCha-on-dart2js done? | Yes, in **pqforge 0.4.5**, consumed here |
| Next coding in **this** package for ChaCha? | No. Do not vendor |

Evidence: `lib/src/core/crypto.dart`, `lib/src/tls/cipher_suite.dart`,
`lib/src/tls/pq_tls_client.dart`, `lib/src/tls/pq_tls_server.dart`,
`test/tls/cipher_suite_test.dart`, `test/core/crypto_facade_test.dart`.
pqforge: `pq_primitives.dart` (`DartChacha20.poly1305Aead`).
