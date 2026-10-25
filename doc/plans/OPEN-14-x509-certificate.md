# OPEN-14 implementation plan: X.509 Certificate

Last updated: 2026-10-25

Status: **proposed**, blocked on review of
[ADR-0014](../adr/ADR-0014-x509-certificate.md).
Issue: [#43](https://github.com/turkananation/pqtransport/issues/43).

This file is the build contract. The implementation PR either follows it
or amends it in the same PR. It does not mark FEATURES done. It does not
add an interop sentence.

## Decisions to confirm

| # | Recommendation | If you want the other one |
| --- | --- | --- |
| D1 | Default client offer stays `[RawPublicKey]`. X.509 is opt-in. | Say so. The LIM-01 flight must move with the default. |
| D2 | `certificate_list` length other than 1 fails closed. Chains stay Not started. | A path builder is a different issue (AIA still excluded). |
| D3 | Pin and/or hook. Self-signature alone does not authenticate. | This would make every self-signed peer succeed. |
| D4 | Classical algorithms are hook-only. No pqforge export in this issue. | P-384 ECDSA and RSA would be pqforge IDs first, then a later PR. |
| D5 | ML-DSA-44 is `unsupported`, not hooked. | Compact-profile TLS is its own slice. |
| D6 | Extension-less v1 certificates parse. Policy applies only to extensions that are present. Non-ASCII names fail closed. | Rejecting v1 means the stock `openssl req -x509` certificate cannot be the fixture. |
| D7 | Closing #43 requires the OpenSSL 3.5.9 X.509 flight on all three RFC 10024 groups, plus the untouched raw-pk flight. curl is attempted against that same OpenSSL. BoringSSL and browsers get no success sentence without a flight in that PR. | Requiring a green BoringSSL or Chrome run before closing #43 is a one-line change to this row. |
| D8 | New certificate failures write one fatal Alert. Old failure paths stay as they are. | |
| D9 | No `dart:io` on the web barrel. No system trust store. No AIA, OCSP, CT, or MTC. | |

## What is already true

Do not rebuild these.

| Piece | Where | Fact |
| --- | --- | --- |
| ML-DSA SPKI | `encodeMlDsa65Spki` / `decodeMlDsa65Spki` | RFC 9881 key, parameters absent, 65 and 87. |
| Certificate framing | `encodeCertificate` | context length 0, one entry, extensions length 0. Payload is the SPKI, which is legal only for RawPublicKey. |
| CertificateVerify | `encodeCertVerify`, `tls13ServerCertVerifyContent` | Scheme from signature length. 64 × `0x20`, context string, `0x00`, transcript hash. |
| Signature schemes | `lengths.dart` | `tlsSignatureMldsa65 = 0x0905`, `tlsSignatureMldsa87 = 0x0906`. OpenSSL 3.5 already checks these on the raw-pk flight. |
| Verify | `PqTransportCrypto.mlDsaVerify` | Selects 65 or 87 from lengths. `context` null. `preHash` is not exposed and must stay false. |
| Raw-pk flight | `tool/interop/openssl` | OpenSSL 3.5.9, three groups, `-enable_server_rpk`. Keep the command line. |
| Alerts on the error | `PqTransportError` | `decode_error` 50, `illegal_parameter` 47, `decrypt_error` 51, `handshake_failure` 40. `bad_certificate` 42, `unsupported_certificate` 43, `certificate_unknown` 46 are not constants yet. |
| Web barrel | `package:pqtransport/pqtransport.dart` | No `dart:io`. New types go through this barrel. `test/core/barrel_test.dart` imports only that library. |

## Module

New file `lib/src/tls/x509.dart`. Pure bytes. No `package:pqforge` import.
Signing is a `Uint8List Function(Uint8List tbs)` argument so the only
ML-DSA call site added on the handshake is `PqTransportCrypto`.

`handshake.dart` keeps the SPKI helpers and calls the X.509 parser.
No import cycle: `x509.dart` does not import `handshake.dart`.

### Wire

RFC 8446:

```text
Certificate {
  certificate_request_context<0..2^8-1>   // server: length 0
  certificate_list<0..2^24-1>             // this issue: exactly one entry
}
CertificateEntry {
  cert_data<1..2^24-1>                    // X509: RFC 5280 DER
                                          // RawPublicKey: RFC 7250 SPKI
  extensions<0..2^16-1>                   // unrecognized: ignore
}
```

`decodeCertificate` takes the negotiated type.

| Negotiated | Payload | Reject |
| --- | --- | --- |
| RawPublicKey (2) | Today's SPKI decode | A certificate. Context length other than 0. Empty list. Trailing bytes. |
| X.509 (0), including "extension was not sent" | One RFC 5280 certificate | A bare SPKI. Empty list. Two or more entries. Context length other than 0. |
| Anything else | | `unsupported` |

Client offer API, names fixed unless the review changes them:

```text
enum TlsCertificateType { x509, rawPublicKey }

PqTlsClient({
  List<TlsCertificateType> certificateTypes = const [TlsCertificateType.rawPublicKey],
  Uint8List? trustedSpki,
  PqCertificateHook? verifyPeer,
  DateTime Function()? now,
  String? serverName,
})
```

`PqCertificateHook` is synchronous and returns `Result<void, PqTransportError>`.
It receives the certificate DER, the leaf SPKI (when the algorithm is
ML-DSA; otherwise null), the CertificateVerify scheme, the RFC 8446
content, and the signature. It does not receive secrets.

Server:

```text
PqTlsServerIdentity({
  required Uint8List publicKey,
  required Uint8List secretKey,
  Uint8List? certificateDer,     // caller-supplied, leaf SPKI must match publicKey
  String? certificateDnsName,    // required to mint; ASCII LDH or "localhost"
})
```

Minting happens once. The encoded Certificate handshake message is cached
on the identity. `certificateDer` is sent as-is after it parses under our
own rules and its SPKI matches `publicKey`. A mismatch fails at identity
construction, not at the first ClientHello.

### Parser (RFC 5280 + RFC 9881)

Cursor, not a tree. DER only.

Reject before any signature:

- Indefinite length, non-minimal length, length-of-length of 0 or greater
  than 3, constructed encoding of a primitive, BIT STRING unused-bits
  other than 0.
- Depth above `tlsX509MaxDepth` (16). Name above `tlsX509MaxNameBytes`.
  One certificate above `tlsX509MaxCertificateBytes` (16384). Check the
  length and then allocate.
- `signatureAlgorithm` contents differ from `tbsCertificate.signature`.
- Parameters present on an ML-DSA AlgorithmIdentifier, including NULL.
- OID `id-ml-dsa-44` (last byte `0x11` on the same NIST arc).
- ML-DSA BIT STRING length other than the parameter-set size plus the
  unused-bits byte.
- Serial empty, negative, non-minimal, or longer than 20 octets.
- `notBefore` after `notAfter`. Time not `UTCTime`/`GeneralizedTime` in
  the RFC 5280 Z form (no fractions, no offsets). Comparison is inclusive.
  Clock is the injected `now`, UTC.
- v2. v1 with an extensions field. v3 tag that is not integer 2.
- Duplicate extension OID. Unknown critical extension.
- `keyUsage` present and `digitalSignature` clear.
- `extKeyUsage` present and `id-kp-serverAuth` (`1.3.6.1.5.5.7.3.1`) absent.
- `subjectAltName` present, `serverName` set, no match.
- `serverName` set, SAN absent.
- Non-ASCII in a DNS name or in `serverName`.
- Wildcard that is not the whole leftmost label, or that matches more
  than one label. `*.example.com` does not match `example.com`.

Then, for ML-DSA only:

- Issuer Name DER equals subject Name DER.
- `mlDsaVerify` over the **original TBS slice**, empty context.
- Pin, if any, then hook, if any.
- CertificateVerify scheme matches the OID. Second `mlDsaVerify` over
  `tls13ServerCertVerifyContent`. Failure here is `decrypt_error` even
  when the certificate signature succeeded.

`allowUnauthenticated: true` still runs the structural parse. It skips
both verifies, the pin, and the hook. `peerAuthenticated` stays false.
Application data is allowed only after Finished, as today.

### Alerts

Add to `lengths.dart` and use them. Do not overload `handshake_failure`
for a bad certificate.

| Condition | Alert |
| --- | --- |
| Truncation, bad DER, trailing junk, non-zero server context, empty list | `decode_error` (50) |
| Wrong inner length that is otherwise framed | `illegal_parameter` (47) |
| ML-DSA-44, unknown certificate type, classical with no hook, scheme not offered | `unsupported_certificate` (43) |
| Bad ML-DSA certificate signature, expired, name mismatch, pin mismatch, critical extension | `bad_certificate` (42) |
| Hook returns failure | `certificate_unknown` (46) |
| CertificateVerify fails | `decrypt_error` (51) |

Write one fatal Alert record with the handshake write key when those keys
exist. One record, then the `Result`. Do not send application data first.

`unsupported()` today has a null alert and is used outside TLS. Add a
TLS-specific factory rather than changing that one.

### Speed

The ML-DSA verify dominates. The parser's job is to do it at most twice
and to avoid work before a cheap reject.

- No ASN.1 object graph. No PEM on the handshake path. No re-encoding of
  TBS to verify.
- `Uint8List.sublistView` for TBS, SPKI, and signature slices that outlive
  the function. Copy only when the byte is cached on the identity.
- Cap, then allocate. A hostile length must fail inside `tlsX509MaxDepth`
  without building a 16 KiB object per nesting level.
- Server Certificate message cached. CertificateVerify is not cacheable
  (transcript).
- Extension scan stops at the first critical OID it does not implement.
  It does not decode every DirectoryString into Dart strings.
- Pin compare is `PqBytes.constantTimeEquals`.
- Do not add a timing gate in CI. Add a hostile-input test: nested
  SEQUENCEs at the depth cap, and a 16 KiB certificate of legal DER that
  fails an OID check, both returning `Result.failure` without calling
  `mlDsaVerify`. A test spy on the crypto object counts verifies: a
  rejected parse is 0, a good ML-DSA certificate plus CertificateVerify
  is 2.

### Negotiation matrix

| Client offer | Server has cert or DNS name | Server EE | Certificate payload |
| --- | --- | --- | --- |
| raw only | no | RawPublicKey, as today | SPKI |
| raw only | yes | RawPublicKey | SPKI. The certificate is not sent. |
| x509 only (omit extension) | no | none; handshake fails before ServerHello | |
| x509 only | yes | extension omitted | one X.509 |
| x509 explicit `[0]` | yes | echoes `0` | one X.509 |
| both, server has a certificate | yes | X.509 shape matching the offer | one X.509 |
| both, server has neither | no | RawPublicKey | SPKI |
| raw only, server selects X.509 | | client fails, no application data | |
| x509 only, server selects raw or omits the extension after the client sent `[2]` only | | client fails | |

QUIC uses the same handshake messages (`quic: true`). One in-memory test
covers that path. No new QUIC flight.

## Tests

File `test/tls/x509_test.dart` for the codec and `test/tls/certificate_type_test.dart`
for negotiation. Each row is one test. A missing row does not close the issue.

Codec, ML-DSA, both sides minted here:

- Round-trip a v3 leaf. SPKI from `decodeMlDsa65Spki` equals the key.
- TBS slice verifies. Flipping one TBS bit fails `bad_certificate` and
  does not run CertificateVerify.
- NULL parameters on the OID fail.
- ML-DSA-44 OID fails `unsupported_certificate`.
- Signature BIT STRING unused-bits `7` fails.
- Non-minimal length fails. Indefinite length fails.
- Serial of 21 octets fails. Negative serial fails.
- `notBefore == now` and `notAfter == now` succeed. One second outside fails.
- Injected clock, so the test does not call `DateTime.now`.
- Unknown critical extension fails. Unknown non-critical is ignored.
- Duplicate extension OID fails.
- `keyUsage` without `digitalSignature` fails. Absent `keyUsage` succeeds.
- EKU without serverAuth fails. Absent EKU succeeds.
- SAN mismatch fails. CN-only with `serverName` set fails.
- CN-only with `serverName` null and a matching pin succeeds.
- Wildcard `*.example.com` matches `a.example.com` and not `example.com`
  or `a.b.example.com`.
- Non-ASCII SAN fails.
- v1 extension-less certificate with a pin succeeds.
- v1 that somehow carries extensions fails.
- Depth-cap input fails with zero ML-DSA verifies.

Certificate message:

- Empty list fails.
- Two entries fail. No application data on the socket test.
- Non-zero `certificate_request_context` fails.
- Trailing byte after the list fails.
- RawPublicKey negotiated, body is an X.509 certificate: fail.
- X.509 negotiated, body is a bare SPKI: fail.
- CertificateEntry extension that is well-formed and unknown: ignored.
- CertificateEntry extension truncated: fail.
- CertificateVerify scheme 0x0906 on a 65 certificate: fail `decrypt_error`.
- CertificateVerify over a transcript that does not include this Certificate: fail.
- Hook returns failure: `peerAuthenticated` false, alert 46, socket has no
  application bytes.
- Hook unset, pin unset, self-signature valid: fail. This is the
  fail-open test.
- `allowUnauthenticated: true`: Finished can succeed, `peerAuthenticated`
  is false, hook is not called (spy).
- Classical AlgorithmIdentifier, hook null: fail. Hook success: 
  `peerAuthenticated` true and `mlDsaVerify` was not used for that
  certificate. The test's hook checks a fixed fixture byte, so the
  library is not claiming it verified ECDSA.

Negotiation:

- Default client still sends RawPublicKey only. Existing
  `rfc8446_hello_test.dart` stays green without edits, or the edits are
  limited to a new named argument's default.
- Client omits the extension, server has `certificateDnsName`, handshake
  completes with the pin, EE has no certificate-type extension.
- Client offers only raw, server has a certificate, payload is still the
  SPKI.
- Client offers only X.509, server has neither name nor DER: server
  fails and writes no ServerHello.
- Both offered, server has a certificate: X.509 on the wire.
- LIM-01 command line is unchanged. `git diff` of
  `tool/interop/openssl/handshake.dart` may only add a function.

Barrel:

- `certificateTypes`, the enum, and the hook type are reachable from
  `package:pqtransport/pqtransport.dart`.
- `grep dart:io lib/src/tls/x509.dart` is empty. The invariant script
  still passes.

## Interop flights

All of these run in the implementation PR, not this one. Version strings
are whatever `openssl version` printed that day, recorded in the PR and
in [OPENSSL_INTEROP.md](../OPENSSL_INTEROP.md). Do not write the sentence
before the log exists.

### OpenSSL 3.5.9 X.509 (required to close #43)

Same binary as LIM-01 (`tool/interop/openssl/run.sh`). New function beside
the raw-pk ones. Do not remove `-enable_server_rpk` from the old ones.

1. `genpkey -algorithm ML-DSA-65`.
2. Two certificates:
   - Stock: `req -new -x509` with the existing `openssl.cnf` (extension-less).
     Client pins the SPKI from `pkey -pubout -outform DER`. `serverName` null.
   - Leaf: a new `openssl-x509.cnf` with CA:FALSE, digitalSignature,
     serverAuth, `DNS:localhost`. Client sets `serverName: localhost`
     and the same pin.
3. `s_server -tls1_3` **without** `-enable_server_rpk`, groups and suite
   as today, `-naccept 1`.
4. Client `certificateTypes: [x509]`, offered suite `0x1302` only.
5. Assert `peerAuthenticated`, suite, and `read finished` in server stderr.
6. Repeat for SecP256r1MLKEM768 and SecP384r1MLKEM1024 (`maximum`).
7. Negative: the same server, client still on the default raw offer.
   Handshake fails. No application data. This proves we did not start
   accepting X.509 by accident on the raw path.

`s_client` against our server, with `-CAfile` of the certificate we minted,
is the other direction. One group is enough there (X25519MLKEM768) if the
s_server flight already covered three. Assert s_client exit 0 and a
protocol line of TLSv1.3. The server identity uses `certificateDnsName`.

### curl (required attempt, claim only if it passes)

Use a curl whose `curl -V` SSL backend is that same OpenSSL 3.5.9.
System curl on OpenSSL 3.0 is not a pass and not a skip: the script
exits non-zero with `curl is not the OpenSSL 3.5.9 under test`.

Command shape: `curl --cacert cert.pem --tls-max 1.3 --curves X25519MLKEM768
--http1.1 https://127.0.0.1:port/`. Our server speaks HTTP/1.1 on
`PqTlsSocket` after the handshake. Assert the body. Do not pass `-k`.

### BoringSSL (no sentence unless it passes)

If `bssl` is on the path, `bssl client -root-certs cert.pem` against our
server. Success: record the `bssl` revision and add one sentence to
OPENSSL_INTEROP. Failure or missing binary: leave the sentence as
"BoringSSL is not this fixture" and attach the stderr in the PR. Do not
treat a BoringSSL reject as a parser bug until we have read the alert.
It may be ML-DSA policy on that revision, which is still "not this fixture".

### Browsers (no success sentence in this issue)

Do not write "works with browsers".

Honest coverage, only if a capture is cheap:

- A ClientHello fixture that omits `server_certificate_type` and offers
  `X25519MLKEM768` is parsed as an X.509 offer. Checked in under
  `test/tls/fixtures/` with the source and date in a comment.
- Chrome 150 private PKI (user-added ML-DSA root) is a follow-up. It is
  not WebPKI and not MTC.

Out of this issue even if the review widens D7: fetching intermediates,
OCSP, CT, the host trust store, name constraints beyond "critical and
unknown fails", IDNA, public-suffix wildcards, client certificates,
`compress_certificate`, ECH.

## Implementation PR checklist

- [ ] ADR-0014 status set to Accepted, date of merge.
- [ ] `lib/src/tls/x509.dart` and the tests above.
- [ ] `lengths.dart` holds the new sizes, OIDs' last-arc constants that
      are not already there, and alert numbers. No new size literal in
      `x509.dart`.
- [ ] Raw-pk `run.sh` still green. New X.509 run green on three groups.
- [ ] `peerAuthenticated` false paths have a socket test with no
      application bytes.
- [ ] FEATURES: "X.509 / certificate chains" becomes a split row.
      Single certificate **Done**, with the test names. Chain building
      **Not started**.
- [ ] CLAIM_BOUNDARY and OPENSSL_INTEROP gain a sentence only for the
      flight that ran. Suggested shape, and only if true:
      "Handshake interop with OpenSSL 3.5.9 on the three RFC 10024 groups,
      auth mode X.509 single ML-DSA-65 certificate, SPKI pin, no path
      building (date). Not BoringSSL. Not a browser."
- [ ] CHANGELOG under Unreleased. No FIPS 140 wording.
- [ ] `bash tool/check_invariants.sh .`, `dart analyze --fatal-infos`,
      `dart test`.
- [ ] #43 stays open until that PR merges.

## Files this design expects the implementation to touch

| File | Change |
| --- | --- |
| `lib/src/tls/x509.dart` | New. Parser, policy, TBS builder. |
| `lib/src/tls/handshake.dart` | Type argument on the certificate codec. EE and ClientHello offer. |
| `lib/src/tls/pq_tls_client.dart` | Offer, pin, hook, clock, alert write, verify order. |
| `lib/src/tls/pq_tls_server.dart` | Select type. Cache Certificate. Mint or load DER. |
| `lib/src/tls/pq_tls_socket.dart` | Pass the new arguments. Do not default them to X.509. |
| `lib/src/core/lengths.dart` | Caps, alerts 42/43/46, certificate type 0. |
| `lib/src/core/errors.dart` | Factories for the three new alerts. |
| `lib/pqtransport.dart` | Export the enum and hook typedef if they are public. |
| `test/tls/x509_test.dart` | New. |
| `test/tls/certificate_type_test.dart` | New. |
| `tool/interop/openssl/handshake.dart` | Add, do not rewrite the raw-pk functions. |
| `tool/interop/openssl/openssl-x509.cnf` | New. Leaf profile. |
| `doc/FEATURES.md`, `CLAIM_BOUNDARY.md`, `OPENSSL_INTEROP.md`, `TRACKER.md`, `CHANGELOG.md` | After the flight, not before. |
