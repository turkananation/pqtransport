# OPEN-14 implementation plan: X.509 Certificate

Last updated: 2026-10-27

Status: **proposed**, blocked on review of
[ADR-0014](../adr/ADR-0014-x509-certificate.md).
Issue: [#43](https://github.com/turkananation/pqtransport/issues/43).

This file is the build contract for two repositories. The implementation
PRs either follow it or amend it in the same PR. It does not mark FEATURES
done. It does not add an interop sentence. The 2026-10-25 contract (codec
in pqtransport, one certificate, classical algorithms as a hook) is withdrawn.

## Decisions to confirm

| # | Recommendation | If you want the other one |
| --- | --- | --- |
| D1 | Default client offer stays `[RawPublicKey]`, ML-DSA schemes only. X.509 is opt-in and is what a browser, curl, and default OpenSSL speak. | Moving the default breaks the LIM-01 flight. |
| D2 | `certificate_list` length 1 through 8, leaf first, path-checked. 0 is `decode_error`. Above 8 fails closed. | A single-entry cap cannot talk to a peer that sends an intermediate. |
| D3 | Trust is anchors and/or an SPKI pin, then an optional hook. A signature alone does not authenticate. | Treating every self-signed peer as trusted is fail-open. |
| D4 | Parse, mint, and every signature below live in pqforge `lib/src/certificates/x509.dart`, exported for any Dart caller. pqtransport does not import PointyCastle or `package:cryptography`. | A direct PointyCastle import here splits the crypto story. |
| D5 | ML-DSA-44 is verified inside `PqX509` and rejected by pqtransport TLS. | Offering 44 on the TLS path is a different identity. |
| D6 | v1 extension-less certificates parse. The parser accepts a legal UTF-8 DirectoryString. pqtransport rejects a non-ASCII `serverName` or DNS SAN. | Rejecting v1 drops the stock `openssl req -x509` fixture. |
| D7 | Closing #43 requires the OpenSSL 3.5.9 X.509 flight on all three RFC 10024 groups, the untouched raw-pk flight, and curl `--cacert` against that OpenSSL. A browser sentence requires a flight in that same PR. The protocol is able to answer a browser ClientHello only on an opted-in chain identity. | Requiring a green Chrome run before closing #43 is a one-line change to this row. |
| D8 | New certificate failures write one fatal Alert. Old failure paths stay as they are. | |
| D9 | No `dart:io` trust store on the web barrel. No AIA, OCSP, CT, or MTC. Anchors are DER bytes the caller supplies. | |

## Order

1. Merge this design. No Dart change.
2. pqforge PR to 0.4.8. Implements the API in this file. Adds `doc/decisions/ADR-0003-x509.md` with the same decisions. Ships to pub.dev.
3. pqtransport PR bumps `pqforge: ^0.4.8`, applies TLS policy, runs the flights. No parser in this repo.

Do not start step 3 against a git commit of pqforge.

## What is already true

Do not rebuild these.

| Piece | Where | Fact |
| --- | --- | --- |
| ML-DSA SPKI | `encodeMlDsa65Spki` / `decodeMlDsa65Spki` | RFC 9881 key, parameters absent, 65 and 87. The pqforge parser must accept those bytes as a leaf key. |
| Certificate framing | `encodeCertificate` | context 0, one entry, extensions 0. Payload is the SPKI. Legal only for RawPublicKey. |
| CertificateVerify content | `tls13ServerCertVerifyContent` | 64 × `0x20`, context string, `0x00`, transcript hash. |
| ML-DSA schemes | `lengths.dart` | `0x0905`, `0x0906`. |
| P-256 ECDSA | `PqEcdsaP256.verify` | Hashes with SHA-256. Raw `r\|\|s`. Rejects high-S. |
| Ed25519 today | `PqClassicalProvider.ed25519Verify` | Async. Not used by `PqX509`. |
| Raw-pk flight | `tool/interop/openssl` | OpenSSL 3.5.9, three groups, `-enable_server_rpk`. Keep the command line. |
| Alerts on the error | `PqTransportError` | 50, 47, 51, 40 exist. 42, 43, 46 do not. |
| Web barrel | `package:pqtransport/pqtransport.dart` | No `dart:io`. |

## pqforge 0.4.8

### Files

| File | Export |
| --- | --- |
| `lib/src/certificates/x509.dart` | Yes. Public types only. |
| `lib/src/certificates/x509_der.dart` | No. Cursor. |
| `lib/src/certificates/x509_sig.dart` | No. Dispatch. |
| `lib/src/hybrid/pq_ecdsa_p384.dart` | Yes, same way `PqEcdsaP256` is exported. |
| `lib/src/hybrid/pq_rsa.dart` | Yes. |
| `lib/src/hybrid/pq_ed25519.dart` | Yes. Sync verify and sign. |
| `lib/pqforge.dart` | Adds those exports. Does not export the cursor. |
| `doc/decisions/ADR-0003-x509.md` | Records this contract. |
| `test/pq_x509_test.dart` | Parser, path, mint, each algorithm. |

No `dart:io` in `lib/src/certificates/`. No swissarmyknife. No TLS alert numbers. Parse and path failures are `PqX509Failure`. They do not throw. `ArgumentError` is not used for hostile DER.

### Model

```dart
abstract final class PqX509 {
  static PqX509Parsed parse(Uint8List der);

  /// Signature over [certificate.tbs] under [key].
  /// False for a wrong key, a wrong algorithm, or a bad signature.
  static bool checkSignature(
    PqX509Certificate certificate,
    PqX509PublicKey key,
  );

  static PqX509Path validate({
    required List<Uint8List> chain,
    required List<Uint8List> anchors,
    required DateTime now,
  });

  /// Self-signed v3 TLS leaf. Issuer name equals subject name.
  /// [sign] is called once, on the exact TBS bytes that are embedded.
  static Uint8List mintLeaf({
    required PqX509Name subject,
    required PqX509PublicKey publicKey,
    required PqX509Algorithm algorithm,
    required Uint8List Function(Uint8List tbs) sign,
    required DateTime notBefore,
    required DateTime notAfter,
    required Uint8List serial,
    required List<PqX509GeneralName> subjectAltNames,
  });
}

final class PqX509Parsed {
  final PqX509Certificate? certificate;
  final PqX509Failure? failure;
}

final class PqX509Path {
  final bool trusted;
  final PqX509Certificate? leaf;
  final PqX509Failure? failure;
}

enum PqX509Failure {
  truncated,
  notDer,
  unsupportedVersion,
  unsupportedAlgorithm,
  badTime,
  badName,
  depth,
  tooLarge,
  badSignature,
  expired,
  notYetValid,
  untrusted,
  pathTooLong,
  badConstraint,
}

enum PqX509Algorithm {
  mlDsa44,
  mlDsa65,
  mlDsa87,
  ecdsaP256Sha256,
  ecdsaP384Sha384,
  ed25519,
  rsaPkcs1Sha256,
  rsaPkcs1Sha384,
  rsaPkcs1Sha512,
  rsaPssSha256,
  rsaPssSha384,
  rsaPssSha512,
}

sealed class PqX509PublicKey {
  const PqX509PublicKey();
}

final class PqX509MlDsaKey extends PqX509PublicKey {
  final PqX509Algorithm algorithm; // mlDsa44, mlDsa65, or mlDsa87
  final Uint8List raw;
}

final class PqX509EcdsaP256Key extends PqX509PublicKey {
  final Uint8List uncompressed; // 65 bytes, 0x04 || X || Y
}

final class PqX509EcdsaP384Key extends PqX509PublicKey {
  final Uint8List uncompressed; // 97 bytes, 0x04 || X || Y
}

final class PqX509Ed25519Key extends PqX509PublicKey {
  final Uint8List raw; // 32 bytes
}

final class PqX509RsaKey extends PqX509PublicKey {
  final Uint8List modulus;  // unsigned, 256, 384, or 512 bytes
  final Uint8List exponent; // unsigned, no sign bit
}

final class PqX509Certificate {
  final Uint8List der;
  final Uint8List tbs;          // exact bytes covered by the signature
  final PqX509Algorithm algorithm;
  final Uint8List signature;    // algorithm-specific, see Formats
  final Uint8List issuerDer;
  final Uint8List subjectDer;
  final Uint8List serial;
  final DateTime notBefore;     // UTC
  final DateTime notAfter;      // UTC
  final PqX509PublicKey publicKey;
  final int version;            // 1 or 3
  final List<PqX509Extension> extensions;
  final List<PqX509GeneralName> subjectAltNames;
  final bool? ca;               // null when basicConstraints is absent
  final int? pathLen;
  final int? keyUsageBits;      // null when keyUsage is absent
  final List<List<int>> extKeyUsage;
}

final class PqX509Extension {
  final List<int> oid;
  final bool critical;
  final Uint8List value;
}

sealed class PqX509GeneralName {}
// dns(String ascii)  ip4(Uint8List 4)  ip6(Uint8List 16)
// other names stay in the raw extension and are not a DNS match

final class PqX509Name {
  final Uint8List der;
  // subject for mintLeaf: one CN, PrintableString if it fits, else UTF8String
}
```

`tbs`, `der`, and `signature` are copies owned by the certificate. Callers may drop the input buffer. The handshake cache copies once, at identity construction, not per flight.

`now` is required. `PqX509` does not call `DateTime.now`. Comparison is inclusive. A non-UTC `DateTime` is read as UTC wall-clock components only if `isUtc` is true; otherwise `validate` returns `badTime`. Callers pass `now.toUtc()`.

### Formats

DER only. Reject indefinite length, non-minimal length, length-of-length of 0 or greater than 3, a constructed encoding of a primitive, and a BIT STRING whose unused-bits are not 0. Depth cap 16. One certificate at most 65536 bytes. One name at most 8192 bytes. Check the length, then allocate. Serial is not empty, not negative, minimal, and at most 20 octets.

```text
Certificate ::= SEQUENCE {
  tbsCertificate       TBSCertificate,
  signatureAlgorithm   AlgorithmIdentifier,
  signatureValue       BIT STRING
}
```

`signatureAlgorithm` contents must equal `tbsCertificate.signature`. Version omitted means v1, and v1 with an extensions field fails. v2 fails. v3 is `[0] EXPLICIT INTEGER 2`.

Times are `UTCTime` or `GeneralizedTime`, RFC 5280 Zulu form, no fractions, no offsets. `notBefore` after `notAfter` fails.

| Algorithm | AlgorithmIdentifier | Public key | Signature bits |
| --- | --- | --- | --- |
| ML-DSA-65/87/44 | OID, parameters field absent. NULL is a failure. | raw key, BIT STRING | raw signature |
| ECDSA P-256 / P-384 | `ecdsa-with-SHA256` or `ecdsa-with-SHA384`, parameters absent. SPKI is `id-ecPublicKey` plus the named curve. | uncompressed point | DER `SEQUENCE { INTEGER r, INTEGER s }`, then fixed-width `r\|\|s` (32 or 48). High-S fails. |
| Ed25519 | OID `1.3.101.112`, parameters absent (RFC 8410). | 32 bytes | 64 bytes |
| RSA PKCS#1 | `sha256WithRSAEncryption` and the 384/512 siblings. Parameters NULL. SPKI algorithm `rsaEncryption`, parameters NULL. | `SEQUENCE { n, e }` | DigestInfo inside PKCS#1 v1.5 |
| RSA-PSS | `id-RSASSA-PSS`. Parameters, when present, are hash, MGF1 with the same hash, salt length equal to the hash, trailer 1. Absent parameters mean those defaults. Anything else fails. | same RSA SPKI | PSS |

RSA modulus is 2048, 3072, or 4096 bits. Exponent is odd and in `3 .. 2^32-1`. Other sizes fail `unsupportedAlgorithm` rather than running a general BigInt verifier on a hostile modulus.

HashML-DSA (`preHash: true`) is not a certificate algorithm. Do not re-encode TBS to verify. The slice in `tbs` is the input.

`mintLeaf` writes a v3 leaf and nothing else:

- `basicConstraints` cA false, critical
- `keyUsage` digitalSignature, critical
- `extKeyUsage` `id-kp-serverAuth` (`1.3.6.1.5.5.7.3.1`)
- `subjectAltName` from the argument
- serial at most 20 octets
- validity from the arguments
- signature from `sign(tbs)` embedded unchanged

`mintLeaf` then `parse` then `checkSignature` with the same public key must succeed. The minter does not invent a CA, a chain, or an extension-less v1 certificate. OpenSSL's extension-less certificate is accepted by `parse` and is not what we emit.

### Path

`validate` implements this subset of RFC 5280 §6. It does not fetch, and it does not read a trust store.

1. Reject an empty chain, an empty anchor list, or a chain longer than 8.
2. `parse` every certificate and every anchor. Any parse failure stops.
3. Leaf is `chain[0]`. Each certificate's issuer DER equals the next certificate's subject DER. The last certificate's issuer DER equals some anchor's subject DER.
4. `checkSignature` on each certificate under the next key. The last certificate is checked under the matching anchor's key. An anchor is not checked against a further issuer.
5. Each certificate is inside its validity, inclusive, at `now`.
6. Every certificate except the leaf has `ca == true` and keyUsage either absent or containing keyCertSign. A `pathLen` that the remaining intermediates exceed fails `badConstraint`.
7. A critical extension this function does not understand fails `badConstraint`. Non-critical unknown extensions are ignored.
8. `nameConstraints`, when present, may constrain DNS and IP only. Any other form, critical or not, fails `badConstraint`. Permitted and excluded subtrees of DNS and IP are enforced. This function does not apply RFC 9525 wildcards; that is TLS policy.
9. On success, `trusted` is true and `leaf` is `chain[0]`. A self-signed leaf is trusted only when it chains to an anchor, including the case where the anchor is that same certificate.

### Signature helpers

`PqEcdsaP384` matches `PqEcdsaP256`: uncompressed point, raw `r\|\|s`, SHA-384 inside the signer, low-S, `verify` returns false and does not throw. PointyCastle `ECCurve_secp384r1`. 97-byte public key, 96-byte signature.

`PqRsa.verifyPkcs1` and `PqRsa.verifyPss` take the modulus, the exponent, the message (not a pre-hash), and the signature. PointyCastle `RSASigner` / `PSSSigner`. False on a bad input. No new package.

`PqEd25519.verify` is synchronous RFC 8032. 32-byte key, 64-byte signature, message not pre-hashed. Test it against the existing async provider's vectors. `PqX509.checkSignature` does not call `Future`-based `ed25519Verify`.

`checkSignature` hashes only inside the ECDSA and RSA helpers. ML-DSA and Ed25519 take the TBS or the TLS content as-is.

## pqtransport

No `lib/src/tls/x509.dart`. `PqTransportCrypto` grows thin wrappers that call `PqX509`, `PqEcdsaP384`, `PqRsa`, and `PqEd25519`. Handshake code does not call PointyCastle.

### Client

```dart
enum TlsCertificateType { x509, rawPublicKey }

PqTlsClient({
  List<TlsCertificateType> certificateTypes =
      const [TlsCertificateType.rawPublicKey],
  List<Uint8List> trustAnchors = const [],
  Uint8List? trustedSpki,
  PqCertificateHook? verifyPeer,
  DateTime Function()? now,
  String? serverName,
})
```

`PqCertificateHook` is synchronous. It returns `Result<void, PqTransportError>`. It receives the leaf `PqX509Certificate`, the chain DER, and the CertificateVerify bytes. It does not receive secrets. It is not called unless `PqX509` already returned trusted, or the pin path already matched. A hook cannot authorize a certificate the signature check rejected.

`now` defaults to `DateTime.now().toUtc` at the call. Tests inject it.

Trust order on the X.509 path:

1. Structural `parse` of each entry. Failure is `decode_error` or `unsupported_certificate` as in the alert table.
2. Anchors non-empty: `validate`. Failure is `bad_certificate`.
3. Anchors empty and pin set: one certificate, self-signed, `checkSignature` with its own key, pin match. Pin compare uses `PqBytes.constantTimeEquals` on the SPKI encoding.
4. Anchors empty and pin empty: fail closed. `bad_certificate`. `peerAuthenticated` stays false.
5. Hook, if set. Failure is `certificate_unknown`.
6. CertificateVerify under the leaf key over `tls13ServerCertVerifyContent`. Failure is `decrypt_error`. Scheme must match the leaf algorithm. RSA PKCS#1 here is `unsupported_certificate`.

`allowUnauthenticated: true` still parses. It skips steps 2 through 6. `peerAuthenticated` stays false. Application data is allowed only after Finished, as today.

SAN policy, only when `serverName` is set: match DNS or IP in `subjectAltNames`, ignore CN, wildcard only as the whole leftmost label, `*.example.com` does not match `example.com`. No SAN fails closed. `serverName` null skips the name check so the extension-less OpenSSL certificate can be pinned.

### Server

Existing ML-DSA constructors stay valid. `certificateChain` empty means raw only.

```dart
PqTlsServerIdentity.x509({
  required PqX509PublicKey leafKey,
  required Uint8List Function(Uint8List content) sign,
  required List<Uint8List> chain, // leaf first, 1..8
  String? certificateDnsName,
})
```

The ML-DSA constructors gain optional `List<Uint8List> certificateChain` and `String? certificateDnsName`. When the chain is non-empty, `sign` is ML-DSA over the CertificateVerify content, empty context, `preHash` false. A classical identity uses `PqTlsServerIdentity.x509` and a `sign` that calls `PqEcdsaP256`, `PqEcdsaP384`, `PqRsa`, or `PqEd25519`. pqtransport does not implement that math.

At construction: `parse` every certificate, leaf key equals `leafKey`, chain length is in 1..8. Mismatch fails before any ClientHello. The encoded Certificate handshake message is cached. CertificateVerify is not cached.

`mintLeaf` is how a test and the OpenSSL-free in-tree server build a single self-signed leaf. A browser test that needs an intermediate uses OpenSSL to mint the chain and passes the bytes. This package does not mint a CA.

Server `signature_algorithms` rule:

| Identity | ClientHello must offer | Sent scheme |
| --- | --- | --- |
| Raw, or X.509 ML-DSA-65 | `0x0905` (today's check) | `0x0905` |
| X.509 ML-DSA-87 | `0x0906` | `0x0906` |
| X.509 P-256 | `0x0403` | `0x0403` |
| X.509 P-384 | `0x0503` | `0x0503` |
| X.509 Ed25519 | `0x0807` | `0x0807` |
| X.509 RSA | `0x0804` (SHA-256 PSS). Also accept `0x0805` / `0x0806` when that is the leaf hash. Never PKCS#1. | the offered PSS scheme |
| X.509 ML-DSA-44 | | fail at construction |

A raw identity keeps rejecting a ClientHello that omits ML-DSA-65. An X.509 identity does not apply that check. It applies the row above. A browser that offers only classical schemes completes only against a classical identity. A browser that offers `0x0905` completes against an ML-DSA-65 chain, which is the Chrome private-PKI shape, and only if that browser trusts the anchor.

### Wire

```text
Certificate {
  certificate_request_context<0..2^8-1>   // server: length 0
  certificate_list<0..2^24-1>             // 1..8 on the X.509 path
}
CertificateEntry {
  cert_data<1..2^24-1>
  extensions<0..2^16-1>                   // unrecognized: ignore
}
```

| Negotiated | Payload | Reject |
| --- | --- | --- |
| RawPublicKey (2) | Today's SPKI decode | A certificate. Context length other than 0. Empty list. More than one entry. Trailing bytes. |
| X.509 (0), including "extension was not sent" | 1..8 DER certificates | A bare SPKI. Empty list. More than 8. Context length other than 0. |

### Negotiation

| Client offer | Server chain | Server EE | Payload |
| --- | --- | --- | --- |
| raw only | empty | RawPublicKey, as today | SPKI |
| raw only | non-empty | RawPublicKey | SPKI. The chain is not sent. |
| x509 only (omit extension) | empty | none; fail before ServerHello | |
| x509 only | non-empty | extension omitted | chain |
| x509 explicit `[0]` | non-empty | echoes `0` | chain |
| both, server has a chain | non-empty | X.509, matching the offer | chain |
| both, server has no chain | empty | RawPublicKey | SPKI |
| raw only, peer sends X.509 | | client fails, no application data | |
| browser ClientHello, omits the extension, no ML-DSA scheme | ML-DSA identity | fail before ServerHello. Do not send a raw key. | |
| browser ClientHello, omits the extension, offers the leaf scheme | matching `x509` identity | extension omitted | chain |

QUIC uses the same handshake messages. One in-memory test sets `quic: true`. No new QUIC flight.

### Alerts

Add to `lengths.dart`. Do not overload `handshake_failure` for a bad certificate.

| Condition | Alert |
| --- | --- |
| Truncation, bad DER, trailing junk, non-zero server context, empty list | `decode_error` (50) |
| Wrong inner length that is otherwise framed | `illegal_parameter` (47) |
| ML-DSA-44 on the TLS path, unknown type, scheme not offered, RSA PKCS#1 on CertificateVerify, chain longer than 8 | `unsupported_certificate` (43) |
| Bad signature, expired, name mismatch, pin mismatch, path failure, critical extension the policy rejects | `bad_certificate` (42) |
| Hook returns failure | `certificate_unknown` (46) |
| CertificateVerify fails | `decrypt_error` (51) |

`PqX509Failure.unsupportedAlgorithm` maps to 43. `badSignature`, `expired`, `notYetValid`, `untrusted`, `badConstraint`, `pathTooLong` map to 42. `truncated` and `notDer` map to 50.

Write one fatal Alert record with the handshake write key when those keys exist. Then the `Result`. `unsupported()` today has a null alert. Add a TLS-specific factory rather than changing that one.

### Speed

The signature dominates. The parser's job is to reject before that call.

- No ASN.1 object per node. No PEM on the handshake path. No re-encoding of TBS.
- Cap, then allocate. A hostile length fails inside the depth cap without a 64 KiB object per nesting level.
- Server Certificate message cached.
- Pin compare is `PqBytes.constantTimeEquals`.
- RSA modulus sizes are the three named above, so a 65536-byte "modulus" never reaches the verifier.
- One `checkSignature` per certificate in the chain, plus one for CertificateVerify. A rejected parse calls it zero times.
- Do not add a timing gate in CI. Hostile-input tests: nested SEQUENCEs at the depth cap, and a max-size certificate that fails an OID check, both with a spy that counts verifies.

## Tests

pqforge, `test/pq_x509_test.dart`, each row one test:

- Round-trip `mintLeaf` for ML-DSA-65, ML-DSA-87, P-256, P-384, Ed25519, RSA-PSS SHA-256, RSA PKCS#1 SHA-256.
- Flipping one TBS bit makes `checkSignature` false.
- NULL parameters on an ML-DSA or ECDSA AlgorithmIdentifier fail `notDer`.
- ML-DSA-44 parses and verifies. It is not a TLS scheme.
- Non-minimal DER, indefinite length, unused-bits other than 0, serial of 21 octets, negative serial.
- `notBefore == now` and `notAfter == now` succeed. One second outside fails. The test passes `now`. It does not call `DateTime.now`.
- v1 extension-less with a matching anchor succeeds. v1 carrying extensions fails. v2 fails.
- Chain of leaf plus intermediate plus anchor succeeds. A broken link fails `badSignature`. A ninth certificate fails `pathTooLong`.
- Unknown critical extension fails `badConstraint`. Unknown non-critical is ignored.
- `nameConstraints` with a URI fails `badConstraint`. A DNS permitted subtree is enforced.
- RSA modulus of 1024 bits and of 8192 bits fail. Exponent 1 fails. Exponent 65537 succeeds.
- High-S ECDSA fails. DER `r` and `s` with a leading `0x00` sign byte succeed and are the same integer as the raw form.
- Ed25519 sync verify matches the async provider on the same vectors.
- `mintLeaf` output parses, verifies, and validates against itself as the only anchor.

pqtransport, `test/tls/certificate_type_test.dart` and the existing hello tests:

- Default client bytes are unchanged. `rfc8446_hello_test.dart` stays green without edits, or the edits are a new named argument's default.
- Client omits the extension, server has a one-certificate ML-DSA chain, pin or anchor set, handshake completes, EE has no certificate-type extension.
- Client offers only raw, server has a chain, payload is still the SPKI.
- Client offers only X.509, server has no chain: no ServerHello.
- Chain of two with an anchor succeeds. Chain of nine fails, no application data.
- Empty list fails. Non-zero context fails. Raw negotiated with an X.509 body fails. X.509 negotiated with a bare SPKI fails.
- CertificateVerify scheme `0x0906` on a 65 leaf is `decrypt_error`.
- RSA PKCS#1 on CertificateVerify is `unsupported_certificate` even if the leaf's certificate signature was PKCS#1.
- Hook unset, anchors empty, pin unset, self-signature valid: fail.
- `allowUnauthenticated: true`: Finished can succeed, `peerAuthenticated` is false, hook spy is not called.
- Classical leaf, hook null: pqforge verified it. `mlDsaVerify` was not called. The test's spy counts calls.
- Browser-shaped ClientHello fixture: no `server_certificate_type`, no ML-DSA scheme, P-256 offered. Against an ML-DSA identity, no ServerHello. Against a P-256 `x509` identity with a chain, handshake completes in memory.
- `grep pointycastle lib/` and `grep cryptography lib/` are empty. The invariant script still passes.
- QUIC in-memory handshake with `certificateTypes: [x509]` completes.

## Interop flights

Run in the pqtransport implementation PR, not this one. Record `openssl version` that day. Do not write the sentence before the log exists.

### OpenSSL 3.5.9 X.509 (required to close #43)

Same binary as LIM-01. New function. Do not remove `-enable_server_rpk` from the old one.

1. `genpkey -algorithm ML-DSA-65`.
2. Two server certificates: the stock extension-less `req -new -x509`, and a v3 leaf (`CA:FALSE`, digitalSignature, serverAuth, `DNS:localhost`) with one intermediate.
3. `s_server -tls1_3` without `-enable_server_rpk`, groups and suite as today, `-naccept 1`.
4. Client `certificateTypes: [x509]`. Stock certificate uses `trustedSpki` and `serverName` null. Chained certificate uses `trustAnchors` and `serverName: localhost`.
5. Assert `peerAuthenticated`, the suite, and `read finished` in server stderr.
6. Repeat for SecP256r1MLKEM768 and SecP384r1MLKEM1024.
7. Negative: same server, client still on the default raw offer. Handshake fails. No application data.

`s_client -CAfile` against our server, one group (X25519MLKEM768), identity from `mintLeaf` or `certificateDnsName`. Exit 0. Protocol line TLSv1.3.

### curl (required to close #43)

`curl -V` must show the same OpenSSL 3.5.9. Otherwise the script exits non-zero with `curl is not the OpenSSL 3.5.9 under test`.

`curl --cacert cert.pem --tls-max 1.3 --curves X25519MLKEM768 --http1.1 https://127.0.0.1:port/`. No `-k`. Assert the body. Our server speaks HTTP/1.1 on `PqTlsSocket` after the handshake.

### P-256 server against OpenSSL (required by this design, same PR)

Our server identity is `PqTlsServerIdentity.x509` with a P-256 leaf and a chain. `openssl s_client -tls1_3 -CAfile root.pem` completes. This is the classical CertificateVerify path. It is not a browser sentence.

### BoringSSL (no sentence unless it passes)

If `bssl` is on the path, one client run against our ML-DSA leaf and one against the P-256 leaf. Success: record the revision and add one sentence. Failure or a missing binary: the sentence stays "BoringSSL is not this fixture". Do not treat a reject as a parser bug until the alert is read.

### Browsers (no success sentence without a flight)

Do not write "works with browsers".

The opted-in server is what a browser has to be able to talk to. A flight, if one is recorded in the implementation PR, is a browser completing TLS 1.3 to `PqTlsSocket` with a private root the tester installed, leaf algorithm one that browser offered, no `-k` equivalent. Public WebPKI, the Chrome Root Store, and Merkle Tree Certificates are out of that sentence even if the flight passes.

Out of this issue even if D7 is widened: AIA fetch, OCSP, CT, the host trust store, IDNA, public-suffix wildcards, client certificates, `compress_certificate`, ECH.

## Implementation checklist

pqforge 0.4.8:

- [ ] `lib/src/certificates/x509.dart` matches the model above.
- [ ] `PqEcdsaP384`, `PqRsa`, `PqEd25519` exported. PointyCastle and `package:cryptography` stay implementation details.
- [ ] ADR-0003 copied from this contract.
- [ ] `dart analyze --fatal-infos`, `dart test`, including a dart2js run of `PqRsa.verifyPkcs1` and `PqEd25519.verify`. The ChaCha Poly1305 failure is why this row exists.
- [ ] pubspec version 0.4.8. No breaking change to existing exports.

pqtransport, after 0.4.8 is on pub.dev:

- [ ] ADR-0014 status set to Accepted, with the merge date.
- [ ] `pqforge: ^0.4.8`. No parser file in this repo. No `pointycastle` or `cryptography` dependency line.
- [ ] `lengths.dart` holds alerts 42/43/46, certificate type 0, chain cap 8. No new size literal in handshake code.
- [ ] Raw-pk `run.sh` still green. X.509 run green on three groups. curl green. P-256 `s_client` green.
- [ ] `peerAuthenticated` false paths have a socket test with no application bytes.
- [ ] FEATURES: X.509 row becomes **Done** only for what the tests cover (opt-in, chain cap 8, caller anchors, the algorithms that flew). AIA, OCSP, CT, system store, and MTC stay **Not started**.
- [ ] CLAIM_BOUNDARY and OPENSSL_INTEROP gain a sentence only for the flight that ran. Suggested shape, and only if true: "Handshake interop with OpenSSL 3.5.9 on the three RFC 10024 groups, auth mode X.509 ML-DSA-65, chain length 1 and 2, caller anchor or SPKI pin (date). curl `--cacert` against that server (date). Not BoringSSL. Not a browser. Not WebPKI."
- [ ] CHANGELOG under Unreleased. No FIPS 140 wording.
- [ ] `bash tool/check_invariants.sh .`, `dart analyze --fatal-infos`, `dart test`.
- [ ] #43 stays open until that pqtransport PR merges.

## Files the pqtransport implementation touches

| File | Change |
| --- | --- |
| `pubspec.yaml` | `pqforge: ^0.4.8` |
| `lib/src/tls/handshake.dart` | Certificate-type argument. Offer. No DER parser. |
| `lib/src/tls/pq_tls_client.dart` | Offer, anchors, pin, hook, clock, alert, verify order. |
| `lib/src/tls/pq_tls_server.dart` | Select type. Cache Certificate. `PqTlsServerIdentity.x509`. |
| `lib/src/tls/pq_tls_socket.dart` | Pass the new arguments. Do not default them to X.509. |
| `lib/src/core/lengths.dart` | Alerts 42/43/46, type 0, chain cap. |
| `lib/src/core/errors.dart` | Factories for the three alerts. |
| `lib/pqtransport.dart` | Export the enum and the hook. Re-export nothing from pqforge that pqforge did not already export. Callers who want `PqX509` import pqforge. |
| `test/tls/certificate_type_test.dart` | New. |
| `tool/interop/openssl/handshake.dart` | Add. Do not rewrite the raw-pk functions. |
| `tool/interop/openssl/openssl-x509.cnf` | Leaf and intermediate profile. |
| `doc/FEATURES.md`, `CLAIM_BOUNDARY.md`, `OPENSSL_INTEROP.md`, `TRACKER.md`, `CHANGELOG.md` | After the flight, not before. |
