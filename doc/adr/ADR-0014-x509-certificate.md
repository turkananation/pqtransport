# ADR-0014: X.509 when RawPublicKey was not negotiated

| | |
| --- | --- |
| Status | **Proposed.** Merging the design PR approves this record. It does not implement it. |
| Date | 2026-10-27. Amended the 2026-10-25 text of this same ADR. |
| Issue | [OPEN-14 / #43](https://github.com/turkananation/pqtransport/issues/43) |
| Slice | 0.6.2, after pqforge 0.4.8 exports the certificate layer |
| Depends on | LIM-01 raw-pk flight stays as it is. Do not edit that flight to make this one pass. |

The 2026-10-25 text put the codec in pqtransport, rejected a chain, and
treated ECDSA, RSA, and Ed25519 as a caller hook. That text is withdrawn.
The hook was an escape hatch, not an implementation.

## Context

RFC 8446 §4.4.2: a Certificate entry is a DER X.509 certificate (RFC 5280)
unless the peers negotiate RFC 7250 `server_certificate_type = RawPublicKey`
(value 2). If the extension is absent, the type is X.509 (value 0).
Browsers, curl, and `openssl s_server` without `-enable_server_rpk` omit
the extension. They send a `certificate_list` of one or more certificates,
leaf first.

What the tree does today:

- `encodeCertificate` / `decodeCertificate` carry one ML-DSA SubjectPublicKeyInfo
  ([handshake.dart](../../lib/src/tls/handshake.dart)).
- EncryptedExtensions always sends RawPublicKey. A ClientHello that omits
  the extension is rejected. A ClientHello whose `signature_algorithms` omits
  ML-DSA-65 is rejected.
- `PqTlsClient` verifies CertificateVerify with `crypto.mlDsaVerify` over the
  raw key. There is no pin, no trust anchor, and no verify hook.
- The OpenSSL 3.5.9 fixture mints an ML-DSA-65 certificate and then discards
  it on the wire via `-enable_server_rpk`.
- Alerts are stored on `PqTransportError.alert`. No TLS Alert record is written
  on the current failure paths.

pqforge 0.4.7 is the right layer for the certificate and the wrong layer
for the handshake:

| Need | pqforge 0.4.7 | Where it goes |
| --- | --- | --- |
| ML-DSA-65/87 sign and verify, empty context, pure | `PqSignaturePrimitives` | Called by the new certificate type. `preHash: true` stays forbidden for certificates (RFC 9881). |
| ML-DSA-44 | Compact profile | The certificate type accepts it. pqtransport TLS rejects it. |
| P-256 ECDSA, raw `r\|\|s`, low-S, SHA-256 inside the signer | `PqEcdsaP256` | Called by the certificate type after DER `SEQUENCE { r, s }` is reduced. |
| P-384 ECDSA | P-384 ECDH only | New `PqEcdsaP384` beside `PqEcdsaP256`. Same PointyCastle dependency. No new package. |
| RSA PKCS#1 and RSA-PSS | Not wrapped. PointyCastle is already a pqforge dependency and is not re-exported | New `PqRsa` inside pqforge. pqtransport does not import `package:pointycastle`. |
| Ed25519 | Async `package:cryptography` on the hybrid signer | New sync RFC 8032 verify in pqforge. `PqX509` does not return a `Future`. |
| X.509 parse, mint, path check | None | New `lib/src/certificates/x509.dart`, exported from `package:pqforge/pqforge.dart`. |
| TLS Certificate message, alerts, `serverName`, `peerAuthenticated` | Out of scope for pqforge | Stay in pqtransport. |

RFC 9881 (October 2025) is the ML-DSA certificate profile: OIDs
`2.16.840.1.101.3.4.3.17` / `.18` / `.19`, parameters absent, raw key in
the BIT STRING, signature over the exact DER of `TBSCertificate`.

Trust, as of October 2026, is not the public web. CA/Browser Forum has
not adopted ML-DSA for publicly trusted TLS. Chrome 150 verifies RFC 9881
for a root the user added. The Chrome Root Store is not taking ML-DSA
X.509. Chrome's public post-quantum certificate plan is Merkle Tree
Certificates, which are a different message and out of scope. A browser
can complete a handshake to this stack only when the server identity is
opted into X.509, the leaf algorithm is one that browser offered, and
that browser already trusts the anchor. This ADR does not claim that
handshake has been run.

## Decision

1. **The certificate layer is a pqforge export. pqtransport consumes it.**
   - Source file: `lib/src/certificates/x509.dart`. The DER cursor and the
     per-algorithm verify functions sit in the same folder and are not
     exported.
   - `lib/pqforge.dart` exports that file. Callers, including projects that
     never import pqtransport, use `import 'package:pqforge/pqforge.dart'`.
   - The type parses one DER certificate, mints a self-signed TLS leaf,
     checks one signature, and validates a path against caller-supplied
     anchors. It does not open sockets, write TLS alerts, read the system
     trust store, or fetch AIA.
   - pqtransport does not grow `lib/src/tls/x509.dart`. It does not import
     `package:pointycastle` or `package:cryptography`.
   - Minimum version: **pqforge 0.4.8**. pqtransport's implementation PR
     bumps `pqforge: ^0.4.8`. No git pin.

2. **Selection stays opt-in. The default bytes do not change.**
   - Default client offer remains `[RawPublicKey]`. LIM-01 and the in-tree
     handshakes stay on today's ClientHello, including `signature_algorithms`
     of `0x0905` then `0x0906` only.
   - `certificateTypes: [x509]` is the browser, curl, and default-OpenSSL
     shape: omit `server_certificate_type`. Also accept an explicit list
     whose only element is `X509(0)`.
   - Offer `[x509, rawPublicKey]` sends the extension in that order.
   - An X.509 client offers the signature schemes pqforge 0.4.8 can verify
     (the table below) plus the two ML-DSA schemes. A raw-only client does
     not.
   - Absent extension on EncryptedExtensions means X.509 only if X.509 was
     acceptable. A raw-only client still fails closed on an absent extension.
   - Server with no certificate chain: today's RawPublicKey path, and it
     still requires ML-DSA-65 in `signature_algorithms`. A browser that
     omits the extension does not get a raw key. The handshake fails before
     ServerHello.
   - Server with a chain: select X.509 when the client offered it or omitted
     the extension. Send the chain, leaf first. Never send a raw key on that
     path. CertificateVerify uses the leaf algorithm, and only if the client
     offered that scheme. Do not require ML-DSA-65 when the leaf is not
     ML-DSA-65.

3. **A chain is a capped path, not a guess.** `certificate_list` length 0
   is `decode_error`. Length 1 through 8 is a path. Length above 8 is
   `unsupported_certificate` and no application data. The leaf is entry 0
   (RFC 8446). Unrecognized CertificateEntry extensions are ignored after
   a structural parse. Their presence is not OCSP, SCT, or AIA. AIA, OCSP,
   CT, and Merkle Tree Certificates stay out.

4. **Signature math lives in pqforge. All of these are in 0.4.8.**

   | Algorithm | Certificate OID | TLS scheme | Implementation |
   | --- | --- | --- | --- |
   | ML-DSA-65 | `2.16.840.1.101.3.4.3.18` | `0x0905` | existing primitive, empty context, `preHash` false |
   | ML-DSA-87 | `2.16.840.1.101.3.4.3.19` | `0x0906` | same |
   | ML-DSA-44 | `2.16.840.1.101.3.4.3.17` | none on this TLS path | verified by `PqX509` for other callers; pqtransport returns `unsupported_certificate` |
   | ECDSA P-256 / SHA-256 | `1.2.840.10045.4.3.2` | `0x0403` | `PqEcdsaP256` after DER `r\|\|s` decode. The signer hashes. Do not pre-hash. |
   | ECDSA P-384 / SHA-384 | `1.2.840.10045.4.3.3` | `0x0503` | new `PqEcdsaP384`, same contract, 48-byte integers |
   | Ed25519 | `1.3.101.112` | `0x0807` | new sync RFC 8032 verify. Pure, not HashEd25519. |
   | RSA PKCS#1 SHA-256/384/512 | `1.2.840.113549.1.1.11` / `.12` / `.13` | not used for CertificateVerify (RFC 8446 §4.4.3) | new `PqRsa.verifyPkcs1`. Legal on a certificate signature. Illegal on CertificateVerify. |
   | RSA-PSS SHA-256/384/512 | `1.2.840.113549.1.1.10` with matching parameters | `0x0804` / `0x0805` / `0x0806` | new `PqRsa.verifyPss`. Salt length equals the hash length. |

   An OID outside this table is `unsupportedAlgorithm` from pqforge and
   `unsupported_certificate` from pqtransport. It is not passed to a hook
   to be "verified" by omission. The hook is extra policy after a
   successful check. It is not the implementation of RSA.

5. **A valid signature is not authentication.** After `PqX509` reports a
   structural parse and a signature result:
   - `trustAnchors` non-empty: `PqX509.validate` must return trusted.
     Anchors are DER certificates the caller supplied. There is no system
     store and no `dart:io` lookup on the web barrel.
   - `trustAnchors` empty and `trustedSpki` set: exactly one certificate,
     self-signed, signature valid, leaf key equal to the pin. This is the
     OpenSSL stock-certificate flight.
   - Both set: path and pin. Either failure stops the handshake.
   - Neither set, hook or not: fail closed. Do not set `peerAuthenticated`.
   - Hook returns failure: `certificate_unknown`.
   - `allowUnauthenticated` stays default false, still skips identity
     checks, and still leaves `peerAuthenticated` false. The hook is not
     consulted when the flag is true.

6. **Names and extensions.** pqforge compares issuer and subject as DER.
   It decodes SAN, keyUsage, EKU, and basicConstraints into fields.
   pqtransport applies TLS policy: `digitalSignature` when keyUsage is
   present, `id-kp-serverAuth` when EKU is present, RFC 9525 SAN match
   when `serverName` is set, no CN fallback, wildcard only as the entire
   leftmost label, no public-suffix list. The parser does not fail a
   legal UTF-8 DirectoryString. pqtransport fails closed when `serverName`
   or a matched DNS SAN is not ASCII. v1 with no extensions parses. v2
   does not. Our minter writes v3 only.

7. **CertificateVerify stays RFC 8446 §4.4.3.** pqtransport builds the
   content (64 bytes of `0x20`, the context string, `0x00`, the transcript
   hash). pqforge checks that content under the leaf key. A bad certificate
   signature is `bad_certificate`. A bad CertificateVerify is `decrypt_error`.
   RSA PKCS#1 on CertificateVerify is `unsupported_certificate` even when
   the certificate signature was PKCS#1.

8. **Browser-shaped peers are an opted-in server identity, not the default.**
   A browser ClientHello omits `server_certificate_type` and lists only the
   schemes that browser implements. The server answers with X.509 only when
   its identity holds a chain and the leaf scheme was offered. The caller
   installs the anchor in the browser. This stack does not read the Chrome
   Root Store and does not mint a publicly trusted chain.

9. **New certificate failures write one fatal Alert** under the handshake
   traffic keys, then the `Result` failure. Older failure paths are not
   rewritten in this issue.

10. **Claims.** This ADR does not authorize a new interop sentence.
    [CLAIM_BOUNDARY.md](../CLAIM_BOUNDARY.md) changes only in the
    implementation PR, and only for a flight that PR actually ran.
    Forbidden until that flight is in the same PR: "works with browsers",
    a BoringSSL success sentence, WebPKI, MTC, and "interoperable with
    OpenSSL" with no version and auth mode.

## Alternatives rejected

| Alternative | Why not |
| --- | --- |
| Keep the codec in pqtransport and import PointyCastle for RSA | Splits the crypto story. PointyCastle is already a pqforge dependency and is not a pqtransport import. [ENGINEERING_GUIDE.md](../ENGINEERING_GUIDE.md). |
| Leave classical algorithms as a hook | The hook does not verify anything. Callers would reimplement RSA. |
| Keep sending RawPublicKey when the peer omitted the extension | That is the bug. Browsers, curl, and default OpenSSL will not negotiate it. |
| Change the default client offer to X.509 | Breaks LIM-01 and every current handshake. |
| Treat a self-signed certificate as authenticated | Anyone can mint one. |
| Put TLS alerts or `peerAuthenticated` in pqforge | pqforge does not own TLS. Applications own trust decisions. |
| Build AIA, OCSP, CT, or the system store | Out of scope. Anchors are bytes. |
| Merkle Tree Certificates | Not what OpenSSL `s_server` or a browser X.509 stack sends. |

## Consequences

- Two implementation PRs, in order. pqforge 0.4.8 first, including its own
  ADR-0003 that copies the decision in
  [OPEN-14-x509-certificate.md](../plans/OPEN-14-x509-certificate.md).
  Then pqtransport, which only calls the export.
- `decodeCertificate` grows a certificate-type argument. RawPublicKey keeps
  today's bytes.
- Server identities gain an optional chain. Empty means raw only, which is
  every identity constructed today.
- A client of a public website still needs the caller to supply the anchors.
  That is not WebPKI.

## Confirmation

Approved when this PR merges. Rejected if the maintainer asks for a
different row in the decision list of the plan. Do not start either
implementation branch from an unmerged revision.
