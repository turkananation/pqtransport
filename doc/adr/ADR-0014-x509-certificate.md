# ADR-0014: X.509 when RawPublicKey was not negotiated

| | |
| --- | --- |
| Status | **Proposed.** Merging the design PR approves this record. It does not implement it. |
| Date | 2026-10-25 |
| Issue | [OPEN-14 / #43](https://github.com/turkananation/pqtransport/issues/43) |
| Slice | 0.6.2 (after 0.6.1 loss recovery, which is Done) |
| Depends on | LIM-01 raw-pk flight stays as it is. Do not edit that flight to make this one pass. |

## Context

RFC 8446 §4.4.2: a Certificate entry is a DER X.509 certificate (RFC 5280)
unless the peers negotiate RFC 7250 `server_certificate_type = RawPublicKey` (value 2).
If the extension is absent, the type is X.509 (value 0). Browsers, curl, and
`openssl s_server` without `-enable_server_rpk` send X.509.

What the tree does today:

- `encodeCertificate` / `decodeCertificate` carry one ML-DSA SubjectPublicKeyInfo
  ([handshake.dart](../../lib/src/tls/handshake.dart) `encodeCertificate`).
- EncryptedExtensions always sends RawPublicKey, and a ClientHello that omits
  it is rejected (`missing certificate_type (raw-pk must be explicit, OPEN-04)`).
- `PqTlsClient` verifies CertificateVerify with `crypto.mlDsaVerify` over the
  raw key. `allowUnauthenticated` defaults false and leaves `peerAuthenticated`
  false. There is no pin and no verify hook. A self-signed mathematical check
  is not a separate step because the raw key *is* the peer identity the
  signature is checked under, and the in-tree peers share that key out of band
  only in tests. The OpenSSL raw-pk flight checks the peer signature against
  the SPKI OpenSSL derived from the same ML-DSA key; it does not pin.
- The OpenSSL 3.5.9 fixture already mints an ML-DSA-65 X.509 certificate and
  then discards it on the wire via `-enable_server_rpk`
  ([tool/interop/openssl/handshake.dart](../../tool/interop/openssl/handshake.dart)).
- Alerts are stored on `PqTransportError.alert`. No TLS Alert record is written.

pqforge 0.4.7 (the floor in `pubspec.yaml`) is the wrong layer for this:

| Need | pqforge 0.4.7 | Decision |
| --- | --- | --- |
| ML-DSA-65/87 sign and verify, empty context, `preHash: false` | `PqSignaturePrimitives` via `PqTransportCrypto.mlDsaSign` / `mlDsaVerify` | Call. Do not reimplement. |
| ML-DSA-44 | `PqSignatureAlgorithm.mlDsa44` on the compact profile | Not a TLS identity here. Reject the OID. |
| HashML-DSA (`preHash: true`) | Supported on the primitive | Forbidden for certificates. RFC 9881 signs the DER `TBSCertificate` with pure ML-DSA. |
| P-256 ECDSA verify, raw `r\|\|s`, low-S | `PqEcdsaP256` | Do not call on this issue. Classical certificates go through the hook. |
| P-384 ECDSA, RSA-PSS, RSA PKCS#1 | Not exported | Do not vendor. A pqforge export would be a later ID if we ever verify those inside the library. |
| Ed25519 verify | `package:cryptography` behind the hybrid signer, async | Not a certificate API. Hook only. |
| X.509, Name, extensions, path building | None | Build the codec here. [PQFORGE_EXPORTS.md](../PQFORGE_EXPORTS.md) already refuses to ask pqforge for TLS codecs. |
| ASN.1 tree parser (PointyCastle) | Transitive, not our import | Do not import `package:pointycastle`. A cursor over the existing `ByteReader` is the parser. |

RFC 9881 (October 2025) is the ML-DSA certificate profile:

- OIDs `2.16.840.1.101.3.4.3.17` / `.18` / `.19` (ML-DSA-44/65/87). The 65 and 87
  encodings are already what `encodeMlDsa65Spki` emits (last byte `0x12` / `0x13`).
- `AlgorithmIdentifier.parameters` MUST be absent. NULL is not absent.
- `subjectPublicKey` is the raw public key in a BIT STRING. No second ASN.1 wrapper.
- `signatureValue` is the raw ML-DSA signature over the exact DER of `TBSCertificate`.
  Context string empty. Do not re-encode TBS and verify that.

Trust, as of October 2026, is not "the public web":

- CA/Browser Forum has not adopted ML-DSA for publicly trusted TLS.
- Chrome 150 verifies RFC 9881 for **user-added** roots (private PKI). The Chrome
  Root Store is not taking ML-DSA X.509. Chrome's public post-quantum certificate
  plan is Merkle Tree Certificates, which are a different message and out of scope.
- BoringSSL contains ML-DSA and MTC work. That is not evidence this stack has
  completed a BoringSSL handshake.

## Decision

1. **Selection follows negotiation, not a guess.**
   - Client offer `[RawPublicKey]` only: today's bytes. Default stays this,
     so the LIM-01 flight and the in-tree handshakes do not change.
   - Client offer `[X509]` only: omit `server_certificate_type` (the shape
     curl, browsers, and default OpenSSL use). Also accept an explicit list
     whose only element is `X509(0)`.
   - Client offer `[X509, RawPublicKey]`: send the extension in that order.
   - Absent extension on EncryptedExtensions means X.509 **only if** X.509 was
     acceptable. If the client offered only RawPublicKey, an absent extension
     fails closed.
   - Server: RawPublicKey was selected → current SPKI payload. It was not →
     one X.509 certificate. Never send a raw key on the X.509 path, and never
     send a certificate on the raw path.
   - Server preference when the client allows both: X.509 if the identity has
     `certificateDer` or `certificateDnsName`; otherwise RawPublicKey if the
     client offered it; otherwise fail before any ServerHello.

2. **One certificate, not a path.** Decode `certificate_list`. Zero entries
   is `decode_error`. More than one is `unsupported_certificate` and no
   application data. Chain building stays **Not started** in FEATURES.
   Unrecognized CertificateEntry extensions are ignored after a structural
   parse (RFC 8446). Their presence is not OCSP, SCT, or AIA.

3. **ML-DSA X.509 is verified here. Classical X.509 is a hook or a failure.**
   - 65 and 87 only. 44 is `unsupported`, not delegated to the hook.
   - Any other public-key algorithm is classical-or-unknown. With no hook:
     `unsupported_certificate`. With a hook: the hook is the verifier. This
     library does not check that signature.
   - `allowUnauthenticated` stays default false, still skips identity checks,
     and still leaves `peerAuthenticated` false. A hook is not consulted when
     the flag is true. The flag is not a substitute for the hook.

4. **A valid self-signature is not authentication.** After the certificate
   parses and (for ML-DSA) the self-signature verifies:
   - `trustedSpki` set: constant-time match against the certificate key.
     Mismatch is `bad_certificate`.
   - `trustedSpki` unset and hook unset: fail closed. Do not set
     `peerAuthenticated`.
   - Hook returns failure: `certificate_unknown`. No application data.
   - Both pin and hook: pin first, then hook. Either failure stops the
     handshake.

5. **Name and extension policy matches what peers actually send.**
   - Issuer and subject compared as DER, not as strings. Self-signed ML-DSA
     verification requires those two slices to be equal.
   - v1 (version omitted) is legal when it has no extensions. That is what
     `openssl req -new -x509` emits with the current
     [openssl.cnf](../../tool/interop/openssl/openssl.cnf). v1 with extensions
     is illegal. v2 is illegal. v3 is `[0] EXPLICIT INTEGER 2`.
   - Extensions that are absent are not invented. `keyUsage` or
     `extKeyUsage`, when present, must allow a TLS server
     (`digitalSignature`, and `id-kp-serverAuth` if EKU is present).
     An unknown **critical** extension fails. A duplicate OID fails.
   - If the caller set `serverName` and a SAN is present, match the SAN
     (DNS or IP) and ignore CN. Wildcard only as the entire leftmost label.
     No public-suffix list. Non-ASCII names fail closed.
   - If the caller set `serverName` and there is no SAN, fail closed.
     CN matching is not the default (RFC 9525). The OpenSSL flight pins the
     SPKI and does not set `serverName`, so the extension-less certificate
     still verifies.
   - Our own emitter never writes that extension-less certificate. It writes
     a v3 leaf: `basicConstraints` CA false, `keyUsage` digitalSignature
     critical, `extKeyUsage` serverAuth, `subjectAltName` from
     `certificateDnsName`, validity from an injected clock, serial at most
     20 octets. Signature through `PqTransportCrypto.mlDsaSign` over the
     exact TBS bytes, empty context, `preHash` left false.

6. **CertificateVerify stays RFC 8446 §4.4.3.** The transcript includes the
   Certificate message. The scheme must match the key (0x0905 or 0x0906).
   A bad CertificateVerify is `decrypt_error`. A bad certificate signature
   is `bad_certificate`. Those are different failures and different tests.
   Classical schemes are decoded only when a hook is installed and the
   client offered that scheme. Otherwise they are `unsupported`.

7. **New certificate failures write one fatal Alert** under the handshake
   traffic keys, then the `Result` failure. Older failure paths are not
   rewritten in this issue.

8. **Claims.** This ADR does not authorize a new interop sentence.
   [CLAIM_BOUNDARY.md](../CLAIM_BOUNDARY.md) changes only in the
   implementation PR, and only to the flight that PR actually ran.
   Forbidden until that flight is in the same PR: "works with browsers",
   "interoperable with OpenSSL" with no version and auth mode, any
   BoringSSL success sentence, WebPKI, MTC.

## Alternatives rejected

| Alternative | Why not |
| --- | --- |
| Keep sending RawPublicKey when the peer omitted the extension | That is the bug. Default OpenSSL, curl, and browsers will not negotiate it. |
| Change the default client offer to X.509 | Breaks LIM-01 and every current handshake. Opt-in preserves the recorded raw-pk flight. |
| Treat a self-signed ML-DSA certificate as authenticated | Anyone can mint one. `allowUnauthenticated` already exists for the explicit skip. |
| Verify ECDSA/RSA inside pqtransport with PointyCastle | Splits the crypto story. The issue allows classical certificates only behind a caller hook. P-384 ECDSA and RSA are not pqforge exports. |
| Ask pqforge for an X.509 type | Protocol layer. Same rule as ClientHello. |
| Build RFC 5280 paths, AIA, OCSP, CT, the system store | Out of scope for #43. FEATURES stays Not started for chain building. `dart:io` trust-store calls are forbidden on the web barrel. |
| Merkle Tree Certificates | Different design, not what OpenSSL `s_server` sends, not this issue. |
| Accept ML-DSA-44 on the TLS path | Identity, SPKI, and CertificateVerify in this package are 65 and 87. |

## Consequences

- Implementation is a follow-up PR. The acceptance list in
  [OPEN-14-x509-certificate.md](../plans/OPEN-14-x509-certificate.md) is the
  contract for that PR.
- `decodeCertificate` grows a certificate-type argument. Callers that want
  today's bytes pass RawPublicKey.
- Server identities gain an optional DER certificate and an optional DNS
  name. Both empty means "raw only", which is every identity constructed
  today.
- A client of a public website still cannot authenticate it. That is a
  later issue (chain building plus a caller-supplied trust anchor), not a
  silent expansion of this one.

## Confirmation

Approved when this PR merges. Rejected if the maintainer asks for a
different row in the decision list of the plan. Do not start the
implementation branch from an unmerged revision.
