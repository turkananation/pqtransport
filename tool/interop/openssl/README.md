# OpenSSL 3.5 — RFC 10024 hybrid handshakes

One live TLS 1.3 flight per group against OpenSSL `s_server`, then
`s_client` and curl against `PqTlsSocket`. The peer is a process.
There is no `dart:ffi` and no checked-in transcript.

## What is claimed

Handshake interop with OpenSSL 3.5.9 on X25519MLKEM768,
SecP256r1MLKEM768, and SecP384r1MLKEM1024. raw-pk and X.509.
SecP384r1MLKEM1024 uses `PqForgeProfile.maximum`.
BoringSSL verifies the OpenSSL leaf. curl does two GETs. Not a browser.

| Item | Value |
| --- | --- |
| Peer | OpenSSL 3.5.9 (or any 3.5+ the script builds) |
| Groups | `X25519MLKEM768` (`0x11EC`), `SecP256r1MLKEM768` (`0x11EB`), `SecP384r1MLKEM1024` (`0x11ED`) |
| Order | X25519 is ML-KEM then classical (`ml_kem_slot` 0). P-256 and P-384 are classical then ML-KEM (`ml_kem_slot` 1). |
| Suite | `TLS_AES_256_GCM_SHA384` (`0x1302`), HKDF-SHA-384 |
| Auth, raw-pk | RFC 7250. `-enable_server_rpk` sends one ML-DSA-65 SubjectPublicKeyInfo. This flight is not edited for X.509. |
| Auth, X.509 client | `PqTlsClient` to `s_server`. ML-DSA-65 leaf, chain length 1, caller CA. DNS `localhost`. |
| Auth, X.509 server | `s_client -verify_return_error` against `PqTlsSocket`. ML-DSA-65, chain length 1 on all three groups, chain length 2 on X25519MLKEM768, one P-256 leaf on X25519MLKEM768. |
| BoringSSL | This script: 0.20261020.0 `X509_verify_cert` on the leaf OpenSSL minted. The TLS peer is `tool/interop/boringssl`. |
| Classical / pure | X25519, secp256r1, secp384r1, and MLKEM1024, both directions, ML-DSA-65 chain length 1. Hybrid stays first. `x25519:secp256r1` finishes on X25519. The other three are HelloRetryRequest. Not MLKEM512. Not MLKEM768. Not TLS 1.2. |
| curl | Two HTTPS GETs on X25519MLKEM768 with `--cacert` and `--http1.1`. One against `s_server`, one against `PqTlsSocket`. Not a browser. Not `curl --http3`. |
| Finished | Each raw-pk and X.509 client group: OpenSSL logs `read finished` and `peerAuthenticated` is true. Each server group: `s_client` exits 0 and prints `Verify return code: 0`. |

## Wire this fixture requires

RFC 8446 Certificate is a request context, then one CertificateEntry:
a 3-byte length, the RFC 7250 SubjectPublicKeyInfo, and extensions.
CertificateVerify is `signature_scheme` (`0x0905` ML-DSA-65 or
`0x0906` ML-DSA-87) plus the signature over the 64-byte `0x20` prefix,
the context string `TLS 1.3, server CertificateVerify`, a `0x00`
separator, and the transcript hash. Records use the 5-byte header as
AEAD additional data. A change_cipher_spec record is ignored and does
not advance the sequence number. Handshake messages may occupy one
record each; the peer public key is kept until CertificateVerify.

Shared secret order matches OpenSSL 3.5. X25519MLKEM768 is ML-KEM
then X25519 (`ml_kem_slot` 0). SecP256r1MLKEM768 and
SecP384r1MLKEM1024 are ECDHE then ML-KEM (`ml_kem_slot` 1). The
swapped X25519 order is a different 64 bytes and is rejected by
`swapped X25519MLKEM768 concatenation is not the peer order` in
`test/core/hybrid_share_test.dart`. An encapsulation key of 1183
bytes (one short of 1184) is `illegal_parameter` in
`test/tls/handshake_test.dart`. A Finished sized for SHA-256 is
refused on the `0x1302` SHA-384 schedule in
`test/tls/cipher_suite_test.dart`.

## Run

From the repository root:

```bash
bash tool/interop/openssl/run.sh
```

`OPENSSL_BIN` may point at an existing OpenSSL 3.5+ binary. Otherwise
`build.sh` downloads OpenSSL 3.5.9, configures it with an rpath to its
own `lib/`, and installs into `.build/` (gitignored). The system
OpenSSL 3.0 is not this peer.
