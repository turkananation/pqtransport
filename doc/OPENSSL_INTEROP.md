# OpenSSL / BoringSSL interop

Last updated: 2026-10-31

Handshake interop with OpenSSL 3.5.9 on X25519MLKEM768,
SecP256r1MLKEM768, and SecP384r1MLKEM1024 in
[`tool/interop/openssl`](../tool/interop/openssl). SecP384r1MLKEM1024
uses `PqForgeProfile.maximum`.

| Item | Value |
| --- | --- |
| Groups | X25519MLKEM768 (`0x11EC`), SecP256r1MLKEM768 (`0x11EB`), SecP384r1MLKEM1024 (`0x11ED`) |
| Suite | `TLS_AES_256_GCM_SHA384` (`0x1302`), SHA-384 |
| raw-pk | RFC 7250. `-enable_server_rpk` sends one ML-DSA-65 SubjectPublicKeyInfo. The raw-pk flight is not edited to make the X.509 flight pass. |
| X.509 client | `PqTlsClient` to `s_server`, no `-enable_server_rpk`. ML-DSA-65 leaf, chain length 1, that CA as the only anchor. DNS `localhost`. All three groups. |
| X.509 server | `openssl s_client -verify_return_error` against `PqTlsSocket`. ML-DSA-65 on all three groups, chain length 1, and chain length 2 on X25519MLKEM768 (leaf + intermediate, root is `-CAfile`). One P-256 leaf (`ecdsa_secp256r1_sha256`) on X25519MLKEM768. Certs are minted by pqforge. |
| Order | X25519: ML-KEM then X25519. P-256 and P-384: ECDHE then ML-KEM. |
| BoringSSL | 0.20261020.0. `X509_verify_cert` on the OpenSSL leaf and CA, and a TLS peer (`tool/interop/boringssl`). Hybrid: X25519MLKEM768, both directions, ML-DSA-65 chain length 1, one P-256 leaf, ML-DSA-65 raw public key. Fallback: X25519, secp256r1, secp384r1, and MLKEM1024, both directions, ML-DSA-65 chain length 1. Suite `0x1302`. Not SecP256r1MLKEM768. Not SecP384r1MLKEM1024. |
| Classical / pure | X25519 (`0x001D`), secp256r1 (`0x0017`), secp384r1 (`0x0018`), MLKEM1024 (`0x0202`). Both directions. ML-DSA-65 chain length 1. The default client offers the hybrid share and then X25519. `s_server -groups x25519:secp256r1` selects X25519 and does not retry. P-256-only, P-384-only, and MLKEM1024-only are HelloRetryRequest. Not MLKEM512. Not MLKEM768. Not TLS 1.2. |
| curl | Two HTTPS GETs, both X25519MLKEM768, `--cacert`, `--http1.1`, curl linked to this OpenSSL. One against `s_server`. One against `PqTlsSocket`. Not `curl --http3`. Not a browser. |
| Gate | `bash tool/interop/openssl/run.sh` |

WebPKI, the system trust store, and a live Chrome flight are not this fixture.

## Still forbidden

- "interoperable with OpenSSL" with no version, group, or auth mode
- "production-ready post-quantum TLS"
- any FIPS 140 module claim
- a group, suite, or auth mode that is not in the table above

## Concatenation

```text
X25519MLKEM768 ss     = ss_mlkem (32) || ss_x25519 (32)
SecP256r1MLKEM768 ss  = ss_ecdhe (32) || ss_mlkem (32)
SecP384r1MLKEM1024 ss = ss_ecdhe (48) || ss_mlkem (32)
```

OpenSSL 3.5 uses `ml_kem_slot` 0 for X25519MLKEM768 (ML-KEM first)
and `ml_kem_slot` 1 for SecP256r1MLKEM768 and SecP384r1MLKEM1024
(ECDHE first). The swapped X25519 order is a different secret. The
local test is
`swapped X25519MLKEM768 concatenation is not the peer order`.
An encapsulation key of 1183 bytes is `illegal_parameter`
(`encapsulation key truncated to 1183 bytes is illegal_parameter`).
A SHA-256-sized Finished on `0x1302` fails
(`a 0x1302 hello whose Hash is SHA-256 aborts`).

## What 0.1 could not do

0.1 sent a private record layout and a raw public key with no
CertificateEntry framing. That peer could not finish. The current
client sends RFC 8446 records (header as AEAD AAD), an RFC 8446
Certificate message carrying one RFC 7250 SPKI, and a CertificateVerify
with the signature scheme and the 64-byte context. OpenSSL splits
EncryptedExtensions, Certificate, CertificateVerify, and Finished
across records. The client keeps the peer key and reassembles a
handshake message that spans records. A change_cipher_spec record is
ignored.
