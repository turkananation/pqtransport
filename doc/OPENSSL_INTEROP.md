# OpenSSL / BoringSSL interop

Last updated: 2026-10-17

**Status: one fixture is green. Do not widen it.**

Handshake interop with OpenSSL 3.5.9 on the X25519MLKEM768 fixture in
[`tool/interop/openssl`](../tool/interop/openssl) (2026-10-17, auth mode
raw-pk).

| Item | Value |
| --- | --- |
| Group | X25519MLKEM768 (`0x11EC`) only |
| Suite | `TLS_AES_256_GCM_SHA384` (`0x1302`), SHA-384 |
| Auth | RFC 7250 raw public key (ML-DSA-65 SPKI). Not an X.509 path. |
| Peer | `openssl s_server -enable_server_rpk`, process, no `dart:ffi` |
| Gate | `bash tool/interop/openssl/run.sh` fails if Finished is not accepted |

BoringSSL is not this fixture. SecP256r1MLKEM768 and SecP384r1MLKEM1024
are not in this fixture. X.509 certificate chains are not parsed.

## Still forbidden

- "interoperable with OpenSSL" with no version, group, or auth mode
- "production-ready post-quantum TLS"
- any FIPS 140 module claim
- "all RFC 10024 groups" against this peer

## Concatenation

```text
X25519MLKEM768 ss     = ss_mlkem (32) || ss_x25519 (32)
SecP256r1MLKEM768 ss  = ss_ecdhe (32) || ss_mlkem (32)
SecP384r1MLKEM1024 ss = ss_ecdhe (48) || ss_mlkem (32)
```

OpenSSL 3.5 uses the same X25519MLKEM768 order (`ml_kem_slot` 0).
The swapped order is a different secret. The local test is
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
