# OpenSSL 3.5 — RFC 10024 hybrid handshakes

One live TLS 1.3 flight per group against OpenSSL `s_server`. The peer
is a process. There is no `dart:ffi` and no checked-in transcript: each
run generates an ML-DSA-65 key, starts `s_server`, and finishes the
handshake or the script exits non-zero.

## What is claimed

Handshake interop with OpenSSL 3.5.9 on X25519MLKEM768,
SecP256r1MLKEM768, and SecP384r1MLKEM1024 in this directory
(2026-10-20, auth mode raw-pk). SecP384r1MLKEM1024 uses
`PqForgeProfile.maximum`.

Nothing wider.

| Item | Value |
| --- | --- |
| Peer | OpenSSL 3.5.9 (or any 3.5+ the script builds) |
| Groups | `X25519MLKEM768` (`0x11EC`), `SecP256r1MLKEM768` (`0x11EB`), `SecP384r1MLKEM1024` (`0x11ED`) |
| Order | X25519 is ML-KEM then classical (`ml_kem_slot` 0). P-256 and P-384 are classical then ML-KEM (`ml_kem_slot` 1). |
| Suite | `TLS_AES_256_GCM_SHA384` (`0x1302`), HKDF-SHA-384 |
| Auth | RFC 7250 raw public key. `-enable_server_rpk` sends the ML-DSA-65 SubjectPublicKeyInfo. The X.509 certificate exists only so OpenSSL will load the key. This library does not parse or validate an X.509 path. |
| Finished | Each group: OpenSSL must log `read finished`. `peerAuthenticated` must be true. |

Not claimed: X.509 path validation, BoringSSL, `curl --http3`, or a
FIPS 140 module.

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
