This page is a pointer. The canonical claim boundary is
[doc/CLAIM_BOUNDARY.md](https://github.com/turkananation/pqtransport/blob/main/doc/CLAIM_BOUNDARY.md).

**Short version for 0.1.0**

- RFC 10024 length and concatenation tests: yes
- Live handshake against pqforge for all three RFC 10024 groups: yes
  (P-384 requires `PqForgeProfile.maximum`)
- RFC 8446-shaped ClientHello: yes (OPEN-01). Certificate still raw (OPEN-04)
- IANA `TLS_AES_256_GCM_SHA384` (0x1302): yes (SHA-384 schedule, OPEN-02 Fixed)
- IANA `TLS_CHACHA20_POLY1305_SHA256` (0x1303): yes (OPEN-13 Fixed; dart2js via pqforge 0.4.5)
- Handshake interop with OpenSSL 3.5.9 on X25519MLKEM768, SecP256r1MLKEM768, and SecP384r1MLKEM1024. raw-pk (2026-10-20) and X.509 both directions (2026-11-01): `s_server` and `s_client` against `PqTlsSocket`. The same peers also finish X25519, secp256r1, secp384r1, and MLKEM1024, both directions, ML-DSA-65 chain length 1. Hybrid stays first. BoringSSL 0.20261020.0 is a TLS peer on X25519MLKEM768 and those four groups. Not SecP256r1MLKEM768 or SecP384r1MLKEM1024. Not MLKEM512. Not MLKEM768. Not a browser. Not WebPKI.
- FIPS 140 / CMVP module: no
- `dart:ffi` / platform `SecureSocket` on the PQ path: no
