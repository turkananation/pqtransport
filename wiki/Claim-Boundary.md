This page is a pointer. The canonical claim boundary is
[doc/CLAIM_BOUNDARY.md](https://github.com/turkananation/pqtransport/blob/main/doc/CLAIM_BOUNDARY.md).

**Short version for 0.1.0**

- RFC 10024 length and concatenation tests: yes
- Live X25519MLKEM768 handshake against pqforge: yes
- RFC 8446-shaped ClientHello: no (roadmap 0.2)
- OpenSSL interop: no (roadmap 0.4)
- IANA `TLS_AES_256_GCM_SHA384` (0x1302): no (SHA-256 schedule)
- FIPS 140 / CMVP module: no
- `dart:ffi` / platform `SecureSocket` on the PQ path: no
