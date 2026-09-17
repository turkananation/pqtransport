This page is a pointer. The canonical claim boundary is
[doc/CLAIM_BOUNDARY.md](https://github.com/turkananation/pqtransport/blob/main/doc/CLAIM_BOUNDARY.md).

**Short version for 0.1.0**

- RFC 10024 length and concatenation tests: yes
- Live handshake against pqforge for all three RFC 10024 groups: yes
  (P-384 requires `PqForgeProfile.maximum`)
- RFC 8446-shaped ClientHello: no (roadmap 0.2, OPEN-01)
- OpenSSL interop: no (roadmap 0.4, blocked on OPEN-01 hellos)
- IANA `TLS_AES_256_GCM_SHA384` (0x1302): no (SHA-256 schedule, OPEN-02)
- FIPS 140 / CMVP module: no
- `dart:ffi` / platform `SecureSocket` on the PQ path: no
