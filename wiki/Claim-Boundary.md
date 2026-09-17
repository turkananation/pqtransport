This page is a pointer. The canonical claim boundary is
[doc/CLAIM_BOUNDARY.md](https://github.com/turkananation/pqtransport/blob/main/doc/CLAIM_BOUNDARY.md).

**Short version for 0.1.0**

- RFC 10024 length and concatenation tests: yes
- Live handshake against pqforge for all three RFC 10024 groups: yes
  (P-384 requires `PqForgeProfile.maximum`)
- RFC 8446-shaped ClientHello: yes (OPEN-01). Certificate still raw (OPEN-04)
- OpenSSL interop: no (roadmap 0.4)
- IANA `TLS_AES_256_GCM_SHA384` (0x1302): no (SHA-256 schedule, OPEN-02)
- FIPS 140 / CMVP module: no
- `dart:ffi` / platform `SecureSocket` on the PQ path: no
