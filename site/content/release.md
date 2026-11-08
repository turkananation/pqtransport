---
title: v0.2.0 Release
description: What pqtransport 0.2.0 adds, what it still does not do, and how the tag is cut.
---

0.2.0 is the first release that validates DNSSEC and that speaks the
groups a classical peer can force. 0.1.0 was the self-interop slice
plus the three RFC 10024 handshakes. Tag this from `main` after the
branch is merged. Do not tag the feature branch.

## What changed

- DNSSEC algorithms 5, 7, 8, 10, 13, 14, 15, and 16. RSA is PKCS#1
  v1.5 through pqforge, moduli 1024, 2048, 3072, and 4096. Ed25519
  and Ed448. Ed448 is RFC 8032 with an empty context.
- `DnsTrustAnchor.dsSet` holds more than one DS. The root publishes
  two KSKs.
- `authenticateDns` checks one name from an anchor you already have.
  `lookup` does not. The AD bit is not read.
- `DnsIterativeResolver` walks root hints you supply. Referrals, glue,
  qname minimization, CNAME, DNAME, NSEC, and NSEC3. NSEC3 is hash
  algorithm 1. Extra iterations default to 0. Answers are cached.
- `TlsNamedGroup` adds X25519 (`0x001D`), secp256r1 (`0x0017`),
  secp384r1 (`0x0018`), and ML-KEM-1024 (`0x0202`). The hybrid share
  stays first when the peer offered it.
- OpenSSL 3.5.9 and BoringSSL 0.20261020.0 on those groups, both
  directions. BoringSSL does not do the two NIST hybrid groups.
  One BoringSSL ECH flight (RFC 9849).
- X.509 is opt-in, chain of 1 to 8, caller anchors. The default offer
  is still a raw public key.
- Encrypted UDP loss recovery is RFC 9002. The handshake is a QUIC
  Initial padded to 1200 bytes.
- Examples: `example/dns_validate.dart` signs a zone in memory.
  `example/dns_live.dart` asks a resolver and checks `yardenah.com`
  from the IANA root DS set.

## What this is not

Not an authoritative DNS server. Not a recursive resolver that sets
the AD bit. Not WebPKI. Not a browser. Not `curl --http3`. Not QUIC
0-RTT. Not ML-KEM-512 or ML-KEM-768 as a standalone group. Not TLS
1.2. Not a FIPS 140 module.

## Dependency floor

`pqforge ^0.4.13`. `swissarmyknife ^0.1.0`. Dart `^3.12.0`.

## Tag

```bash
git checkout main
git pull
git tag -a v0.2.0 -m "pqtransport 0.2.0"
git push origin v0.2.0
```

The notes above are the release text. The long form is
[CHANGELOG.md](https://github.com/turkananation/pqtransport/blob/main/CHANGELOG.md).
