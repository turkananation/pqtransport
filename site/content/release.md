---
title: v0.1.0 Release
description: Release posture, gates, and the Jaspr site build for pqtransport 0.1.0.
---

pqtransport 0.1.0 is the self-interop vertical slice **plus live NIST
groups** (pqforge 0.4.4). It is shipped in the tree and unpublished on
pub.dev until the owner cuts a release.

## Gates that must stay green

- `dart format`
- `dart analyze --fatal-infos`
- `bash tool/check_invariants.sh .` (no `dart:ffi`, no stray sizes, claim language)
- `dart test` — 153 passed
- Line coverage of `lib/` — 90.7%
- This Jaspr site build (`cd site && jaspr build`)

## What 0.1.0 actually shipped

Live RFC 10024 handshake for all three groups, RFC 10024 codecs,
encrypted UDP with replay-before-AEAD, DNS wire + breaker + cache,
mDNS probe/announce/browse, HTTP/1.1 over `PqTlsSocket`, QUIC 1-RTT
sketch. IANA `0x1302` (SHA-384 AES-GCM) default and `0x1303` (ChaCha)
offered. `requireGroup` refuses profile/group mismatch. Evidence:
[`doc/ACHIEVEMENTS.md`](https://github.com/turkananation/pqtransport/blob/main/doc/ACHIEVEMENTS.md).

## Tag

```bash
git tag -a v0.1.0 -m "pqtransport v0.1.0"
git push origin v0.1.0
```

## Site

```bash
cd site
dart pub get
dart pub global activate jaspr_cli
dart pub global run jaspr_cli:jaspr build --sitemap-domain https://turkananation.github.io/pqtransport
```

GitHub Pages deploys `site/build/jaspr` from `.github/workflows/pages.yml`.
