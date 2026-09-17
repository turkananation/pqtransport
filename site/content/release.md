---
title: v0.1.0 Release
description: Release posture, gates, and the Jaspr site build for pqtransport 0.1.0.
---

pqtransport 0.1.0 is the self-interop vertical slice. It is shipped in
the tree and unpublished on pub.dev until the owner cuts a release.

## Gates that must stay green

- `dart format`
- `dart analyze --fatal-infos`
- `bash tool/check_invariants.sh .` (no `dart:ffi`, no stray sizes, claim language)
- `dart test` — 93 passed
- Line coverage of `lib/` — 90.5%
- This Jaspr site build (`cd site && jaspr build`)

## What 0.1.0 actually shipped

Live X25519MLKEM768 handshake, RFC 10024 codecs for three groups,
encrypted UDP with replay-before-AEAD, DNS wire + breaker + cache,
mDNS probe/announce/browse, HTTP/1.1 over `PqTlsSocket`, QUIC 1-RTT
sketch. Evidence:
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
