# pqtransport site

Jaspr static documentation site for [`package:pqtransport`](https://github.com/turkananation/pqtransport).
Mirrors [swissarmyknife](https://turkananation.github.io/swissarmyknife/)
(pure Dart, `jaspr` + `jaspr_content`) with the PQ/hybrid theme of
[pqcrypto](https://turkananation.github.io/pqcrypto/) and
[pqforge](https://turkananation.github.io/pqforge/).

## Stack

- [jaspr](https://pub.dev/packages/jaspr) `^0.23.4` (static mode)
- [jaspr_content](https://pub.dev/packages/jaspr_content) `^0.5.4`
- [jaspr_router](https://pub.dev/packages/jaspr_router) `^0.9.0`
- Dart SDK `^3.12.0`

## Develop

```bash
cd site
dart pub get
dart pub global activate jaspr_cli
dart pub global run jaspr_cli:jaspr serve
```

## Build (GitHub Pages)

```bash
dart pub global run jaspr_cli:jaspr build \
  --sitemap-domain https://turkananation.github.io/pqtransport
```

Output: `site/build/jaspr`. Base path is `/pqtransport/`
(`content/_data/site.yaml`).
