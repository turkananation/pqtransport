# Site

Last updated: 2026-09-17

The public site is a **Jaspr** static build, the same architecture as
[`swissarmyknife`](https://turkananation.github.io/swissarmyknife/), with
the PQ/hybrid visual language of
[`pqcrypto`](https://turkananation.github.io/pqcrypto/) and
[`pqforge`](https://turkananation.github.io/pqforge/).

Live URL:
[https://turkananation.github.io/pqtransport/](https://turkananation.github.io/pqtransport/).

## Why Jaspr

swissarmyknife keeps the documentation language the same as the package
language: Dart. pqtransport does the same. The site is not a JS theme
wrapped around markdown and it is not Jekyll. It is `jaspr` `^0.23.4` +
`jaspr_content` `^0.5.4` + `jaspr_router` `^0.9.0` in static mode.

## Source

| Path | Role |
|---|---|
| [`site/pubspec.yaml`](../site/pubspec.yaml) | Jaspr static app, `publish_to: none` |
| [`site/lib/main.server.dart`](../site/lib/main.server.dart) | `ContentApp` + `DocsLayout` + PQ theme |
| [`site/lib/components/site_header.dart`](../site/lib/components/site_header.dart) | Header, theme toggle, GitHub button |
| [`site/content/*.md`](../site/content/) | Pages |
| [`site/content/_data/site.yaml`](../site/content/_data/site.yaml) | `base: /pqtransport/` |
| [`site/web/images/`](../site/web/images/) | Logo, hybrid concat diagram, stack diagram |
| [`tool/fix_pages_base.py`](../tool/fix_pages_base.py) | Prefix TOC anchors with `/pqtransport/` |
| [`.github/workflows/pages.yml`](../.github/workflows/pages.yml) | `jaspr build` → Pages artifact → deploy |

## How it is published

GitHub Pages **must** use **GitHub Actions** as the source
(Settings → Pages → Build and deployment → Source: GitHub Actions).

Branch / Jekyll deploy is not used. There is no root `index.html`
snapshot and no `_config.yml`.

The workflow:

1. `dart pub get` in `site/`
2. `jaspr build --sitemap-domain https://turkananation.github.io/pqtransport`
3. Rewrite root-absolute TOC hrefs for the project Pages base
4. `actions/upload-pages-artifact` of `site/build/jaspr`
5. `actions/deploy-pages`

If Pages source is still “Deploy from a branch”, GitHub will keep
serving a Jekyll README and `deploy-pages` will fail. That is
intentional.

## Pages

Overview, Getting Started, Architecture, Hybrid Groups, Protocols, API,
Cookbook, Platform, Features, Claim Boundary, Bugs, Roadmap, Release,
Sister packages.

## Theme

Ink field `#070d14`, phosphor lattice `#b6f25c`, cyan wire `#4ee0d4`,
classical gold `#f5c35b`. Light + dark via Jaspr `ContentTheme` /
`ThemeToggle`.

## Build locally

```bash
cd site
dart pub get
dart pub global activate jaspr_cli
dart pub global run jaspr_cli:jaspr serve
# or
dart pub global run jaspr_cli:jaspr build \
  --sitemap-domain https://turkananation.github.io/pqtransport
python3 ../tool/fix_pages_base.py build/jaspr
```

Output: `site/build/jaspr`.
