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

## Workspace member, not an excluded folder

`site/` is a **separate Dart package** (`pqtransport_site`,
`publish_to: none`) in a pub **workspace**.

The root `pubspec.yaml` lists it:

```yaml
workspace:
  - site
```

`site/pubspec.yaml` sets `resolution: workspace`. One lockfile: the
repository-root `pubspec.lock`. There is no `site/pubspec.lock`.

This is the fix for the 201 CI analyzer errors. Those were not defects
in the Jaspr sources. Root `dart analyze` was resolving `site/lib`
against `package:pqtransport`, which does not depend on jaspr, so every
import looked missing.

Do **not**:

- `analyzer.exclude: site/**` (hides the package instead of analyzing it)
- add `jaspr` to the root `pubspec.yaml` (leaks a docs framework into
  every consumer)

Do:

```bash
dart pub get                          # workspace, both packages
dart analyze --fatal-infos . site     # type-checks lib/ and site/lib/
dart format --set-exit-if-changed lib test example site
```

[`tool/check_invariants.sh`](../tool/check_invariants.sh) fails if any
of the forbidden shortcuts come back.

## Source

| Path | Role |
|---|---|
| [`site/pubspec.yaml`](../site/pubspec.yaml) | Jaspr static app, `publish_to: none`, `resolution: workspace` |
| [`site/lib/main.server.dart`](../site/lib/main.server.dart) | `ContentApp` + `DocsLayout` + PQ theme |
| [`site/lib/components/site_header.dart`](../site/lib/components/site_header.dart) | Header, theme toggle, GitHub button |
| [`site/content/*.md`](../site/content/) | Pages |
| [`site/content/_data/site.yaml`](../site/content/_data/site.yaml) | `base: /pqtransport/` |
| [`site/web/images/`](../site/web/images/) | Logo, hybrid concat diagram, stack diagram |
| [`tool/fix_pages_base.py`](../tool/fix_pages_base.py) | Prefix TOC anchors with `/pqtransport/` |
| [`.github/workflows/pages.yml`](../.github/workflows/pages.yml) | `jaspr build` → Pages artifact → deploy |

## How it is published

GitHub Pages source is **GitHub Actions**
(Settings → Pages → Build and deployment → Source: GitHub Actions).

Branch / Jekyll deploy is not used.

The workflow:

1. `dart pub get` at the workspace root
2. `jaspr build --sitemap-domain https://turkananation.github.io/pqtransport` in `site/`
3. Rewrite root-absolute TOC hrefs for the project Pages base
4. `actions/upload-pages-artifact` of `site/build/jaspr`
5. `actions/deploy-pages`

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
dart pub get
cd site
dart format --set-exit-if-changed .
dart analyze --fatal-infos
dart pub global activate jaspr_cli
dart pub global run jaspr_cli:jaspr serve
# or
dart pub global run jaspr_cli:jaspr build \
  --sitemap-domain https://turkananation.github.io/pqtransport
python3 ../tool/fix_pages_base.py build/jaspr
```

Output: `site/build/jaspr`.
