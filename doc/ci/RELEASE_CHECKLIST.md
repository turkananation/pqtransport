# Release Checklist

Same loop as pqforge: one `v<version>` tag drives GitHub Release **and**
pub.dev. pqtransport is a library — there are no AOT CLI binaries.

- [ ] Update version in `pubspec.yaml`.
- [ ] Update `CHANGELOG.md`.
- [ ] Check README and `/doc` claim wording ([CLAIM_BOUNDARY.md](../CLAIM_BOUNDARY.md)).
- [ ] Confirm the release commit is the exact commit intended for publication.
- [ ] Confirm `main` CI is green on that commit.
- [ ] Confirm automated publishing is enabled on
      [pub.dev/packages/pqtransport/admin](https://pub.dev/packages/pqtransport/admin):
      - GitHub repository `turkananation/pqtransport`
      - tag pattern `v{{version}}`
      - publishing from **push** events (tag push)
      - GitHub Actions environment **`pub.dev`** (this is an environment
        *name*, not the workflow filename `publish.yml`)
      - matching GitHub Environment created at
        Settings → Environments → `pub.dev`
- [ ] Tag the release commit `v<version>` and push the tag. That single tag
      drives both:
      - `.github/workflows/publish.yml` — `dart pub publish` via GitHub Actions
        OIDC (no long-lived pub token). The job uses `environment: pub.dev`.
      - `.github/workflows/release.yml` — format / analyze / invariants / tests
        / dry-run, then create the GitHub Release.
- [ ] Confirm the publish and release workflow runs succeeded, then verify the
      pub.dev version and the GitHub release notes.
      GitHub Pages and wiki sync only from `main`/`develop`, so site/wiki
      updates go live after those merges.

## First version (package not yet on pub.dev)

pub.dev automated publishing only works **after** the package exists.
`0.1.0` is a one-time manual `dart pub publish` from a maintainer machine
that is logged into pub.dev. Then enable GitHub Actions publishing on the
admin page above. From the next tag onward, the workflow is the publisher.

Do not also run `dart pub publish` by hand for a tagged release once OIDC is
enabled. Manual publish remains a fallback if OIDC is not yet enabled.
`workflow_dispatch` on `publish.yml` is a second fallback (for example when
an existing tag will not re-fire `push`).

## GitHub immutable releases

If the repository has **immutable releases** enabled, never publish an empty
GitHub Release and attach files later — the tag name is burned if you delete
that release. pqtransport currently attaches no binaries, so creating the
release in one shot (this workflow) is enough. Keep immutability off unless
you are willing to draft-first for every future asset.
