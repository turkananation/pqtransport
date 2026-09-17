---
name: Documentation
about: Claim-boundary, architecture, tracker, or README fix.
title: "docs: "
labels: "documentation"
assignees: ""
---

## Page

Path under `doc/` or `README.md`.

## Problem

Inaccuracy, missing cross-link, or wording that drifts toward a forbidden claim.

Forbidden contiguous phrases (must not appear in `*.md` / `*.dart`):

- module-validation wording that reads as a FIPS/CMVP listing
- hard constant-time execution claims
- hard memory-erasure claims

See `doc/CLAIM_BOUNDARY.md` and `tool/check_invariants.sh`.

## Suggested wording
