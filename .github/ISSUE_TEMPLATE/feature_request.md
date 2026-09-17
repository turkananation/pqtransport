---
name: Feature request
about: Propose a protocol slice or API change.
title: "feat: "
labels: "enhancement"
assignees: ""
---

## Problem

What cannot be done today, or which OPEN-/BLK- item this addresses.

## Proposed solution

Be specific about wire format, hybrid group, and which barrel (`pqtransport.dart` vs `pqtransport_io.dart`).

## Non-goals / claim boundary

Confirm this does **not** require claiming:

- OpenSSL interop without a recorded fixture
- IANA `TLS_AES_256_GCM_SHA384` (0x1302) on a SHA-256 schedule
- FIPS 140 / CMVP module status
- `dart:ffi` or platform `SecureSocket` on the PQ path

## Alternatives

What was considered (e.g. wait for a pqforge export vs implement here).

## Additional context

Link `doc/ROADMAP.md` / `doc/BUGS.md` IDs if this is already tracked.
