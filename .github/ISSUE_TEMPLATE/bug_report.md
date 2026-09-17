---
name: Bug report
about: A correctness, parse, or fail-open defect in pqtransport.
title: "fix: "
labels: "bug"
assignees: ""
---

## Description

A clear description of what is wrong.

## Reproduction

1. Protocol / API (`PqTlsSocket`, `PqEncryptedUdpSocket`, DNS, mDNS, QUIC, HTTP, …)
2. Hybrid group (`X25519MLKEM768` / `SecP256r1MLKEM768` / `SecP384r1MLKEM1024`)
3. Inputs / transcript
4. Observed error or byte mismatch

## Expected

What should have happened. Cite the RFC (10024 / 8446 / 9000 / 1035 / …) or `doc/` page if you can.

## Environment

- `pqtransport` version:
- Dart / Flutter SDK:
- OS / target (VM, dart2js, dart2wasm, Flutter):
- `pqforge` / `swissarmyknife` versions:

## Additional context

Stack traces, hex dumps, or failing tests.

> **Security:** if this is a vulnerability, do **not** file a public issue. Open a [private advisory](https://github.com/turkananation/pqtransport/security/advisories/new) or email turkananation@gmail.com. See `SECURITY.md`.
