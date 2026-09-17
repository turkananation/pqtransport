---
title: Sister packages
description: pqcrypto, pqforge, swissarmyknife, and pqtransport — one stack, four claim floors.
---

The TurkanaNation post-quantum Dart family is four packages with a
strict evidence floor. Do not upgrade a claim this layer is not allowed
to make.

| Package | Site | Role |
| --- | --- | --- |
| [pqcrypto](https://turkananation.github.io/pqcrypto/) | primitives | FIPS 203/204/205 + KAT / ACVP evidence. Zero runtime deps. |
| [pqforge](https://turkananation.github.io/pqforge/) | recipes | KEM-DEM, hybrids, AES-256-GCM, streaming, CLI. Sits on pqcrypto. |
| [swissarmyknife](https://turkananation.github.io/swissarmyknife/) | utilities | Result, StateMachine, Cache, CircuitBreaker, Throttler. Jaspr site. |
| **pqtransport** | this site | Protocol layer. Sits on pqforge + swissarmyknife. |

## Routing rule for agents

- Need KATs, ML-KEM encapsulate, ML-DSA sign, SLH-DSA? → **pqcrypto**.
- Need envelopes, files, hybrid application KEX, CLI? → **pqforge**.
- Need Result / StateMachine / breaker / cache? → **swissarmyknife**.
- Need TLS / UDP / DNS / mDNS / QUIC / HTTP over PQ crypto? → **pqtransport**.

pqtransport must not take a direct `pqcrypto` dependency unless a
documented exception lands. Crypto stays one stack (`pqforge`).

## Visual family

- pqcrypto — light forest, evidence-first, algorithm tables.
- pqforge — dark cyan / gold, named recipes, CLI.
- swissarmyknife — cream / emerald, Jaspr docs layout, release discipline.
- pqtransport — ink / phosphor lattice / cyan wire. Hybrid of lattice
  and classical, because that **is** the RFC 10024 story.

This site is a Jaspr static build, matching swissarmyknife, with the
PQ/hybrid theme of the crypto sisters.
