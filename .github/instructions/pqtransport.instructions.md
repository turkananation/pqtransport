---
applyTo: "lib/**/*.dart,test/**/*.dart,doc/**/*.md"
---

# pqtransport coding instructions

Follow `doc/ENGINEERING_GUIDE.md` and `doc/CLAIM_BOUNDARY.md`.

1. Web-safe code stays in `lib/pqtransport.dart`. IO is a separate barrel.
2. `StateMachine.trigger` returns `Result`. Do not throw at codec boundaries.
3. Replay windows peek the sequence **before** AEAD open.
4. TLS application traffic secrets are `late`, not `late final` (they are
   reassigned at `deriveApplication`).
5. Hide pqforge `requireLength` if both packages are imported.
6. Tests first for wire formats. Live crypto tests cover X25519MLKEM768 only
   until pqforge grows P-256/P-384 ECDH.
