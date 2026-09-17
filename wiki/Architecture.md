Canonical page:
[doc/ARCHITECTURE.md](https://github.com/turkananation/pqtransport/blob/main/doc/ARCHITECTURE.md).

Stack: application → HTTP / DNS / mDNS / QUIC frames → TLS or encrypted UDP →
pqforge (ML-KEM, ML-DSA, AES-256-GCM, X25519) + swissarmyknife (`Result`,
`StateMachine`).
