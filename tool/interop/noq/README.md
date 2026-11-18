# noq

Peer: [noq](https://github.com/n0-computer/noq) 1.5.0, commit
`bb1c63ee620b622281bfad8330b9a5a14e73372a`. TLS is rustls 0.23.46
with aws-lc-rs, not ring. ring has no ML-DSA.

The client trusts the ML-DSA-65 CA this flight mints, offers ALPN
`h3`, and sets `max_concurrent_multipath_paths(2)`. That sends
`initial_max_path_id` 1 (RFC 10069, transport parameter `0x3e`).
After the handshake it calls `open_path` to the same server address
and waits until `PATH_NEW_CONNECTION_ID` for that path has arrived.
The first ClientHello from this rustls build offers only an X25519
share, so the server sends HelloRetryRequest and the finished group
is X25519MLKEM768. Exit 0 is a completed handshake and an established
second path. The certificate check is rustls, not this package.
That is not every RFC 10069 frame, and the extra path has no
separate PTO.

picoquic 1.1.54.0 still does not offer ML-DSA-65. That flight stays
a refusal. This one is the multipath peer.
