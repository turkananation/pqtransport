# picoquic

Peer: picoquic 1.1.54.0, tag `v2026.11.16.f557eab`, picotls
`e446233b4100ebcdec60901c05bfb7f4cd369c5d`, OpenSSL 3.5.9.

`run.sh` is in `tool/interop/run_all.sh`. The demo's ClientHello
offers ed25519, ECDSA, and RSA-PSS. It does not offer ML-DSA-65
(`0x0905`). This server answers `unsupported_certificate`. With
`-M` the demo prints `Enable multipath: Refused` and uses one
client port. The flight exits 0 only for that result. A completed
handshake or a second path fails the job, because that would be a
different peer than the one this script builds. Multipath
(RFC 10069) is not claimed. A classical certificate is not minted.
