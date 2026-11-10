# MASQUE and multipath peers

Not run. Not claimed. The Dart code speaks the RFCs below. A claim
needs the named process to exit 0, with the ML-DSA-65 leaf checked,
in both directions.

| Protocol | Pin | What has to be true |
| --- | --- | --- |
| Capsule Protocol, RFC 9297, and CONNECT-UDP, RFC 9298 | `quic-go/masque-go` v0.6.0 on `quic-go` v0.65.0, Go 1.27 | Context ID 0 UDP payload, `Capsule-Protocol: ?1`, `:protocol connect-udp`. neqo is a second client only. |
| CONNECT-IP, RFC 9484 | `quic-go/connect-ip-go` v0.6.0 | One `ADDRESS_ASSIGN`, one `ROUTE_ADVERTISEMENT`, one IPv4 and one IPv6 packet of at least 1280 bytes on context ID 0. A packet outside the assigned prefix is dropped. Skip draft DNS and PREF64 capsules. Do not implement them. |
| HTTP/2 extended CONNECT, RFC 8441 | curl 8.23.0 `--with-nghttp2` | `wss://` against this stack. The curl in `tool/interop/openssl/build_curl.sh` is still 8.16.0 and has no nghttp2. |
| Multipath, RFC 10069 | picoquic 1.1.54.0, built on OpenSSL 3.5.9 | Confirm the frame numbers match the RFC before the flight. First flight is single-path with multipath off. A two-path flight requires `initialMaxPathId` on `PqQuicConn`. Extra-path PTO is not implemented. |

Do not pin Cloudflare WARP or iCloud Private Relay. Do not treat
curl `--enable-proxy-http3` as a capsule proof. That flag is the
client of a CONNECT-UDP proxy, and curl 8.23 still has
[curl/curl#23802](https://github.com/curl/curl/issues/23802).
No proxy credentials in any flight.
