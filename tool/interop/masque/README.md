# masque-go and connect-ip-go

`run.sh` builds two clients and runs them against `PqHttp3Session`.
Go 1.27.3. The peers are tag v0.6.0. That tag requires quic-go
v0.63.0, not a later quic-go.

| Flight | What exited 0 |
| --- | --- |
| `udp_flight.dart` | masque-go client. CONNECT-UDP, context ID 0, payload `ping-masque` forwarded to a local UDP echo and returned. ML-DSA-65 checked by Go. |
| `ip_flight.dart` | connect-ip-go client. ADDRESS_ASSIGN `192.0.2.11/32`, one IPv4 route, one 20-byte IPv4 packet, reply sent to that address. ML-DSA-65 checked by Go. |

Both are their client and this server. The reverse has not been
run. The UDP and IP payloads are QUIC DATAGRAM frames. The address
and route capsules are the Capsule Protocol. DATAGRAM capsules are
not what these peers send. Draft DNS and PREF64 capsules are not
implemented. Multipath is not this directory.

No proxy credentials.
