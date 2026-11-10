# masque-go and connect-ip-go

`run.sh` builds both clients and both proxies. The clients run
against `PqHttp3Session`. The proxies are the reverse flights.
Go 1.27.3. The peers are tag v0.6.0. That tag requires quic-go
v0.63.0, not a later quic-go.

| Flight | What exited 0 |
| --- | --- |
| `udp_flight.dart` | masque-go client. CONNECT-UDP, context ID 0, payload `ping-masque` forwarded to a local UDP echo and returned. ML-DSA-65 checked by Go. |
| `ip_flight.dart` | connect-ip-go client. ADDRESS_ASSIGN `192.0.2.11/32`, one IPv4 route, one 20-byte IPv4 packet, reply sent to that address. ML-DSA-65 checked by Go. |
| `udp_reverse_flight.dart` | This stack is the client. A masque-go v0.6.0 proxy dials the UDP echo. Payload `ping-reverse`. `reverse-udp leaf=mlDsa65 group=x25519MlKem768 echoed=true quicDatagrams=true`. The response does not contain `capsule-protocol`. |
| `ip_reverse_flight.dart` | This stack is the client. A connect-ip-go v0.6.0 proxy assigns `192.0.2.11/32`. One 20-byte IPv4 packet, proto 17, `192.0.2.11` to `198.51.100.1`, comes back swapped. `reverse-ip leaf=mlDsa65 group=x25519MlKem768 echoed=true quicDatagrams=true`. |

The leaf on the reverse flights is minted by OpenSSL 3.5.9 as
seed-only PKCS#8, which is the form Go 1.27 loads. This client
checks `peerLeafAlgorithm == mlDsa65` and
`negotiatedGroupName == x25519MlKem768`.

The UDP and IP payloads are QUIC DATAGRAM frames. The address
and route capsules are the Capsule Protocol. DATAGRAM capsules are
not what these peers send. Draft DNS and PREF64 capsules are not
implemented. Multipath is not this directory.

No proxy credentials.
