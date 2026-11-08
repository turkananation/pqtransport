---
title: Protocols
description: UDP, TLS 1.3, DNSSEC, DoH/DoT, mDNS, QUIC, and HTTP in pqtransport 0.2.0.
---

Status vocabulary matches [`doc/FEATURES.md`](https://github.com/turkananation/pqtransport/blob/main/doc/FEATURES.md):
**Done** (tested), **Partial**, **Fail-closed**, **Not started**.

## UDP

Versioned datagram envelope: `version || hdrLen || header || nonce || ct||tag`.
AES-256-GCM with AAD-bound sequence. Replay peeks the sequence **before**
AEAD open. Send path uses swissarmyknife `Throttler`. Encrypted session
is X25519MLKEM768, SecP256r1MLKEM768, or SecP384r1MLKEM1024 with
identical HKDF extra on both roles.

The handshake is a QUIC Initial long header. The client datagram is
padded to 1200 bytes, and the server discards anything shorter. The
server answers with its own Initial. A peer opens the client packet
with the client initial keys and the server packet with the server
initial keys, both from the client's destination connection ID.
Application data is a QUIC short header. A dropped frame is sent
again under a new packet number. Not ECN. Not `curl --http3`.

The call is `PqEncryptedUdpSocket.initiate`, then `accept`, then
`completeInitiate`, then `send`. Both endpoints and the KEM key are
in the [Cookbook](cookbook#encrypted-udp).

## TLS 1.3

Client and server `StateMachine`s from swissarmyknife. Illegal event →
`failed` + `Result.failure`. RFC 8446-shaped ClientHello / ServerHello
(OPEN-01). EncryptedExtensions + Certificate + CertificateVerify +
Finished. RFC 7250 RawPublicKey is the default. Opt-in X.509 is a
caller-supplied chain of 1 to 8, leaf first, checked by pqforge. Trust
is caller anchors or one self-signed SPKI pin. No AIA, no system trust
store, no browser. AES-256-GCM (`0x1302`) or ChaCha20-Poly1305
(`0x1303`) records; handshake vs application epochs reset sequence.
TLS exporter is deterministic on a fixture. Schedule follows the suite:
HKDF-SHA-384 for IANA `0x1302` (default), HKDF-SHA-256 for IANA
`0x1303`. Private-use `0xFF00` is retired.

HelloRetryRequest is on the wire with cookie extension 44 and
`selected_group` (OPEN-05). Once-only; a second HRR fails closed.
BoringSSL's HRR carries no cookie; that decodes. OpenSSL 3.5.9 completes
the three RFC 10024 groups (raw-pk and X.509, both directions) and
X25519, secp256r1, secp384r1, and MLKEM1024. BoringSSL 0.20261020.0 is
a TLS peer on X25519MLKEM768 and those four fallback groups, not on
SecP256r1MLKEM768 or SecP384r1MLKEM1024. curl linked to this OpenSSL
does two HTTP/1.1 GETs with `--cacert`. Not `curl --http3`.

ECH (RFC 9849) is self-interop and one BoringSSL flight. The suite is
DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-128-GCM, via `PqHpke`
(pqforge 0.4.10). Inner name `localhost`, public name `public.example`.
A client with an `EchConfig` does not send a cleartext second hello.
Not an OpenSSL flight. Not GREASE. Not DNS. Not a browser.

The call is `PqTlsSocket.client` and `PqTlsSocket.server`, then
`handshake`, `send`, and `exporter`. SNI, ALPN, and
`peerAuthenticated` are in the [Cookbook](cookbook#tls-13). The
program is `example/tls13.dart`.

## DNS / DoH / DoT

Wire codec for A, AAAA, CNAME, MX, TXT, SRV, CAA, HTTPS, SVCB, OPT, PTR,
NS, DNSKEY, DS, and RRSIG. Compression pointer cycles are rejected. Rdata name pointers
(CNAME / NS / PTR / MX / SRV / HTTPS / SVCB) resolve against the outer
message (OPEN-08). TTL cache uses an injected
clock. `CircuitBreaker` wraps exchange and opens after
`failureThreshold`. Resolver failover is DoH, then DoT, then UDP.
DNSSEC verifies algorithms 5, 7, 8, 10, 13, 14, 15, and 16 via pqforge, from a
caller-supplied trust anchor down the zone cuts. RSA is PKCS#1 with
moduli of 1024, 2048, 3072, and 4096 bits. A trust anchor may be a DS
set. Algorithm 16 is Ed448, pure, empty context. The stub sets RD,
DO, and CD, requires a matching response id, retries a truncated UDP
answer over TCP, and retries BADCOOKIE once. `example/dns_validate.dart`
signs a zone in memory. `example/dns_live.dart` validates
`yardenah.com` from the IANA root DS set. SOA and unknown RRs decode.
NSEC and NSEC3 prove a missing name and a missing type, and a cached
proof answers a later name in that span. NSEC3 is hash algorithm 1,
SHA-1 from pqforge 0.4.11. The iteration field is 0 through 65535.
The iterative resolver's ceiling defaults to 0. That resolver follows
referrals from root hints and returns secure, insecure, or bogus.
The AD bit is not validation. Not an authoritative server.

`PqDnsClient.lookup` is one query. `resolve` follows CNAME.
`authenticateDns` takes `lookup`, not `resolve`. DoH is
`DohClient.h2` or `DohClient.h3`, then `PqDnsResolver(doh: exchange)`.
DoT is `DotClient` after ALPN `dot`, with `encodeDnsTcp`. The
iterative walker is `DnsIterativeResolver`. Each of those calls is
in the [Cookbook](cookbook#dns-stub). The programs are
`example/dns_stub.dart`, `example/dns_validate.dart`,
`example/dns_live.dart`, `example/doh.dart`, and `example/dot.dart`.

## mDNS

Probe / announce / browse on 5353. Receivers join `224.0.0.251` /
`ff02::fb` (`joinMdnsGroups`). Optional ML-DSA-65 TXT (`pqsig=`).
An optional second field, `pqslh=`, is SLH-DSA-SHA2-128f and is not
the default. EventBus announcements per client. Real LAN mDNS uses
`IoDatagramChannel.joinMulticast`. Browsers have no raw UDP (LIM-04).
SLH-DSA-SHA2-128f is archival only. The other eleven sets are not
used here, and TLS CertificateVerify stays ML-DSA.

The call is `beginProbe`, two `completeProbe`s, then `announce`.
`signTxt` takes `crypto`, `secretKey`, `name`, and `body`.
`signTxtArchival` is the optional SLH-DSA-SHA2-128f path. Both are
in the [Cookbook](cookbook#mdns). The program is
`example/mdns_discovery.dart`.

## QUIC / HTTP

1-RTT short-header HP and Initial long-header HP. AES for Initial and
for an AES 1-RTT suite. ChaCha20 header protection (RFC 9001 §5.4.4)
uses the pqforge keystream. CRYPTO frames carry a live TLS handshake
(RFC 9001, no TLS records). ACK processor is present. QUIC, HTTP/2,
and HTTP/3 in this tree are self-interop slices. They are not complete
RFC 9000, 9113, or 9114 stacks. The gap list is `TODO.md`.

HTTP/1.1 request/response is Done, including GET over a completed
`PqTlsSocket`. HTTP/2 is Done on ALPN `h2` (RFC 9113 + RFC 7541). HTTP/3
is Done on ALPN `h3` (RFC 9114 + RFC 9204 QPACK on QUIC STREAM). Silent
h2/h3→h1 downgrade is refused (`allowDowngrade: false`).

HTTP/1.1 is `PqHttpClient.roundTrip` after the server listens on
`applicationData`. HTTP/2 is `PqHttp2Session.server` plus
`roundTripH2`. HTTP/3 is `PqQuicConn.pair` plus `roundTripH3`. The
three calls are in the [Cookbook](cookbook#http11). The programs are
`example/http1.dart`, `example/http2.dart`, and `example/http3.dart`.
