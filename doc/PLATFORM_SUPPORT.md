# Platform Support

Last updated: 2026-09-17

`pqtransport` targets Dart SDK `>=3.12.0 <4.0.0`. Cryptography is
pure-Dart via pqforge (no `dart:ffi` in this package). Which
**transports** work depends on the barrel and the host.

## Barrels

| Import | Platforms | Provides |
|---|---|---|
| `package:pqtransport/pqtransport.dart` | VM, Flutter, web (dart2js / dart2wasm) | TLS, HTTP/1.1 codec, DNS codec, hybrid, memory sockets, QUIC sketch |
| `package:pqtransport/pqtransport_io.dart` | Dart VM, Flutter mobile/desktop | Everything above plus `IoDatagramChannel` (`dart:io` `RawDatagramSocket`) |

The web barrel must not import `dart:io` or `dart:ffi`. IO crypto does
not exist — `pqtransport_io.dart` only adds a datagram driver.

## Matrix

| Capability | Dart VM (Linux/macOS/Windows) | Flutter iOS/Android | Flutter desktop | Web |
|---|---|---|---|---|
| In-memory TLS (`MemoryByteSocket` + `PqTlsSocket`) | Yes | Yes | Yes | Yes |
| ChaCha20-Poly1305 (`0x1303`) | Yes | Yes | Yes | **No** on dart2js (PointyCastle Poly1305 needs 64-bit integers). AES-GCM `0x1302` is the web suite. dart2wasm can run ChaCha. |
| HTTP/1.1 codec over that TLS | Yes | Yes | Yes | Yes |
| DNS wire codec / cache / breaker | Yes | Yes | Yes | Yes |
| Encrypted UDP (memory network) | Yes | Yes | Yes | Yes |
| Encrypted UDP (real NIC) | Yes (`IoDatagramChannel`) | Yes | Yes | **No** |
| mDNS probe/announce (memory flood) | Yes | Yes | Yes | Yes |
| mDNS on a real LAN | Bind/send/receive unicast only until OPEN-09 (`joinMulticast`) | same | same | **No** |
| QUIC / HTTP/3 | Sketch only (all platforms) | Sketch | Sketch | Sketch (and no raw UDP) |
| Platform `SecureSocket` / `HttpClient` TLS | Not used on the PQ path | Not used | Not used | Not used |

## Web

Browsers do not expose generic UDP, multicast, or a raw QUIC socket to
Dart. Web callers:

1. Import the web barrel only.
2. Supply a `PqTransportSocket` over whatever byte pipe they have
   (WebSocket, a VM sidecar, `MemoryByteSocket` in tests).
3. Run `PqTlsSocket` on that pipe. Default suite is IANA `0x1302`
   (AES-256-GCM). IANA `0x1303` (ChaCha) is refused on dart2js because
   PointyCastle Poly1305 needs 64-bit integers.

DoH in a browser is an HTTPS POST of `application/dns-message`. 0.1.0
`DohExchange` is a helper, not a `fetch` wrapper — the caller provides
the HTTP round-trip.

## IO datagrams

```dart
import 'package:pqtransport/pqtransport_io.dart';

final ch = await IoDatagramChannel.bind(InternetAddress.anyIPv4, 0);
```

`IoDatagramChannel` does **not** call `joinMulticast` on 224.0.0.251 /
ff02::fb (OPEN-09). Unicast bind/send/receive works; real LAN mDNS
discovery does not. The in-memory `MemoryDatagramNetwork` floods those
group addresses so tests can exercise probe/announce/browse.

## Verified in this tree

| Gate | Where |
|---|---|
| Web-safe barrel import | `test/core/barrel_test.dart` |
| `dart:io` UDP bind/send | `test/io/io_channel_test.dart` |
| Analyzer on both barrels | `dart analyze` clean |
| No `dart:ffi` | invariant script |

Not yet a release gate: `dart compile js` of the public example,
`dart pub publish --dry-run`. Add those before the first pub.dev cut.

## Flutter notes

- Use the web barrel in a Flutter web build.
- Use the IO barrel in iOS/Android/desktop for real UDP.
- Do not add a plugin just to reach platform TLS. That abandons the
  package's reason to exist.
- Isolates / widget trees are a Client Integration concern, not this
  layer.

## Native crypto backends in pqforge

pqforge can register a `PqClassicalProvider` (X25519/Ed25519). That is
pqforge's seam, not pqtransport's. This package always talks bytes
through `PqTransportCrypto`. A native provider in the host app does not
change our barrels and does not authorize a `dart:ffi` import here.
