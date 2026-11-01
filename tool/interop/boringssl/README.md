# BoringSSL 0.20261020.0

A process, not `dart:ffi`. The peer is `boringssl_peer`, linked against
the pinned BoringSSL. `boringssl_verify` is unchanged: `X509_verify_cert`
on a leaf, which is not this handshake.

## What is claimed

Handshake interop with BoringSSL 0.20261020.0 on X25519MLKEM768 and
`TLS_AES_256_GCM_SHA384` (`0x1302`), both directions (2026-11-01).
The same peer also finishes X25519, secp256r1, secp384r1, and
MLKEM1024, both directions, ML-DSA-65 chain length 1. The default
client still offers the hybrid first. P-256, P-384, and MLKEM1024
are HelloRetryRequest. BoringSSL sends that retry with no cookie.

| Item | Value |
| --- | --- |
| Peer | BoringSSL 0.20261020.0 (`d3bf4795ad5b79d646cddf2fec687da5b9b502db`) |
| Hybrid | `X25519MLKEM768` (`0x11EC`). ML-KEM then X25519. ML-DSA-65 chain length 1, one P-256 leaf, ML-DSA-65 raw public key. |
| Fallback | `X25519` (`29`), `secp256r1` (`23`), `secp384r1` (`24`), `MLKEM1024` (`0x0202`). ML-DSA-65 chain length 1 only. |
| Suite | `TLS_AES_256_GCM_SHA384` (`0x1302`) |
| Negative | A different CA is rejected on the hybrid flight. ECH without the server key ends in `ech_required` and no second ClientHello. |
| ECH | RFC 9849, both directions, X25519MLKEM768 only. Inner name `localhost`, public name `public.example`. `bssl s_server` / `bssl s_client`. Not OpenSSL. Not DNS. Not GREASE. Not a browser. |
| Not claimed | SecP256r1MLKEM768, SecP384r1MLKEM1024, MLKEM512, MLKEM768, TLS 1.2, a browser, WebPKI, curl. |

SecP256r1MLKEM768 and SecP384r1MLKEM1024 are not `SSL_GROUP_*` values in
this pin. They stay on the OpenSSL 3.5.9 fixture.

## Run

From the repository root:

```bash
bash tool/interop/boringssl/run.sh
```
