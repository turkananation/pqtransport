//! Handshake-only quiche peer. Not HTTP/3.
//!
//! `client <host:port> <ca.pem>` verifies the server with that CA.
//! `server <port> <cert.pem> <key.pem>` presents that chain.
//!
//! The only group is X25519MLKEM768. The only signature scheme is
//! ML-DSA-65. The only TLS 1.3 suite requested is
//! TLS_AES_256_GCM_SHA384. ALPN is `h3` because that is the
//! application token on the QUIC handshake, not because this process
//! speaks HTTP/3.

use std::io::{self, Write};
use std::net::{SocketAddr, UdpSocket};
use std::process::ExitCode;
use std::time::{Duration, Instant};

use boring::ssl::{SslContextBuilder, SslMethod, SslSignatureAlgorithm, SslVersion};

const ALPN: &[u8] = b"h3";
const GROUP: &str = "X25519MLKEM768";
// IANA TLS SignatureScheme mldsa65 and cipher suite
// TLS_AES_256_GCM_SHA384. BoringSSL's rust wrapper has no setter for
// the sign list or the TLS 1.3 suite list. The C API does.
const ML_DSA_65: u16 = 0x0905;
const TLS_AES_256_GCM_SHA384: u16 = 0x1302;

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let mode = args.next().unwrap_or_default();
    match mode.as_str() {
        "client" => client(args),
        "server" => server(args),
        _ => {
            eprintln!(
                "usage: quiche_peer client <host:port> <ca.pem>\n       \
                 quiche_peer server <port> <cert.pem> <key.pem>"
            );
            ExitCode::from(64)
        }
    }
}

fn context_builder() -> SslContextBuilder {
    let mut builder = SslContextBuilder::new(SslMethod::tls()).unwrap_or_else(|err| {
        die(&format!("SslContextBuilder: {err}"));
    });
    builder
        .set_min_proto_version(Some(SslVersion::TLS1_3))
        .unwrap_or_else(|err| die(&format!("min version: {err}")));
    builder
        .set_max_proto_version(Some(SslVersion::TLS1_3))
        .unwrap_or_else(|err| die(&format!("max version: {err}")));
    // BoringSSL's default verify list is classical. An ML-DSA leaf is
    // rejected unless this is set. The sign list is pinned the same
    // way so a classical key cannot be used.
    let scheme = [SslSignatureAlgorithm::ML_DSA_65];
    builder
        .set_verify_algorithm_prefs(&scheme)
        .unwrap_or_else(|err| die(&format!("verify prefs: {err}")));
    let ctx = builder.as_ptr();
    let pinned = unsafe {
        boring_sys::SSL_CTX_set_signing_algorithm_prefs(ctx.cast(), &ML_DSA_65, 1) == 1
            && boring_sys::SSL_CTX_set1_tls13_ciphers(
                ctx.cast(),
                &TLS_AES_256_GCM_SHA384,
                std::ptr::null(),
                1,
            ) == 1
    };
    if !pinned {
        die("could not pin ML-DSA-65 and TLS_AES_256_GCM_SHA384");
    }
    builder
}

fn config() -> quiche::Config {
    let mut config = quiche::Config::with_boring_ssl_ctx_builder(
        quiche::PROTOCOL_VERSION,
        context_builder(),
    )
    .unwrap_or_else(|err| die(&format!("quiche config: {err:?}")));
    config
        .set_application_protos(&[ALPN])
        .unwrap_or_else(|err| die(&format!("alpn: {err:?}")));
    config
        .set_curves_list(GROUP)
        .unwrap_or_else(|err| die(&format!("groups: {err:?}")));
    config.set_max_idle_timeout(30_000);
    config.set_max_recv_udp_payload_size(65527);
    config.set_max_send_udp_payload_size(1200);
    config.set_initial_max_data(10_000_000);
    config.set_initial_max_stream_data_bidi_local(1_000_000);
    config.set_initial_max_stream_data_bidi_remote(1_000_000);
    config.set_initial_max_stream_data_uni(1_000_000);
    config.set_initial_max_streams_bidi(16);
    config.set_initial_max_streams_uni(16);
    config.set_disable_active_migration(true);
    config
}

fn random_cid() -> quiche::ConnectionId<'static> {
    let mut bytes = vec![0u8; 8];
    let mut file = std::fs::File::open("/dev/urandom").unwrap_or_else(|err| {
        die(&format!("urandom: {err}"));
    });
    io::Read::read_exact(&mut file, &mut bytes).unwrap_or_else(|err| {
        die(&format!("urandom: {err}"));
    });
    quiche::ConnectionId::from_vec(bytes)
}

fn client(mut args: impl Iterator<Item = String>) -> ExitCode {
    let peer_text = args.next().unwrap_or_default();
    let ca = args.next().unwrap_or_default();
    if peer_text.is_empty() || ca.is_empty() || args.next().is_some() {
        eprintln!("usage: quiche_peer client <host:port> <ca.pem>");
        return ExitCode::from(64);
    }
    let peer: SocketAddr = peer_text.parse().unwrap_or_else(|_| {
        die(&format!("not a socket address: {peer_text}"));
    });
    let mut config = config();
    config
        .load_verify_locations_from_file(&ca)
        .unwrap_or_else(|err| die(&format!("ca: {err:?}")));
    config.verify_peer(true);
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap_or_else(|err| die(&format!("bind: {err}")));
    let local = socket.local_addr().unwrap();
    let scid = random_cid();
    let mut conn = quiche::connect(Some("localhost"), &scid, local, peer, &mut config)
        .unwrap_or_else(|err| die(&format!("connect: {err:?}")));
    let mut out = [0u8; 65535];
    flush(&socket, &mut conn, &mut out);
    let ok = drive(&socket, &mut conn, &mut out);
    if ok {
        let len = conn.peer_cert().map(|cert| cert.len()).unwrap_or(0);
        if len == 0 {
            eprintln!("established with no peer certificate");
            return ExitCode::from(1);
        }
        println!("established peer_cert={len}");
        let _ = io::stdout().flush();
        // Keep ACKing long enough for the peer to finish its flight.
        let grace = Instant::now() + Duration::from_secs(2);
        while Instant::now() < grace && !conn.is_closed() {
            pump_once(&socket, &mut conn, &mut out, Duration::from_millis(50));
        }
        ExitCode::SUCCESS
    } else {
        explain(&conn);
        ExitCode::from(1)
    }
}

fn server(mut args: impl Iterator<Item = String>) -> ExitCode {
    let port_text = args.next().unwrap_or_default();
    let cert = args.next().unwrap_or_default();
    let key = args.next().unwrap_or_default();
    if port_text.is_empty() || cert.is_empty() || key.is_empty() || args.next().is_some() {
        eprintln!("usage: quiche_peer server <port> <cert.pem> <key.pem>");
        return ExitCode::from(64);
    }
    let port: u16 = port_text.parse().unwrap_or_else(|_| {
        die(&format!("not a port: {port_text}"));
    });
    let mut config = config();
    config
        .load_cert_chain_from_pem_file(&cert)
        .unwrap_or_else(|err| die(&format!("cert: {err:?}")));
    config
        .load_priv_key_from_pem_file(&key)
        .unwrap_or_else(|err| die(&format!("key: {err:?}")));
    config.verify_peer(false);
    let socket = UdpSocket::bind(("127.0.0.1", port))
        .unwrap_or_else(|err| die(&format!("bind {port}: {err}")));
    let local = socket.local_addr().unwrap();
    println!("listening {local}");
    let _ = io::stdout().flush();
    let mut buf = [0u8; 65535];
    let mut out = [0u8; 65535];
    let deadline = Instant::now() + Duration::from_secs(25);
    let mut conn: Option<quiche::Connection> = None;
    let mut announced = false;
    while Instant::now() < deadline {
        let wait = Duration::from_millis(200);
        socket
            .set_read_timeout(Some(wait))
            .unwrap_or_else(|err| die(&format!("timeout: {err}")));
        match socket.recv_from(&mut buf) {
            Ok((len, from)) => {
                if conn.is_none() {
                    let hdr = match quiche::Header::from_slice(&mut buf[..len], 8) {
                        Ok(hdr) => hdr,
                        Err(err) => {
                            eprintln!("header: {err:?}");
                            continue;
                        }
                    };
                    if hdr.ty != quiche::Type::Initial {
                        eprintln!("ignored {:?}", hdr.ty);
                        continue;
                    }
                    let scid = random_cid();
                    match quiche::accept(&scid, None, local, from, &mut config) {
                        Ok(accepted) => conn = Some(accepted),
                        Err(err) => {
                            eprintln!("accept: {err:?}");
                            continue;
                        }
                    }
                }
                let current = conn.as_mut().unwrap();
                let info = quiche::RecvInfo {
                    to: local,
                    from,
                };
                match current.recv(&mut buf[..len], info) {
                    Ok(n) => eprintln!("recv {n} from {from}"),
                    Err(quiche::Error::Done) => {}
                    Err(err) => eprintln!("recv failed: {err:?}"),
                }
            }
            Err(err)
                if err.kind() == io::ErrorKind::WouldBlock
                    || err.kind() == io::ErrorKind::TimedOut =>
            {
                if let Some(current) = conn.as_mut() {
                    current.on_timeout();
                }
            }
            Err(err) => die(&format!("udp: {err}")),
        }
        if let Some(current) = conn.as_mut() {
            flush(&socket, current, &mut out);
            if current.is_established() && !announced {
                println!("established");
                let _ = io::stdout().flush();
                announced = true;
            }
            if current.is_closed() {
                explain(current);
                return if announced {
                    ExitCode::SUCCESS
                } else {
                    ExitCode::from(1)
                };
            }
        }
    }
    if let Some(current) = conn.as_ref() {
        explain(current);
    }
    if announced {
        ExitCode::SUCCESS
    } else {
        eprintln!("timed out before the handshake");
        ExitCode::from(1)
    }
}

/// Returns true once the handshake is established.
fn drive(socket: &UdpSocket, conn: &mut quiche::Connection, out: &mut [u8]) -> bool {
    let deadline = Instant::now() + Duration::from_secs(20);
    while Instant::now() < deadline {
        if conn.is_established() {
            return true;
        }
        if conn.is_closed() {
            return false;
        }
        let wait = conn
            .timeout()
            .unwrap_or(Duration::from_millis(200))
            .min(Duration::from_millis(200));
        pump_once(socket, conn, out, wait);
    }
    conn.is_established()
}

fn pump_once(
    socket: &UdpSocket,
    conn: &mut quiche::Connection,
    out: &mut [u8],
    wait: Duration,
) {
    let mut buf = [0u8; 65535];
    socket
        .set_read_timeout(Some(wait))
        .unwrap_or_else(|err| die(&format!("timeout: {err}")));
    match socket.recv_from(&mut buf) {
        Ok((len, from)) => {
            let info = quiche::RecvInfo {
                to: socket.local_addr().unwrap(),
                from,
            };
            match conn.recv(&mut buf[..len], info) {
                Ok(n) => eprintln!("recv {n} from {from}"),
                Err(quiche::Error::Done) => {}
                Err(err) => eprintln!("recv failed: {err:?}"),
            }
        }
        Err(err)
            if err.kind() == io::ErrorKind::WouldBlock || err.kind() == io::ErrorKind::TimedOut =>
        {
            conn.on_timeout();
        }
        Err(err) => die(&format!("udp: {err}")),
    }
    flush(socket, conn, out);
}

fn flush(socket: &UdpSocket, conn: &mut quiche::Connection, out: &mut [u8]) {
    loop {
        match conn.send(out) {
            Ok((n, info)) => {
                if let Err(err) = socket.send_to(&out[..n], info.to) {
                    eprintln!("sendto: {err}");
                    break;
                }
                eprintln!("send {n} to {}", info.to);
            }
            Err(quiche::Error::Done) => break,
            Err(err) => {
                eprintln!("send failed: {err:?}");
                break;
            }
        }
    }
}

fn explain(conn: &quiche::Connection) {
    if let Some(err) = conn.peer_error() {
        eprintln!("peer error: {err:?}");
    }
    if let Some(err) = conn.local_error() {
        eprintln!("local error: {err:?}");
    }
    eprintln!(
        "closed={} established={}",
        conn.is_closed(),
        conn.is_established()
    );
}

fn die(message: &str) -> ! {
    eprintln!("{message}");
    std::process::exit(1);
}
