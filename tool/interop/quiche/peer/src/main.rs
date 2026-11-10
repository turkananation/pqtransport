//! quiche peer. Handshake modes are `client` and `server`.
//! HTTP/3 modes are `h3-client` and `h3-server`.
//! `h3-ext-client` and `h3-ext-server` speak extended CONNECT
//! (RFC 9220), PRIORITY_UPDATE (RFC 9218), and an HTTP datagram
//! (RFC 9297) carried in a QUIC DATAGRAM frame (RFC 9221).
//!
//! The only group is X25519MLKEM768. The only signature scheme is
//! ML-DSA-65. The only TLS 1.3 suite requested is
//! TLS_AES_256_GCM_SHA384. ALPN is `h3`.
//!
//! `h3-client <host:port> <ca.pem>` verifies the server certificate
//! and prints `h3 status=200 body=pq-h3 peer_cert=N`.
//! `h3-server <port> <cert.pem> <key.pem>` answers GET /pq with
//! body `quiche-h3`.

use std::io::{self, Write};
use std::net::{SocketAddr, UdpSocket};
use std::process::ExitCode;
use std::time::{Duration, Instant};

use boring::ssl::{SslContextBuilder, SslMethod, SslSignatureAlgorithm, SslVersion};
use quiche::h3::NameValue;

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
        "h3-client" => h3_client(args),
        "h3-server" => h3_server(args),
        "h3-ext-client" => h3_ext_client(args),
        "h3-ext-server" => h3_ext_server(args),
        _ => {
            eprintln!(
                "usage: quiche_peer client <host:port> <ca.pem>\n       \
                 quiche_peer server <port> <cert.pem> <key.pem>\n       \
                 quiche_peer h3-client <host:port> <ca.pem>\n       \
                 quiche_peer h3-server <port> <cert.pem> <key.pem>\n       \
                 quiche_peer h3-ext-client <host:port> <ca.pem>\n       \
                 quiche_peer h3-ext-server <port> <cert.pem> <key.pem>"
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

fn h3_config() -> quiche::h3::Config {
    // quiche 0.30 decodes static and literal QPACK only. It rejects a
    // dynamic-table reference. Capacity stays at the RFC default of 0
    // so both sides use that encoding. Grease stays on.
    quiche::h3::Config::new().unwrap_or_else(|err| die(&format!("h3 config: {err:?}")))
}

fn header_value<'a>(list: &'a [quiche::h3::Header], name: &[u8]) -> Option<&'a [u8]> {
    list.iter().find(|header| header.name() == name).map(|header| header.value())
}

fn h3_client(mut args: impl Iterator<Item = String>) -> ExitCode {
    let peer_text = args.next().unwrap_or_default();
    let ca = args.next().unwrap_or_default();
    if peer_text.is_empty() || ca.is_empty() || args.next().is_some() {
        eprintln!("usage: quiche_peer h3-client <host:port> <ca.pem>");
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
    if !drive(&socket, &mut conn, &mut out) {
        explain(&conn);
        return ExitCode::from(1);
    }
    let cert_len = conn.peer_cert().map(|cert| cert.len()).unwrap_or(0);
    if cert_len == 0 {
        eprintln!("established with no peer certificate");
        return ExitCode::from(1);
    }
    let h3_config = h3_config();
    let mut h3 = match quiche::h3::Connection::with_transport(&mut conn, &h3_config) {
        Ok(http) => http,
        Err(err) => {
            eprintln!("h3: {err:?}");
            explain(&conn);
            return ExitCode::from(1);
        }
    };
    let request = [
        quiche::h3::Header::new(b":method", b"GET"),
        quiche::h3::Header::new(b":scheme", b"https"),
        quiche::h3::Header::new(b":authority", b"localhost"),
        quiche::h3::Header::new(b":path", b"/pq"),
        quiche::h3::Header::new(b"x-pq", b"interop"),
    ];
    let mut sent = false;
    let mut stream_id = 0u64;
    let mut status = String::new();
    let mut body = Vec::new();
    let mut finished = false;
    let deadline = Instant::now() + Duration::from_secs(20);
    while Instant::now() < deadline && !conn.is_closed() {
        if !sent {
            match h3.send_request(&mut conn, &request, true) {
                Ok(id) => {
                    stream_id = id;
                    sent = true;
                }
                Err(quiche::h3::Error::StreamBlocked) | Err(quiche::h3::Error::Done) => {}
                Err(err) => {
                    eprintln!("h3 send: {err:?}");
                    explain(&conn);
                    return ExitCode::from(1);
                }
            }
        }
        loop {
            match h3.poll(&mut conn) {
                Ok((id, quiche::h3::Event::Headers { list, .. })) if id == stream_id => {
                    if let Some(value) = header_value(&list, b":status") {
                        status = String::from_utf8_lossy(value).into_owned();
                    }
                }
                Ok((id, quiche::h3::Event::Data)) if id == stream_id => {
                    let mut buf = [0u8; 4096];
                    loop {
                        match h3.recv_body(&mut conn, id, &mut buf) {
                            Ok(n) => body.extend_from_slice(&buf[..n]),
                            Err(quiche::h3::Error::Done) => break,
                            Err(err) => {
                                eprintln!("h3 body: {err:?}");
                                explain(&conn);
                                return ExitCode::from(1);
                            }
                        }
                    }
                }
                Ok((id, quiche::h3::Event::Finished)) if id == stream_id => finished = true,
                Ok((_, quiche::h3::Event::Reset(code))) => {
                    eprintln!("h3 reset {code}");
                    explain(&conn);
                    return ExitCode::from(1);
                }
                Ok(_) => {}
                Err(quiche::h3::Error::Done) => break,
                Err(err) => {
                    eprintln!("h3 poll: {err:?}");
                    explain(&conn);
                    return ExitCode::from(1);
                }
            }
        }
        flush(&socket, &mut conn, &mut out);
        if finished && status == "200" && body == b"pq-h3" {
            println!("h3 status=200 body=pq-h3 peer_cert={cert_len}");
            let _ = io::stdout().flush();
            let grace = Instant::now() + Duration::from_secs(1);
            while Instant::now() < grace && !conn.is_closed() {
                pump_once(&socket, &mut conn, &mut out, Duration::from_millis(50));
            }
            return ExitCode::SUCCESS;
        }
        let wait = conn
            .timeout()
            .unwrap_or(Duration::from_millis(50))
            .min(Duration::from_millis(50));
        pump_once(&socket, &mut conn, &mut out, wait);
    }
    eprintln!("h3 client timed out status={status} body={}", String::from_utf8_lossy(&body));
    explain(&conn);
    ExitCode::from(1)
}

fn h3_server(mut args: impl Iterator<Item = String>) -> ExitCode {
    let port_text = args.next().unwrap_or_default();
    let cert = args.next().unwrap_or_default();
    let key = args.next().unwrap_or_default();
    if port_text.is_empty() || cert.is_empty() || key.is_empty() || args.next().is_some() {
        eprintln!("usage: quiche_peer h3-server <port> <cert.pem> <key.pem>");
        return ExitCode::from(64);
    }
    let port: u16 = port_text.parse().unwrap_or_else(|_| die(&format!("not a port: {port_text}")));
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
    let h3_config = h3_config();
    let mut buf = [0u8; 65535];
    let mut out = [0u8; 65535];
    let deadline = Instant::now() + Duration::from_secs(25);
    let mut conn: Option<quiche::Connection> = None;
    let mut http: Option<quiche::h3::Connection> = None;
    let mut served = false;
    while Instant::now() < deadline {
        let wait = Duration::from_millis(50);
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
                let info = quiche::RecvInfo { to: local, from };
                match current.recv(&mut buf[..len], info) {
                    Ok(_) => {}
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
        let Some(current) = conn.as_mut() else {
            continue;
        };
        if current.is_established() && http.is_none() {
            match quiche::h3::Connection::with_transport(current, &h3_config) {
                Ok(created) => http = Some(created),
                Err(err) => {
                    eprintln!("h3: {err:?}");
                    explain(current);
                    return ExitCode::from(1);
                }
            }
        }
        if let Some(session) = http.as_mut() {
            loop {
                match session.poll(current) {
                    Ok((stream, quiche::h3::Event::Headers { list, .. })) => {
                        let method = header_value(&list, b":method").unwrap_or(b"");
                        let path = header_value(&list, b":path").unwrap_or(b"");
                        println!(
                            "h3 request method={} path={}",
                            String::from_utf8_lossy(method),
                            String::from_utf8_lossy(path)
                        );
                        let _ = io::stdout().flush();
                        if method != b"GET" || path != b"/pq" {
                            eprintln!("unexpected request");
                            return ExitCode::from(1);
                        }
                        let response = [
                            quiche::h3::Header::new(b":status", b"200"),
                            quiche::h3::Header::new(b"content-type", b"text/plain"),
                        ];
                        if let Err(err) = session.send_response(current, stream, &response, false) {
                            eprintln!("h3 response: {err:?}");
                            explain(current);
                            return ExitCode::from(1);
                        }
                        match session.send_body(current, stream, b"quiche-h3", true) {
                            Ok(_) => served = true,
                            Err(err) => {
                                eprintln!("h3 body: {err:?}");
                                explain(current);
                                return ExitCode::from(1);
                            }
                        }
                    }
                    Ok((stream, quiche::h3::Event::Data)) => {
                        let mut discard = [0u8; 4096];
                        while session.recv_body(current, stream, &mut discard).is_ok() {}
                    }
                    Ok(_) => {}
                    Err(quiche::h3::Error::Done) => break,
                    Err(err) => {
                        eprintln!("h3 poll: {err:?}");
                        explain(current);
                        return ExitCode::from(1);
                    }
                }
            }
        }
        flush(&socket, current, &mut out);
        if served {
            let grace = Instant::now() + Duration::from_secs(2);
            while Instant::now() < grace && !current.is_closed() {
                pump_once(&socket, current, &mut out, Duration::from_millis(50));
            }
            return ExitCode::SUCCESS;
        }
        if current.is_closed() {
            explain(current);
            return ExitCode::from(1);
        }
    }
    eprintln!("h3 server timed out");
    ExitCode::from(1)
}

fn die(message: &str) -> ! {
    eprintln!("{message}");
    std::process::exit(1);
}

fn ext_config() -> quiche::Config {
    let mut config = config();
    // RFC 9221. quiche advertises max_datagram_frame_size 65536.
    config.enable_dgram(true, 32, 32);
    config
}

fn h3_ext_config() -> quiche::h3::Config {
    let mut config = h3_config();
    // Server only. A client that sends this setting is rejected.
    config.enable_extended_connect(true);
    config
}

fn put_varint(out: &mut Vec<u8>, value: u64) {
    if value < 64 {
        out.push(value as u8);
    } else if value < 16384 {
        out.push(0x40 | ((value >> 8) as u8));
        out.push((value & 0xff) as u8);
    } else {
        die("varint does not fit in two bytes");
    }
}

fn get_varint(buf: &[u8]) -> Option<(u64, usize)> {
    if buf.is_empty() {
        return None;
    }
    let len = 1usize << (buf[0] >> 6);
    if buf.len() < len {
        return None;
    }
    let mut value = (buf[0] & 0x3f) as u64;
    for byte in &buf[1..len] {
        value = (value << 8) | *byte as u64;
    }
    Some((value, len))
}

fn send_flow_dgram(
    conn: &mut quiche::Connection,
    flow_id: u64,
    payload: &[u8],
) -> Result<(), quiche::Error> {
    let mut body = Vec::with_capacity(payload.len() + 2);
    put_varint(&mut body, flow_id);
    body.extend_from_slice(payload);
    conn.dgram_send(&body)
}

fn recv_flow_dgram(conn: &mut quiche::Connection) -> Result<Option<(u64, Vec<u8>)>, quiche::Error> {
    let mut buf = [0u8; 65535];
    match conn.dgram_recv(&mut buf) {
        Ok(n) => {
            let Some((flow, off)) = get_varint(&buf[..n]) else {
                die("HTTP datagram is not a quarter stream id");
            };
            Ok(Some((flow, buf[off..n].to_vec())))
        }
        Err(quiche::Error::Done) => Ok(None),
        Err(err) => Err(err),
    }
}

fn h3_ext_client(mut args: impl Iterator<Item = String>) -> ExitCode {
    let peer_text = args.next().unwrap_or_default();
    let ca = args.next().unwrap_or_default();
    if peer_text.is_empty() || ca.is_empty() || args.next().is_some() {
        eprintln!("usage: quiche_peer h3-ext-client <host:port> <ca.pem>");
        return ExitCode::from(64);
    }
    let peer: SocketAddr = peer_text.parse().unwrap_or_else(|_| {
        die(&format!("not a socket address: {peer_text}"));
    });
    let mut config = ext_config();
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
    if !drive(&socket, &mut conn, &mut out) {
        explain(&conn);
        return ExitCode::from(1);
    }
    let cert_len = conn.peer_cert().map(|cert| cert.len()).unwrap_or(0);
    if cert_len == 0 {
        eprintln!("established with no peer certificate");
        return ExitCode::from(1);
    }
    // Do not enable_extended_connect here. RFC 9220: the client does
    // not send SETTINGS_ENABLE_CONNECT_PROTOCOL.
    let h3_config = h3_config();
    let mut h3 = match quiche::h3::Connection::with_transport(&mut conn, &h3_config) {
        Ok(http) => http,
        Err(err) => {
            eprintln!("h3: {err:?}");
            explain(&conn);
            return ExitCode::from(1);
        }
    };
    let request = [
        quiche::h3::Header::new(b":method", b"CONNECT"),
        quiche::h3::Header::new(b":protocol", b"websocket"),
        quiche::h3::Header::new(b":scheme", b"https"),
        quiche::h3::Header::new(b":authority", b"localhost"),
        quiche::h3::Header::new(b":path", b"/pq"),
    ];
    let mut sent = false;
    let mut stream_id = 0u64;
    let mut status = String::new();
    let mut saw_echo = false;
    let mut echo_at: Option<Instant> = None;
    let deadline = Instant::now() + Duration::from_secs(20);
    while Instant::now() < deadline && !conn.is_closed() {
        loop {
            match h3.poll(&mut conn) {
                Ok((id, quiche::h3::Event::Headers { list, .. })) => {
                    if sent && id == stream_id {
                        if let Some(value) = header_value(&list, b":status") {
                            status = String::from_utf8_lossy(value).into_owned();
                        }
                    }
                }
                Ok((id, quiche::h3::Event::Data)) => {
                    let mut buf = [0u8; 4096];
                    while h3.recv_body(&mut conn, id, &mut buf).is_ok() {}
                }
                Ok(_) => {}
                Err(quiche::h3::Error::Done) => break,
                Err(err) => {
                    eprintln!("h3 poll: {err:?}");
                    explain(&conn);
                    return ExitCode::from(1);
                }
            }
        }
        loop {
            match recv_flow_dgram(&mut conn) {
                Ok(Some((_, payload))) => {
                    if payload == b"qd-lost" {
                        eprintln!("retransmitted datagram qd-lost");
                        return ExitCode::from(1);
                    }
                    if payload == b"qd-pq" {
                        saw_echo = true;
                        echo_at.get_or_insert_with(Instant::now);
                    }
                }
                Ok(None) => break,
                Err(err) => {
                    eprintln!("dgram: {err:?}");
                    explain(&conn);
                    return ExitCode::from(1);
                }
            }
        }
        if !sent
            && h3.extended_connect_enabled_by_peer()
            && h3.dgram_enabled_by_peer(&conn)
        {
            match h3.send_request(&mut conn, &request, false) {
                Ok(id) => {
                    stream_id = id;
                    if let Err(err) = h3.send_priority_update_for_request(
                        &mut conn,
                        id,
                        &quiche::h3::Priority::new(1, true),
                    ) {
                        eprintln!("priority: {err:?}");
                        explain(&conn);
                        return ExitCode::from(1);
                    }
                    if let Err(err) = send_flow_dgram(&mut conn, id / 4, b"qd-quiche") {
                        eprintln!("dgram send: {err:?}");
                        explain(&conn);
                        return ExitCode::from(1);
                    }
                    sent = true;
                }
                Err(quiche::h3::Error::StreamBlocked) | Err(quiche::h3::Error::Done) => {}
                Err(err) => {
                    eprintln!("h3 send: {err:?}");
                    explain(&conn);
                    return ExitCode::from(1);
                }
            }
        }
        flush(&socket, &mut conn, &mut out);
        if sent && status == "200" && saw_echo {
            let since = echo_at.unwrap_or_else(Instant::now);
            if since.elapsed() >= Duration::from_secs(2) {
                println!(
                    "h3-ext status=200 protocol=websocket dgram=qd-pq lost=0 peer_cert={cert_len}"
                );
                let _ = io::stdout().flush();
                return ExitCode::SUCCESS;
            }
        }
        let wait = conn
            .timeout()
            .unwrap_or(Duration::from_millis(50))
            .min(Duration::from_millis(50));
        pump_once(&socket, &mut conn, &mut out, wait);
    }
    eprintln!(
        "h3-ext client timed out sent={sent} status={status} echo={saw_echo} connect={} dgram={}",
        h3.extended_connect_enabled_by_peer(),
        h3.dgram_enabled_by_peer(&conn)
    );
    explain(&conn);
    ExitCode::from(1)
}

fn h3_ext_server(mut args: impl Iterator<Item = String>) -> ExitCode {
    let port_text = args.next().unwrap_or_default();
    let cert = args.next().unwrap_or_default();
    let key = args.next().unwrap_or_default();
    if port_text.is_empty() || cert.is_empty() || key.is_empty() || args.next().is_some() {
        eprintln!("usage: quiche_peer h3-ext-server <port> <cert.pem> <key.pem>");
        return ExitCode::from(64);
    }
    let port: u16 = port_text.parse().unwrap_or_else(|_| die(&format!("not a port: {port_text}")));
    let mut config = ext_config();
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
    let h3_config = h3_ext_config();
    let mut buf = [0u8; 65535];
    let mut out = [0u8; 65535];
    let deadline = Instant::now() + Duration::from_secs(25);
    let mut conn: Option<quiche::Connection> = None;
    let mut http: Option<quiche::h3::Connection> = None;
    let mut echo_at: Option<Instant> = None;
    while Instant::now() < deadline {
        let wait = Duration::from_millis(50);
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
                let info = quiche::RecvInfo { to: local, from };
                match current.recv(&mut buf[..len], info) {
                    Ok(_) => {}
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
        let Some(current) = conn.as_mut() else {
            continue;
        };
        if current.is_established() && http.is_none() {
            match quiche::h3::Connection::with_transport(current, &h3_config) {
                Ok(created) => http = Some(created),
                Err(err) => {
                    eprintln!("h3: {err:?}");
                    explain(current);
                    return ExitCode::from(1);
                }
            }
        }
        if let Some(session) = http.as_mut() {
            loop {
                match session.poll(current) {
                    Ok((stream, quiche::h3::Event::Headers { list, .. })) => {
                        let method = header_value(&list, b":method").unwrap_or(b"");
                        let path = header_value(&list, b":path").unwrap_or(b"");
                        let protocol = header_value(&list, b":protocol").unwrap_or(b"");
                        println!(
                            "h3-ext request method={} protocol={} path={}",
                            String::from_utf8_lossy(method),
                            String::from_utf8_lossy(protocol),
                            String::from_utf8_lossy(path)
                        );
                        let _ = io::stdout().flush();
                        if method != b"CONNECT" || protocol != b"websocket" || path != b"/pq" {
                            eprintln!("unexpected extended CONNECT");
                            return ExitCode::from(1);
                        }
                        let response = [quiche::h3::Header::new(b":status", b"200")];
                        if let Err(err) = session.send_response(current, stream, &response, false) {
                            eprintln!("h3 response: {err:?}");
                            explain(current);
                            return ExitCode::from(1);
                        }
                    }
                    Ok((id, quiche::h3::Event::PriorityUpdate)) => {
                        match session.take_last_priority_update(id) {
                            Ok(value) => {
                                println!("priority={}", String::from_utf8_lossy(&value));
                                let _ = io::stdout().flush();
                            }
                            Err(quiche::h3::Error::Done) => {}
                            Err(err) => {
                                eprintln!("priority: {err:?}");
                                return ExitCode::from(1);
                            }
                        }
                    }
                    Ok((stream, quiche::h3::Event::Data)) => {
                        let mut discard = [0u8; 4096];
                        while session.recv_body(current, stream, &mut discard).is_ok() {}
                    }
                    Ok(_) => {}
                    Err(quiche::h3::Error::Done) => break,
                    Err(err) => {
                        eprintln!("h3 poll: {err:?}");
                        explain(current);
                        return ExitCode::from(1);
                    }
                }
            }
            loop {
                match recv_flow_dgram(current) {
                    Ok(Some((flow, payload))) => {
                        if payload == b"qd-lost" {
                            println!("dgram=qd-lost");
                            let _ = io::stdout().flush();
                            return ExitCode::from(1);
                        }
                        if payload == b"qd-pq" {
                            println!("dgram=qd-pq");
                            let _ = io::stdout().flush();
                            if let Err(err) = send_flow_dgram(current, flow, b"qd-quiche") {
                                eprintln!("dgram echo: {err:?}");
                                return ExitCode::from(1);
                            }
                            echo_at.get_or_insert_with(Instant::now);
                        }
                    }
                    Ok(None) => break,
                    Err(err) => {
                        eprintln!("dgram: {err:?}");
                        return ExitCode::from(1);
                    }
                }
            }
        }
        flush(&socket, current, &mut out);
        if let Some(since) = echo_at {
            if since.elapsed() >= Duration::from_secs(2) {
                return ExitCode::SUCCESS;
            }
        }
        if current.is_closed() {
            explain(current);
            return ExitCode::from(1);
        }
    }
    eprintln!("h3-ext server timed out");
    ExitCode::from(1)
}
