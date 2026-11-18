//! noq client against a pqtransport QUIC server.
//!
//! The process trusts one PEM trust anchor, offers multipath
//! (`max_concurrent_multipath_paths(2)`, so `initial_max_path_id` is 1),
//! and opens a second path to the same server address. Exit 0 only when
//! the handshake completed, multipath was negotiated, and path 1 was
//! established. rustls on aws-lc-rs checked the certificate.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use noq::{ClientConfig, Endpoint, FourTuple, PathStatus, TransportConfig};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::CertificateDer;

fn main_trace() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .try_init();
}

#[tokio::main]
async fn main() {
    main_trace();
    let mut args = std::env::args().skip(1);
    let Some(host_port) = args.next() else {
        eprintln!("usage: pq_noq_client <host:port> <ca.pem>");
        std::process::exit(64);
    };
    let Some(ca_path) = args.next() else {
        eprintln!("usage: pq_noq_client <host:port> <ca.pem>");
        std::process::exit(64);
    };
    let server: SocketAddr = host_port.parse().unwrap_or_else(|_| {
        eprintln!("bad address {host_port}");
        std::process::exit(64);
    });
    let ca = CertificateDer::from_pem_file(&ca_path).unwrap_or_else(|err| {
        eprintln!("ca pem: {err}");
        std::process::exit(1);
    });
    let mut roots = rustls::RootCertStore::empty();
    roots.add(ca).unwrap_or_else(|err| {
        eprintln!("ca rejected: {err}");
        std::process::exit(1);
    });
    let mut transport = TransportConfig::default();
    transport.max_concurrent_multipath_paths(2);
    let mut rustls_config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_root_certificates(roots)
    .with_no_client_auth();
    rustls_config.alpn_protocols = vec![b"h3".to_vec()];
    let quic = noq::crypto::rustls::QuicClientConfig::try_from(rustls_config).unwrap_or_else(|err| {
        eprintln!("quic crypto: {err}");
        std::process::exit(1);
    });
    let mut config = ClientConfig::new(Arc::new(quic));
    config.transport_config(Arc::new(transport));
    let endpoint = Endpoint::client("0.0.0.0:0".parse().unwrap()).unwrap_or_else(|err| {
        eprintln!("bind: {err}");
        std::process::exit(1);
    });
    endpoint.set_default_client_config(config);
    let connecting = endpoint.connect(server, "localhost").unwrap_or_else(|err| {
        eprintln!("connect: {err}");
        std::process::exit(1);
    });
    let conn = match tokio::time::timeout(Duration::from_secs(8), connecting).await {
        Ok(Ok(conn)) => conn,
        Ok(Err(err)) => {
            eprintln!("handshake: {err}");
            std::process::exit(1);
        }
        Err(_) => {
            eprintln!("handshake timed out");
            std::process::exit(1);
        }
    };
    if !conn.is_multipath_enabled() {
        eprintln!("multipath not negotiated");
        std::process::exit(1);
    }
    // PATH_NEW_CONNECTION_ID is 1-RTT. The handshake future resolves
    // before that frame has to have arrived. open_path fails at once
    // until the server has issued a connection ID for the new path.
    let mut opened = None;
    let wait_started = std::time::Instant::now();
    while wait_started.elapsed() < Duration::from_secs(5) {
        let attempt = conn.open_path(FourTuple::from_remote(server), PathStatus::Available);
        if attempt.path_id().is_some() {
            opened = Some(attempt);
            break;
        }
        match tokio::time::timeout(Duration::from_millis(20), attempt).await {
            Ok(Err(err)) if err.to_string().contains("CIDs exhausted") => {
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            Ok(Err(err)) => {
                eprintln!("open_path: {err}");
                std::process::exit(1);
            }
            Ok(Ok(_)) => {
                eprintln!("open_path resolved without a path id");
                std::process::exit(1);
            }
            Err(_) => {}
        }
    }
    let Some(opened) = opened else {
        eprintln!("open_path: no remote connection id");
        std::process::exit(1);
    };
    let path_id = opened.path_id();
    let path = match tokio::time::timeout(Duration::from_secs(5), opened).await {
        Ok(Ok(path)) => path,
        Ok(Err(err)) => {
            eprintln!("open_path id={path_id:?}: {err}");
            std::process::exit(1);
        }
        Err(_) => {
            eprintln!("open_path timed out id={path_id:?}");
            std::process::exit(1);
        }
    };
    println!(
        "noq-mp handshake=ok multipath=1 path={} remote={}",
        path.id(),
        path.remote_address()
            .map(|addr| addr.to_string())
            .unwrap_or_else(|_| "none".to_string())
    );
    conn.close(0u32.into(), b"done");
    let _ = tokio::time::timeout(Duration::from_secs(2), endpoint.wait_idle()).await;
}
