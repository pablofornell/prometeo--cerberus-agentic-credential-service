//! TLS 1.3 only, plain HTTP refused (A8), CA export and pin, client certificates, LAN bind rule.
#![allow(
    missing_docs,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test code"
)]

mod common;

use std::sync::Arc;
use std::time::Duration;

use cerberus_api::tls::{CaExport, LocalCa, write_leaf};
use cerberus_api::{ApiConfig, AppState, ServerError, router, start};
use cerberus_types::{Clock, SystemClock, VaultId};
use common::{Client, Fixture, Options, client_config};
use rustls::pki_types::ServerName;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

#[tokio::test]
async fn a8_tls12_only_client_fails_the_handshake() {
    let fx = Fixture::new().await;
    let config = client_config(&fx.ca_der, &[&rustls::version::TLS12], None);
    let tcp = TcpStream::connect(fx.addr).await.expect("tcp");
    let result = TlsConnector::from(config)
        .connect(ServerName::try_from("localhost").expect("name"), tcp)
        .await;
    let error = result.expect_err("TLS 1.2 must fail");
    assert!(
        error.to_string().to_lowercase().contains("protocol")
            || error.to_string().contains("alert"),
        "{error}"
    );
    fx.stop().await;
}

#[tokio::test]
async fn a8_plain_http_is_refused() {
    let fx = Fixture::new().await;
    let mut tcp = TcpStream::connect(fx.addr).await.expect("tcp");
    tcp.write_all(b"GET /v1/health HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await
        .expect("write");
    let mut got = Vec::new();
    let read = tokio::time::timeout(Duration::from_secs(5), tcp.read_to_end(&mut got)).await;
    assert!(read.is_ok(), "the server must close the connection");
    assert!(
        !String::from_utf8_lossy(&got).contains("HTTP/1"),
        "no HTTP answer on a plain connection"
    );
    assert!(!String::from_utf8_lossy(&got).contains("ok"), "no data");
    fx.stop().await;
}

#[tokio::test]
async fn a_client_that_offers_both_versions_gets_tls13() {
    let fx = Fixture::new().await;
    let config = client_config(
        &fx.ca_der,
        &[&rustls::version::TLS13, &rustls::version::TLS12],
        None,
    );
    let tcp = TcpStream::connect(fx.addr).await.expect("tcp");
    let tls = TlsConnector::from(config)
        .connect(ServerName::try_from("localhost").expect("name"), tcp)
        .await
        .expect("handshake");
    assert_eq!(
        tls.get_ref().1.protocol_version(),
        Some(rustls::ProtocolVersion::TLSv1_3)
    );
    fx.stop().await;
}

#[tokio::test]
async fn a_client_with_another_ca_does_not_trust_the_server() {
    let fx = Fixture::new().await;
    let other = LocalCa::create(&VaultId::generate(), SystemClock.now()).expect("ca");
    let client = Client::new(fx.addr, other.cert_der(), None);
    assert!(client.connect().await.is_err());
    fx.stop().await;
}

#[tokio::test]
async fn the_leaf_works_while_the_vault_is_locked_and_the_files_are_private() {
    let fx = Fixture::new().await;
    fx.lock().await;
    let resp = fx.client().send("GET", "/v1/health", None, &[], None).await;
    assert_eq!(resp.status, 200);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let key = std::fs::metadata(&fx.tls.leaf_key_der)
            .expect("key")
            .permissions()
            .mode();
        assert_eq!(key & 0o777, 0o600);
        let dir = std::fs::metadata(fx.tls.leaf_key_der.parent().expect("dir")).expect("dir");
        assert_eq!(dir.permissions().mode() & 0o777, 0o700);
    }
    fx.stop().await;
}

#[tokio::test]
async fn ca_export_has_pem_pin_and_fingerprint() {
    let fx = Fixture::new().await;
    let export = CaExport::from_der(&fx.ca_der).expect("export");
    assert!(export.pem.starts_with("-----BEGIN CERTIFICATE-----\n"));
    assert!(export.pem.ends_with("-----END CERTIFICATE-----\n"));
    let body: String = export
        .pem
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .collect();
    assert_eq!(
        data_encoding::BASE64
            .decode(body.as_bytes())
            .expect("base64"),
        fx.ca_der
    );
    assert!(
        export
            .pem
            .lines()
            .all(|l| l.len() <= 64 || l.starts_with("-----"))
    );
    let pin = export.pin.strip_prefix("sha256/").expect("prefix");
    assert_eq!(
        data_encoding::BASE64
            .decode(pin.as_bytes())
            .expect("b64")
            .len(),
        32
    );
    assert_eq!(export.cert_sha256_hex.len(), 64);
    fx.stop().await;
}

#[tokio::test]
async fn leaf_renewal_keeps_the_pin_and_needs_no_restart() {
    let fx = Fixture::with(Options {
        keep_ca: true,
        ..Options::default()
    })
    .await;
    let ca = Arc::clone(fx.ca.as_ref().expect("ca"));
    let pin_before = CaExport::from_der(&fx.ca_der).expect("export").pin;
    let ca_der = fx.ca_der.clone();
    let peer = |addr| {
        let ca_der = ca_der.clone();
        async move {
            let config = client_config(&ca_der, &[&rustls::version::TLS13], None);
            let tcp = TcpStream::connect(addr).await.expect("tcp");
            let tls = TlsConnector::from(config)
                .connect(ServerName::try_from("localhost").expect("name"), tcp)
                .await
                .expect("handshake");
            tls.get_ref().1.peer_certificates().expect("certs")[0]
                .as_ref()
                .to_vec()
        }
    };
    let before = peer(fx.addr).await;
    let leaf = ca
        .issue_leaf(&cerberus_api::tls::leaf_names(&[]), SystemClock.now())
        .expect("leaf");
    write_leaf(&fx.tls, &leaf).expect("write");
    fx.server
        .as_ref()
        .expect("server")
        .reload_leaf()
        .expect("reload");
    let after = peer(fx.addr).await;
    assert_ne!(before, after, "the server presents the new leaf");
    assert_eq!(after, leaf.cert_der);
    assert_eq!(
        CaExport::from_der(&fx.ca_der).expect("export").pin,
        pin_before
    );
    assert_eq!(
        fx.client()
            .send("GET", "/v1/health", None, &[], None)
            .await
            .status,
        200
    );
    fx.stop().await;
}

async fn mtls_fixture(require: bool) -> (Fixture, Client) {
    let fx = Fixture::with(Options {
        keep_ca: true,
        client_ca: true,
        require_client_cert: require,
        ..Options::default()
    })
    .await;
    let ca = Arc::clone(fx.ca.as_ref().expect("ca"));
    let cert = ca
        .issue_client(fx.agent, SystemClock.now())
        .expect("client cert");
    fx.core
        .bind_client_cert(&common::op_ctx(&fx.owner), fx.key_id, cert.sha256())
        .await
        .expect("bind");
    let client = Client::new(
        fx.addr,
        &fx.ca_der,
        Some((cert.cert_der.clone(), cert.key_der.expose_secret().to_vec())),
    );
    (fx, client)
}

#[tokio::test]
async fn a_key_bound_to_a_client_cert_needs_that_cert() {
    let (fx, with_cert) = mtls_fixture(false).await;
    // With the certificate: fine.
    assert_eq!(with_cert.get("/v1/status", &fx.token).await.status, 200);
    // Without it: the same 401 as any bad credential.
    let resp = fx.client().get("/v1/status", &fx.token).await;
    common::assert_error_shape(&resp, 401, "unauthenticated");
    // A certificate from another CA does not pass the handshake.
    let other = LocalCa::create(&VaultId::generate(), SystemClock.now()).expect("ca");
    let stranger = other
        .issue_client(fx.agent, SystemClock.now())
        .expect("cert");
    let client = Client::new(
        fx.addr,
        &fx.ca_der,
        Some((
            stranger.cert_der.clone(),
            stranger.key_der.expose_secret().to_vec(),
        )),
    );
    let failed = match client.connect().await {
        Err(_) => true,
        Ok(mut sender) => {
            let request = hyper::Request::builder()
                .uri("/v1/health")
                .header("host", "localhost")
                .body(common::http_body_util_lite::Full::new(""))
                .expect("request");
            sender.send_request(request).await.is_err()
        }
    };
    assert!(failed, "a client cert of another CA must not get an answer");
    fx.stop().await;
}

#[tokio::test]
async fn required_client_cert_fails_the_handshake_without_one() {
    let (fx, with_cert) = mtls_fixture(true).await;
    assert_eq!(with_cert.get("/v1/status", &fx.token).await.status, 200);
    let bare = fx.client();
    let failed = match bare.connect().await {
        Err(_) => true,
        Ok(mut sender) => {
            let request = hyper::Request::builder()
                .uri("/v1/health")
                .header("host", "localhost")
                .body(common::http_body_util_lite::Full::new(""))
                .expect("request");
            sender.send_request(request).await.is_err()
        }
    };
    assert!(failed, "no certificate, no connection");
    fx.stop().await;
}

#[tokio::test]
async fn a_lan_bind_needs_mandatory_client_certs() {
    let fx = Fixture::new().await;
    let mut config = ApiConfig::loopback(fx.tls.clone());
    config.bind = vec!["0.0.0.0:0".parse().expect("addr")];
    assert!(matches!(
        config.validate(),
        Err(ServerError::LanBindNeedsMtls)
    ));
    config.client_ca_der = Some(fx.ca_der.clone());
    assert!(
        matches!(config.validate(), Err(ServerError::LanBindNeedsMtls)),
        "optional is not enough"
    );
    config.require_client_cert = true;
    assert!(config.validate().is_ok());
    config.require_client_cert = false;
    let state = AppState::new(fx.core.clone(), &config);
    let refused = start(&config, state.clone(), router(&state)).await;
    assert!(matches!(refused, Err(ServerError::LanBindNeedsMtls)));
    config.bind = vec![];
    assert!(matches!(config.validate(), Err(ServerError::NoBind)));
    fx.stop().await;
}

#[tokio::test]
async fn a_lan_bind_works_with_client_certs() {
    let fx = Fixture::with(Options {
        keep_ca: true,
        client_ca: true,
        require_client_cert: true,
        bind_lan: true,
        ..Options::default()
    })
    .await;
    assert!(fx.addr.ip().is_unspecified());
    let ca = Arc::clone(fx.ca.as_ref().expect("ca"));
    let cert = ca.issue_client(fx.agent, SystemClock.now()).expect("cert");
    let addr = std::net::SocketAddr::new(std::net::Ipv4Addr::LOCALHOST.into(), fx.addr.port());
    let client = Client::new(
        addr,
        &fx.ca_der,
        Some((cert.cert_der.clone(), cert.key_der.expose_secret().to_vec())),
    );
    assert_eq!(
        client
            .send("GET", "/v1/health", None, &[], None)
            .await
            .status,
        200
    );
    fx.stop().await;
}

#[tokio::test]
async fn shutdown_closes_the_listener() {
    let fx = Fixture::new().await;
    let addr = fx.addr;
    let client = fx.client();
    assert_eq!(
        client
            .send("GET", "/v1/health", None, &[], None)
            .await
            .status,
        200
    );
    fx.stop().await;
    assert!(TcpStream::connect(addr).await.is_err());
}

#[tokio::test]
async fn http2_works_and_the_host_check_uses_the_authority() {
    let fx = Fixture::new().await;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(rustls::pki_types::CertificateDer::from(fx.ca_der.clone()))
        .expect("root");
    let mut config = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("versions")
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"h2".to_vec()];
    let tcp = TcpStream::connect(fx.addr).await.expect("tcp");
    let tls = TlsConnector::from(Arc::new(config))
        .connect(ServerName::try_from("localhost").expect("name"), tcp)
        .await
        .expect("handshake");
    assert_eq!(tls.get_ref().1.alpn_protocol(), Some(&b"h2"[..]));
    let (mut sender, conn) = hyper::client::conn::http2::handshake(
        hyper_util::rt::TokioExecutor::new(),
        hyper_util::rt::TokioIo::new(tls),
    )
    .await
    .expect("h2");
    tokio::spawn(async move {
        drop(conn.await);
    });
    for (authority, status) in [("localhost", 200), ("rebind.example", 403)] {
        let request = hyper::Request::builder()
            .uri(format!("https://{authority}/v1/health"))
            .body(common::http_body_util_lite::Full::new(""))
            .expect("request");
        let response = sender.send_request(request).await.expect("send");
        assert_eq!(response.status(), status, "{authority}");
    }
    fx.stop().await;
}

/// The chain the server sends: every certificate, DER.
async fn served_chain(addr: std::net::SocketAddr, ca_der: &[u8]) -> Vec<Vec<u8>> {
    let config = client_config(ca_der, &[&rustls::version::TLS13], None);
    let tcp = TcpStream::connect(addr).await.expect("tcp");
    let tls = TlsConnector::from(config)
        .connect(ServerName::try_from("localhost").expect("name"), tcp)
        .await
        .expect("handshake");
    tls.get_ref()
        .1
        .peer_certificates()
        .expect("certs")
        .iter()
        .map(|c| c.as_ref().to_vec())
        .collect()
}

/// DEC-FIX8-1: the server sends [leaf, CA], so a client that trusts only the pinned CA can check it.
#[tokio::test]
async fn the_server_sends_the_leaf_and_the_ca() {
    let fx = Fixture::new().await;
    let chain = served_chain(fx.addr, &fx.ca_der).await;
    assert_eq!(chain.len(), 2);
    assert_eq!(chain[1], fx.ca_der, "the CA follows the leaf");
    fx.stop().await;
}

/// DEC-FIX7-12: at unlock the server renews a leaf near its end with the vault CA and serves it
/// with no restart.
#[tokio::test]
async fn the_leaf_is_renewed_at_unlock() {
    let fx = Fixture::with(Options {
        keep_ca: true,
        ..Options::default()
    })
    .await;
    let ca = Arc::clone(fx.ca.as_ref().expect("ca"));
    let server = fx.server.as_ref().expect("server");
    // A leaf made 80 days ago has 10 days left: less than the 30-day renewal margin.
    let old_start = SystemClock.now() - jiff::SignedDuration::from_hours(80 * 24);
    let old = ca
        .issue_leaf(&cerberus_api::tls::leaf_names(&[]), old_start)
        .expect("old leaf");
    write_leaf(&fx.tls, &old).expect("write");
    server.reload_leaf().expect("reload");
    fx.lock().await;
    let task = server.spawn_leaf_renewal(fx.core.clone(), fx.tls.clone(), Vec::new());
    let ca_der = fx.ca_der.clone();
    let addr = fx.addr;
    let peer = || {
        let ca_der = ca_der.clone();
        async move {
            let config = client_config(&ca_der, &[&rustls::version::TLS13], None);
            let tcp = TcpStream::connect(addr).await.expect("tcp");
            let tls = TlsConnector::from(config)
                .connect(ServerName::try_from("localhost").expect("name"), tcp)
                .await
                .expect("handshake");
            tls.get_ref().1.peer_certificates().expect("certs")[0]
                .as_ref()
                .to_vec()
        }
    };
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(peer().await, old.cert_der, "no renewal while locked");
    fx.unlock().await;
    let mut served = peer().await;
    for _ in 0..50 {
        if served != old.cert_der {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
        served = peer().await;
    }
    assert_ne!(served, old.cert_der, "the leaf was renewed at unlock");
    let (_, cert) = x509_parser::parse_x509_certificate(&served).expect("parse");
    let days_left =
        (cert.validity().not_after.timestamp() - SystemClock.now().as_second()) / 86_400;
    assert!(days_left > 80, "fresh leaf: {days_left} days left");
    let chain = served_chain(addr, &ca_der).await;
    assert_eq!(chain.len(), 2, "the renewed chain keeps the CA");
    assert_eq!(chain[1], ca_der);
    task.abort();
    fx.stop().await;
}

/// DEC-FIX8-3: a request that never ends does not outlive `shutdown`: after the grace time the
/// connection is cut.
#[tokio::test]
async fn shutdown_cuts_a_connection_with_a_request_in_flight() {
    let fx = Fixture::new().await;
    let mut config = ApiConfig::loopback(fx.tls.clone());
    config.bind = vec!["127.0.0.1:0".parse().expect("addr")];
    config.limits.shutdown_grace = Duration::from_millis(300);
    let state = AppState::new(fx.core.clone(), &config);
    let app = router(&state).route(
        "/slow",
        axum::routing::get(std::future::pending::<&'static str>),
    );
    let server = start(&config, state, app).await.expect("start");
    let addr = server.local_addrs()[0];
    let tcp = TcpStream::connect(addr).await.expect("tcp");
    let mut tls = TlsConnector::from(client_config(&fx.ca_der, &[&rustls::version::TLS13], None))
        .connect(ServerName::try_from("localhost").expect("name"), tcp)
        .await
        .expect("handshake");
    tls.write_all(b"GET /slow HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await
        .expect("write");
    tokio::time::sleep(Duration::from_millis(200)).await;
    tokio::time::timeout(Duration::from_secs(5), server.shutdown())
        .await
        .expect("shutdown ends");
    let mut buf = [0u8; 64];
    let read = tokio::time::timeout(Duration::from_secs(2), tls.read(&mut buf))
        .await
        .expect("the connection was cut");
    assert!(matches!(read, Ok(0) | Err(_)));
    fx.stop().await;
}

async fn server_with(
    fx: &Fixture,
    edit: impl FnOnce(&mut ApiConfig),
) -> (cerberus_api::RunningServer, std::net::SocketAddr) {
    let mut config = ApiConfig::loopback(fx.tls.clone());
    config.bind = vec!["127.0.0.1:0".parse().expect("addr")];
    edit(&mut config);
    let state = AppState::new(fx.core.clone(), &config);
    let server = start(&config, state.clone(), router(&state))
        .await
        .expect("start");
    let addr = server.local_addrs()[0];
    (server, addr)
}

async fn tls_connect(
    addr: std::net::SocketAddr,
    ca_der: &[u8],
) -> tokio_rustls::client::TlsStream<TcpStream> {
    let tcp = TcpStream::connect(addr).await.expect("tcp");
    TlsConnector::from(client_config(ca_der, &[&rustls::version::TLS13], None))
        .connect(ServerName::try_from("localhost").expect("name"), tcp)
        .await
        .expect("handshake")
}

/// AUD-4: a client that finishes the TLS handshake and then sends nothing is closed after the
/// first-request time. hyper's `header_read_timeout` alone does not fire for this case.
#[tokio::test]
async fn aud4_a_silent_tls_connection_is_closed() {
    let fx = Fixture::new().await;
    let (server, addr) = server_with(&fx, |config| {
        config.limits.header_timeout = Duration::from_millis(300);
    })
    .await;
    let mut tls = tls_connect(addr, &fx.ca_der).await;
    let mut buf = [0u8; 64];
    let read = tokio::time::timeout(Duration::from_secs(5), tls.read(&mut buf))
        .await
        .expect("the silent connection was closed by the server");
    assert!(matches!(read, Ok(0) | Err(_)));
    server.shutdown().await;
    fx.stop().await;
}

/// AUD-4: an authenticated connection that sent one request and is then idle is closed after the
/// idle time, but a request that is still running is not cut.
#[tokio::test]
async fn aud4_an_idle_keep_alive_connection_is_closed_but_a_running_request_is_not() {
    let fx = Fixture::new().await;
    let mut config = ApiConfig::loopback(fx.tls.clone());
    config.bind = vec!["127.0.0.1:0".parse().expect("addr")];
    config.limits.idle_timeout = Duration::from_millis(400);
    let state = AppState::new(fx.core.clone(), &config);
    let nap = axum::Router::new().route(
        "/nap",
        axum::routing::get(|| async {
            tokio::time::sleep(Duration::from_millis(1200)).await;
            "ok"
        }),
    );
    let app = router(&state).merge(cerberus_api::agent_layers(&state, nap));
    let server = start(&config, state, app).await.expect("start");
    let addr = server.local_addrs()[0];
    let mut tls = tls_connect(addr, &fx.ca_der).await;
    let request = format!(
        "GET /nap HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {}\r\n\r\n",
        fx.token
    );
    tls.write_all(request.as_bytes()).await.expect("write");
    let mut seen = Vec::new();
    let mut buf = [0u8; 512];
    // The request runs three times longer than the idle time and still gets its answer.
    while !seen.ends_with(b"ok") {
        let n = tokio::time::timeout(Duration::from_secs(5), tls.read(&mut buf))
            .await
            .expect("read")
            .expect("the running request was not cut");
        assert!(n > 0, "closed before the answer");
        seen.extend_from_slice(&buf[..n]);
    }
    assert!(String::from_utf8_lossy(&seen).starts_with("HTTP/1.1 200"));
    // Now the connection is idle and the server closes it.
    let read = tokio::time::timeout(Duration::from_secs(5), tls.read(&mut buf))
        .await
        .expect("the idle connection was closed");
    assert!(matches!(read, Ok(0) | Err(_)));
    server.shutdown().await;
    fx.stop().await;
}

/// The HTTP/2 connection preface. The version check of the server waits for all 24 bytes.
const H2_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

type ReadSide = tokio::io::ReadHalf<tokio_rustls::client::TlsStream<TcpStream>>;

/// Sends the h2 preface one byte per `every`, then stops. The bytes never make a request.
fn trickle(tls: tokio_rustls::client::TlsStream<TcpStream>, every: Duration) -> ReadSide {
    let (read, mut write) = tokio::io::split(tls);
    tokio::spawn(async move {
        for byte in H2_PREFACE {
            if write.write_all(&[*byte]).await.is_err() || write.flush().await.is_err() {
                return;
            }
            tokio::time::sleep(every).await;
        }
        // Keep the write side open, so only the server can end the connection.
        std::future::pending::<()>().await;
    });
    read
}

/// True when the server ends the connection within `wait`.
async fn closed_within(read: &mut (impl tokio::io::AsyncRead + Unpin), wait: Duration) -> bool {
    let mut buf = [0u8; 256];
    let ends = async {
        loop {
            match read.read(&mut buf).await {
                Ok(0) | Err(_) => return,
                Ok(_) => {}
            }
        }
    };
    tokio::time::timeout(wait, ends).await.is_ok()
}

/// AUD-4 (re-check): one byte at a time does not keep a connection. The preface trickle would last
/// 24 x 150 ms; the first request head is due after 500 ms, and the bytes do not move that.
#[tokio::test]
async fn aud4_a_byte_trickling_client_is_closed() {
    let fx = Fixture::new().await;
    let (server, addr) = server_with(&fx, |config| {
        config.limits.header_timeout = Duration::from_millis(500);
        config.limits.idle_timeout = Duration::from_secs(30);
    })
    .await;
    let mut read = trickle(
        tls_connect(addr, &fx.ca_der).await,
        Duration::from_millis(150),
    );
    assert!(
        closed_within(&mut read, Duration::from_secs(3)).await,
        "the trickling connection was kept"
    );
    server.shutdown().await;
    fx.stop().await;
}

/// AUD-4 (re-check): an HTTP/2 client that sends PING frames and no request is closed.
#[tokio::test]
async fn aud4_an_http2_client_that_only_sends_pings_is_closed() {
    let fx = Fixture::new().await;
    let (server, addr) = server_with(&fx, |config| {
        config.limits.header_timeout = Duration::from_millis(500);
        config.limits.idle_timeout = Duration::from_secs(30);
    })
    .await;
    let mut config = (*client_config(&fx.ca_der, &[&rustls::version::TLS13], None)).clone();
    config.alpn_protocols = vec![b"h2".to_vec()];
    let tcp = TcpStream::connect(addr).await.expect("tcp");
    let tls = TlsConnector::from(Arc::new(config))
        .connect(ServerName::try_from("localhost").expect("name"), tcp)
        .await
        .expect("handshake");
    assert_eq!(tls.get_ref().1.alpn_protocol(), Some(&b"h2"[..]));
    let (_sender, conn) =
        hyper::client::conn::http2::Builder::new(hyper_util::rt::TokioExecutor::new())
            .timer(hyper_util::rt::TokioTimer::new())
            .keep_alive_interval(Duration::from_millis(100))
            .keep_alive_while_idle(true)
            .handshake::<_, common::http_body_util_lite::Full>(hyper_util::rt::TokioIo::new(tls))
            .await
            .expect("h2");
    // `conn` ends when the server closes the connection.
    let ended = tokio::time::timeout(Duration::from_secs(3), conn).await;
    assert!(ended.is_ok(), "the PING-only connection was kept");
    server.shutdown().await;
    fx.stop().await;
}

/// AUD-4: a connection with no authenticated request is closed at `auth_timeout`, even when it
/// keeps sending requests that need no token and even while such a request runs. A connection
/// that authenticated is not.
#[tokio::test]
async fn aud4_a_connection_without_an_authenticated_request_is_closed_at_the_auth_deadline() {
    let fx = Fixture::new().await;
    let mut config = ApiConfig::loopback(fx.tls.clone());
    config.bind = vec!["127.0.0.1:0".parse().expect("addr")];
    config.limits.auth_timeout = Duration::from_secs(1);
    let state = AppState::new(fx.core.clone(), &config);
    let app = router(&state).route(
        "/slow",
        axum::routing::get(std::future::pending::<&'static str>),
    );
    let server = start(&config, state, app).await.expect("start");
    let addr = server.local_addrs()[0];
    let client = common::Client::new(addr, &fx.ca_der, None);
    let host = format!("localhost:{}", addr.port());
    let get = |path: &str, token: Option<&str>| {
        let mut builder = hyper::Request::builder()
            .uri(path.to_owned())
            .header("host", host.clone());
        if let Some(token) = token {
            builder = builder.header("authorization", format!("Bearer {token}"));
        }
        builder
            .body(common::http_body_util_lite::Full::new(""))
            .expect("request")
    };
    // Health checks every 100 ms: progress, but never a token.
    let clock = cerberus_types::Stopwatch::start();
    let mut health = client.connect().await.expect("connect");
    let mut served = 0;
    while clock.elapsed() < Duration::from_secs(4) {
        match health.send_request(get("/v1/health", None)).await {
            Ok(response) => {
                assert_eq!(response.status(), 200);
                served += 1;
            }
            Err(_) => break,
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let lived = clock.elapsed();
    assert!(served > 3, "served {served}");
    assert!(
        lived >= Duration::from_millis(900) && lived < Duration::from_secs(3),
        "the unauthenticated connection lived {lived:?}"
    );
    // A running request that needs no token does not keep the connection either.
    let mut slow = client.connect().await.expect("connect");
    let cut = tokio::time::timeout(
        Duration::from_secs(3),
        slow.send_request(get("/slow", None)),
    )
    .await;
    assert!(
        matches!(cut, Ok(Err(_))),
        "the running unauthenticated request was kept"
    );
    // The same pattern with a token is served for longer than the deadline.
    let mut agent = client.connect().await.expect("connect");
    let clock = cerberus_types::Stopwatch::start();
    while clock.elapsed() < Duration::from_millis(1800) {
        let response = agent
            .send_request(get("/v1/status", Some(&fx.token)))
            .await
            .expect("the authenticated connection was kept");
        assert_eq!(response.status(), 200);
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    server.shutdown().await;
    fx.stop().await;
}

/// AUD-4: an SSE stream is a running request, so it outlives the idle time with no traffic (the
/// heartbeat comes only every 15 s).
#[tokio::test]
async fn aud4_an_event_stream_outlives_the_idle_time() {
    let fx = Fixture::new().await;
    let (server, addr) = server_with(&fx, |config| {
        config.limits.header_timeout = Duration::from_millis(300);
        config.limits.idle_timeout = Duration::from_millis(300);
    })
    .await;
    let prod = fx
        .core
        .create_item_as_operator(
            &common::op_ctx(&fx.owner),
            common::web_login(
                fx.workspace,
                "Shop admin prod",
                cerberus_types::Environment::Prod,
            ),
        )
        .await
        .expect("prod item")
        .summary
        .id;
    let client = common::Client::new(addr, &fx.ca_der, None);
    let body = serde_json::json!({
        "item_id": prod.to_string(),
        "reason": "Deploy check for the checkout page"
    })
    .to_string();
    let resp = client.post("/v1/requests", &fx.token, &body).await;
    assert_eq!(resp.status, 202, "{}", String::from_utf8_lossy(&resp.body));
    let id = resp.json()["id"].as_str().expect("id").to_owned();
    let (status, _, stream) = client
        .send_stream(
            "GET",
            &format!("/v1/requests/{id}/events"),
            Some(&fx.token),
            &[],
            None,
        )
        .await;
    assert_eq!(status, 200);
    let core = fx.core.clone();
    let owner = common::op_ctx(&fx.owner);
    let request_id: cerberus_types::AccessRequestId = id.parse().expect("id");
    tokio::spawn(async move {
        // Five idle times with no byte on the stream.
        tokio::time::sleep(Duration::from_millis(1500)).await;
        core.approve_request(&owner, request_id, cerberus_types::ApprovalOption::Once)
            .await
            .expect("approve");
    });
    let events = common::read_events(stream, 10, Duration::from_secs(10)).await;
    assert_eq!(events.len(), 2, "{events:?}");
    assert_eq!(events[1].1["status"], "approved");
    server.shutdown().await;
    fx.stop().await;
}

/// GET `/v1/status` with the token on an open connection.
async fn status_on(
    sender: &mut hyper::client::conn::http1::SendRequest<common::http_body_util_lite::Full>,
    addr: std::net::SocketAddr,
    token: &str,
) -> u16 {
    let request = hyper::Request::builder()
        .uri("/v1/status")
        .header("host", format!("localhost:{}", addr.port()))
        .header("authorization", format!("Bearer {token}"))
        .body(common::http_body_util_lite::Full::new(""))
        .expect("request");
    sender
        .send_request(request)
        .await
        .expect("send")
        .status()
        .as_u16()
}

/// AUD-4 and NEW-1: silent and trickling clients hold every connection slot, and the deadlines
/// are long. An agent with a token still connects at once (the oldest unauthenticated connection
/// gives way), and once it has authenticated, more such clients never push it out.
#[tokio::test]
async fn aud4_an_agent_gets_in_while_unauthenticated_clients_hold_every_slot() {
    let fx = Fixture::new().await;
    let (server, addr) = server_with(&fx, |config| {
        config.limits.max_connections = 4;
        config.limits.header_timeout = Duration::from_secs(30);
        config.limits.idle_timeout = Duration::from_secs(30);
    })
    .await;
    let mut held = Vec::new();
    let mut trickling = Vec::new();
    for _ in 0..2 {
        held.push(tls_connect(addr, &fx.ca_der).await);
        trickling.push(trickle(
            tls_connect(addr, &fx.ca_der).await,
            Duration::from_millis(200),
        ));
    }
    let client = common::Client::new(addr, &fx.ca_der, None);
    let mut agent = tokio::time::timeout(Duration::from_secs(3), client.connect())
        .await
        .expect("the agent got a connection")
        .expect("connect");
    let status = tokio::time::timeout(
        Duration::from_secs(3),
        status_on(&mut agent, addr, &fx.token),
    )
    .await
    .expect("the agent got an answer");
    assert_eq!(status, 200);
    // Four more silent clients: each one evicts an unauthenticated connection, never the agent.
    for _ in 0..4 {
        held.push(tls_connect(addr, &fx.ca_der).await);
    }
    assert_eq!(status_on(&mut agent, addr, &fx.token).await, 200);
    server.shutdown().await;
    fx.stop().await;
}

/// A TLS connection from the local address `from`.
#[cfg(target_os = "linux")]
async fn tls_connect_from(
    from: &str,
    addr: std::net::SocketAddr,
    ca_der: &[u8],
) -> tokio_rustls::client::TlsStream<TcpStream> {
    let socket = tokio::net::TcpSocket::new_v4().expect("socket");
    socket
        .bind(format!("{from}:0").parse().expect("from"))
        .expect("bind");
    let tcp = socket.connect(addr).await.expect("tcp");
    TlsConnector::from(client_config(ca_der, &[&rustls::version::TLS13], None))
        .connect(ServerName::try_from("localhost").expect("name"), tcp)
        .await
        .expect("handshake")
}

/// NEW-1: another `127.x` address is the same source as `127.0.0.1`, so a client there gets no
/// budget of its own. Its connection is the oldest of the one loopback source and gives way
/// first; if `127.0.0.2` were a separate source, the newer connections of `127.0.0.1` would.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn new1_another_loopback_address_gets_no_separate_budget() {
    let fx = Fixture::new().await;
    let (server, addr) = server_with(&fx, |config| {
        config.limits.max_connections = 3;
        config.limits.header_timeout = Duration::from_secs(30);
        config.limits.idle_timeout = Duration::from_secs(30);
    })
    .await;
    let mut other = tls_connect_from("127.0.0.2", addr, &fx.ca_der).await;
    let mut first = tls_connect_from("127.0.0.1", addr, &fx.ca_der).await;
    let mut second = tls_connect_from("127.0.0.1", addr, &fx.ca_der).await;
    let ca = fx.ca_der.clone();
    let newer = tokio::spawn(async move { tls_connect_from("127.0.0.1", addr, &ca).await });
    assert!(
        closed_within(&mut other, Duration::from_secs(3)).await,
        "the 127.0.0.2 connection kept its slot"
    );
    let _newer = tokio::time::timeout(Duration::from_secs(3), newer)
        .await
        .expect("the new connection was served")
        .expect("task");
    assert!(!closed_within(&mut first, Duration::from_millis(300)).await);
    assert!(!closed_within(&mut second, Duration::from_millis(300)).await);
    server.shutdown().await;
    fx.stop().await;
}

/// An HTTP/2 connection whose client gives every stream a flow-control window of 0, so the server
/// can send response headers but never a byte of a body.
async fn h2_zero_window(
    addr: std::net::SocketAddr,
    ca_der: &[u8],
) -> (
    hyper::client::conn::http2::SendRequest<common::http_body_util_lite::Full>,
    tokio::task::JoinHandle<()>,
) {
    let mut config = (*client_config(ca_der, &[&rustls::version::TLS13], None)).clone();
    config.alpn_protocols = vec![b"h2".to_vec()];
    let tcp = TcpStream::connect(addr).await.expect("tcp");
    let tls = TlsConnector::from(Arc::new(config))
        .connect(ServerName::try_from("localhost").expect("name"), tcp)
        .await
        .expect("handshake");
    let (sender, conn) =
        hyper::client::conn::http2::Builder::new(hyper_util::rt::TokioExecutor::new())
            .initial_stream_window_size(0)
            .handshake::<_, common::http_body_util_lite::Full>(hyper_util::rt::TokioIo::new(tls))
            .await
            .expect("h2");
    let ended = tokio::spawn(async move {
        drop(conn.await);
    });
    (sender, ended)
}

/// NEW-6: a token holder that never takes a response (HTTP/2 window 0) does not keep the
/// connection: the response waits `send_timeout` for the client, then the connection is closed.
/// The idle time is long, so only the send rule can close it.
#[tokio::test]
async fn new6_a_response_the_client_never_takes_closes_the_connection() {
    let fx = Fixture::new().await;
    let (server, addr) = server_with(&fx, |config| {
        config.limits.idle_timeout = Duration::from_secs(30);
        config.limits.send_timeout = Duration::from_millis(600);
    })
    .await;
    let (mut sender, ended) = h2_zero_window(addr, &fx.ca_der).await;
    let request = hyper::Request::builder()
        .uri(format!("https://localhost:{}/v1/status", addr.port()))
        .header("authorization", format!("Bearer {}", fx.token))
        .body(common::http_body_util_lite::Full::new(""))
        .expect("request");
    let response = sender.send_request(request).await.expect("send");
    assert_eq!(response.status(), 200);
    // Keep the body (dropping it would reset the stream). With a window of 0 no byte of it can
    // come; the poll below never gives back capacity, since it gets no data.
    let clock = cerberus_types::Stopwatch::start();
    let mut body = response.into_body();
    let first = tokio::time::timeout(
        Duration::from_millis(200),
        http_body_util::BodyExt::frame(&mut body),
    )
    .await;
    assert!(first.is_err(), "a body frame came through: {first:?}");
    let closed = tokio::time::timeout(Duration::from_secs(3), ended).await;
    assert!(closed.is_ok(), "the stalled response kept the connection");
    assert!(
        clock.elapsed() >= Duration::from_millis(500),
        "closed at {:?}",
        clock.elapsed()
    );
    drop(body);
    server.shutdown().await;
    fx.stop().await;
}

/// NEW-6: one agent cannot take every authenticated slot. Past `max_connections_per_agent`, a
/// good token on a new connection gets `429 rate_limited`; when one of its connections ends, the
/// new one is served.
#[tokio::test]
async fn new6_one_agent_cannot_hold_every_connection() {
    let fx = Fixture::new().await;
    let (server, addr) = server_with(&fx, |config| {
        config.limits.max_connections_per_agent = 2;
        config.limits.idle_timeout = Duration::from_secs(30);
    })
    .await;
    let client = common::Client::new(addr, &fx.ca_der, None);
    let mut first = client.connect().await.expect("connect");
    let mut second = client.connect().await.expect("connect");
    let mut third = client.connect().await.expect("connect");
    assert_eq!(status_on(&mut first, addr, &fx.token).await, 200);
    assert_eq!(status_on(&mut second, addr, &fx.token).await, 200);
    assert_eq!(status_on(&mut third, addr, &fx.token).await, 429);
    // The first two keep working.
    assert_eq!(status_on(&mut second, addr, &fx.token).await, 200);
    drop(first);
    let clock = cerberus_types::Stopwatch::start();
    loop {
        let status = status_on(&mut third, addr, &fx.token).await;
        if status == 200 {
            break;
        }
        assert_eq!(status, 429);
        assert!(
            clock.elapsed() < Duration::from_secs(3),
            "the closed connection still counts"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    server.shutdown().await;
    fx.stop().await;
}

/// NEW-6: revoking a key closes the connections that it authenticated, even an idle one with a
/// long idle time.
#[tokio::test]
async fn new6_revoking_a_key_closes_its_connections() {
    let fx = Fixture::new().await;
    let (server, addr) = server_with(&fx, |config| {
        config.limits.idle_timeout = Duration::from_secs(30);
    })
    .await;
    let mut tls = tls_connect(addr, &fx.ca_der).await;
    let request = format!(
        "GET /v1/status HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {}\r\n\r\n",
        fx.token
    );
    tls.write_all(request.as_bytes()).await.expect("write");
    let mut buf = [0u8; 64];
    let n = tls.read(&mut buf).await.expect("read");
    assert!(buf[..n].starts_with(b"HTTP/1.1 200"));
    assert!(
        !closed_within(&mut tls, Duration::from_millis(1200)).await,
        "closed before the revoke"
    );
    fx.core
        .revoke_agent_key(&common::op_ctx(&fx.owner), fx.key_id)
        .await
        .expect("revoke");
    assert!(
        closed_within(&mut tls, Duration::from_secs(3)).await,
        "the revoked key kept its connection"
    );
    server.shutdown().await;
    fx.stop().await;
}

/// AUD-30: a temporary file that already exists with a loose mode must not decide the mode of the
/// key file.
#[cfg(unix)]
#[tokio::test]
async fn aud30_a_stale_loose_temp_file_does_not_set_the_key_mode() {
    use std::os::unix::fs::PermissionsExt;
    let fx = Fixture::with(Options {
        keep_ca: true,
        ..Options::default()
    })
    .await;
    let ca = Arc::clone(fx.ca.as_ref().expect("ca"));
    let tmp = fx.tls.leaf_key_der.with_extension("tmp");
    std::fs::write(&tmp, b"old").expect("tmp");
    std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o644)).expect("chmod");
    let leaf = ca
        .issue_leaf(&cerberus_api::tls::leaf_names(&[]), SystemClock.now())
        .expect("leaf");
    write_leaf(&fx.tls, &leaf).expect("write");
    let mode = std::fs::metadata(&fx.tls.leaf_key_der)
        .expect("key")
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600);
    fx.stop().await;
}

/// A leaf of another CA (left behind by a setup that was killed, or by an older vault in the folder) is not accepted for
/// this CA, and the renewal replaces it at once, although it is new and has the right names.
#[test]
fn a_leaf_of_another_ca_is_not_issued_by_this_ca_and_is_renewed() {
    let dir = tempfile::tempdir().expect("tempdir");
    let paths = cerberus_api::tls::TlsPaths::in_data_dir(dir.path());
    let now = SystemClock.now();
    let dead = LocalCa::create(&VaultId::generate(), now).expect("dead ca");
    let live = LocalCa::create(&VaultId::generate(), now).expect("live ca");
    let names = cerberus_api::tls::leaf_names(&[]);
    write_leaf(&paths, &dead.issue_leaf(&names, now).expect("leaf")).expect("write");
    assert!(cerberus_api::tls::leaf_issued_by(&paths, dead.cert_der()));
    assert!(!cerberus_api::tls::leaf_issued_by(&paths, live.cert_der()));
    assert!(
        cerberus_api::tls::renew_leaf_if_needed(&live, &paths, &names, now).expect("renew"),
        "the leaf of the dead CA is replaced"
    );
    assert!(cerberus_api::tls::leaf_issued_by(&paths, live.cert_der()));
    assert!(
        !cerberus_api::tls::renew_leaf_if_needed(&live, &paths, &names, now).expect("renew"),
        "a leaf of this CA is kept"
    );
    // No leaf at all is not issued by any CA.
    let empty = cerberus_api::tls::TlsPaths::in_data_dir(&dir.path().join("none"));
    assert!(!cerberus_api::tls::leaf_issued_by(&empty, live.cert_der()));
}
