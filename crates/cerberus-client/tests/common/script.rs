//! A scripted TLS server: it answers with a queue of prepared replies and counts requests.
//! The certificates come from the real `LocalCa`, so pins match what the app shows.
#![allow(
    dead_code,
    missing_docs,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use cerberus_api::tls::{CaExport, LocalCa};
use cerberus_types::{Clock, SystemClock, VaultId};
use http_body_util::Full as Body;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

/// One prepared reply.
pub enum Reply {
    /// Status and JSON body.
    Json(u16, String),
    /// Close the connection without an answer.
    Drop,
    /// Status 200 `text/event-stream` with this body.
    Events(String),
}

pub struct Pki {
    pub ca: LocalCa,
    pub export: CaExport,
}

impl Pki {
    pub fn new() -> Self {
        let ca = LocalCa::create(&VaultId::generate(), SystemClock.now()).unwrap();
        let export = ca.export().unwrap();
        Self { ca, export }
    }

    pub fn ca_file(&self, dir: &std::path::Path) -> std::path::PathBuf {
        let path = dir.join(format!("ca-{}.pem", self.export.cert_sha256_hex));
        std::fs::write(&path, &self.export.pem).unwrap();
        path
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Versions {
    Tls13,
    Tls12Only,
}

pub struct Script {
    pub addr: SocketAddr,
    pub requests: Arc<AtomicUsize>,
    pub seen: Arc<Mutex<Vec<String>>>,
    queue: Arc<Mutex<VecDeque<Reply>>>,
}

impl Script {
    /// `send_ca`: put the CA certificate after the leaf in the chain.
    pub async fn start(pki: &Pki, send_ca: bool, versions: Versions, replies: Vec<Reply>) -> Self {
        let leaf = pki
            .ca
            .issue_leaf(
                &["localhost".to_owned(), "127.0.0.1".to_owned()],
                SystemClock.now(),
            )
            .unwrap();
        let mut chain = vec![CertificateDer::from(leaf.cert_der.clone())];
        if send_ca {
            chain.push(CertificateDer::from(pki.ca.cert_der().to_vec()));
        }
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
            leaf.key_der.expose_secret().to_vec(),
        ));
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let builder = rustls::ServerConfig::builder_with_provider(provider);
        let builder = match versions {
            Versions::Tls13 => builder.with_protocol_versions(&[&rustls::version::TLS13]),
            Versions::Tls12Only => builder.with_protocol_versions(&[&rustls::version::TLS12]),
        }
        .unwrap();
        let config = builder
            .with_no_client_auth()
            .with_single_cert(chain, key)
            .unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(config));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let requests = Arc::new(AtomicUsize::new(0));
        let seen = Arc::new(Mutex::new(Vec::new()));
        let queue = Arc::new(Mutex::new(VecDeque::from(replies)));
        let (r, s, q) = (requests.clone(), seen.clone(), queue.clone());
        tokio::spawn(async move {
            loop {
                let Ok((tcp, _)) = listener.accept().await else {
                    return;
                };
                let acceptor = acceptor.clone();
                let (r, s, q) = (r.clone(), s.clone(), q.clone());
                tokio::spawn(async move {
                    let Ok(tls) = acceptor.accept(tcp).await else {
                        return;
                    };
                    let service = service_fn(move |req: hyper::Request<hyper::body::Incoming>| {
                        let (r, s, q) = (r.clone(), s.clone(), q.clone());
                        async move {
                            r.fetch_add(1, Ordering::SeqCst);
                            let auth = req
                                .headers()
                                .get("authorization")
                                .and_then(|v| v.to_str().ok())
                                .unwrap_or("")
                                .to_owned();
                            s.lock().unwrap().push(format!(
                                "{} {} auth={}",
                                req.method(),
                                req.uri(),
                                !auth.is_empty()
                            ));
                            let reply = q.lock().unwrap().pop_front();
                            match reply {
                                None | Some(Reply::Drop) => Err(std::io::Error::other("drop")),
                                Some(Reply::Json(status, body)) => Ok::<_, std::io::Error>(
                                    hyper::Response::builder()
                                        .status(status)
                                        .header("content-type", "application/json")
                                        .body(Body::new(Bytes::from(body)))
                                        .unwrap(),
                                ),
                                Some(Reply::Events(body)) => Ok(hyper::Response::builder()
                                    .status(200)
                                    .header("content-type", "text/event-stream")
                                    .body(Body::new(Bytes::from(body)))
                                    .unwrap()),
                            }
                        }
                    });
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(TokioIo::new(tls), service)
                        .await;
                });
            }
        });
        Self {
            addr,
            requests,
            seen,
            queue,
        }
    }

    pub fn url(&self) -> String {
        format!("https://127.0.0.1:{}", self.addr.port())
    }

    pub fn count(&self) -> usize {
        self.requests.load(Ordering::SeqCst)
    }
}
