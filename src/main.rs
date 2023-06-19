use std::sync::Arc;

use clap::Parser;
use mio::event::Source;
use mio::net::TcpListener;
use mio::{Events, Interest, Poll, Token};
use rustls::{ClientConfig, RootCertStore, ServerConfig};

use crate::cert_resolver::DynamicCertificateResolver;
use crate::dns_resolver::DnsResolver;
use crate::options::Options;
use crate::proxy_conn::ProxyConnection;
use crate::proxy_manager::ProxyManager;
use crate::tls_conn::TlsStream;
use crate::types::Result;

mod cert_resolver;
mod dns_resolver;
mod logger;
mod options;
mod proxy_conn;
mod proxy_manager;
mod tls_conn;
mod types;

fn main() -> Result<()> {
    let options = Options::parse();
    logger::setup_logger(options.log_file.as_str(), options.log_level)?;
    let resolver = Arc::new(DynamicCertificateResolver::new(
        options.ca_crt_path,
        options.ca_key_path,
    )?);
    let server_config = Arc::new(
        ServerConfig::builder()
            .with_safe_defaults()
            .with_no_client_auth()
            .with_cert_resolver(resolver),
    );
    let mut root_store = RootCertStore::empty();
    root_store.add_server_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.0.iter().map(|ta| {
        rustls::OwnedTrustAnchor::from_subject_spki_name_constraints(
            ta.subject,
            ta.spki,
            ta.name_constraints,
        )
    }));
    let client_config = Arc::new(
        ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(root_store)
            .with_no_client_auth(),
    );
    let mut listener = TcpListener::bind("0.0.0.0:443".parse()?)?;
    let mut poll = Poll::new()?;
    listener.register(poll.registry(), Token(0), Interest::READABLE)?;
    let mut resolver = DnsResolver::new(options.dns_server.clone(), Token(1), poll.registry())?;
    let mut manager = ProxyManager::new();
    let mut events = Events::with_capacity(1024);
    let mut index = 2;
    loop {
        poll.poll(&mut events, None).unwrap();
        for event in &events {
            log::info!("event:{:?}", event);
            match event.token().0 {
                0 => {
                    while let Ok((client, _)) = listener.accept() {
                        let conn = ProxyConnection::new(
                            TlsStream::new_server(client, server_config.clone(), Some(4096))?,
                            index,
                            client_config.clone(),
                            poll.registry(),
                        )?;
                        manager.push(index, conn);
                        index += 2;
                        if index < 2 {
                            index = 2;
                        }
                    }
                }
                1 => {
                    resolver.resolve(&mut manager, poll.registry())?;
                }
                i => {
                    manager.dispatch(i / 2 * 2, &mut resolver);
                }
            }
            manager.safe_remove(poll.registry());
        }
    }
}
