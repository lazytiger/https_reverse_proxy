use std::fs::File;
use std::io::Write;
use std::mem::MaybeUninit;
use std::sync::Arc;

use clap::Parser;
use mio::event::Source;
use mio::net::TcpListener;
use mio::{Events, Interest, Poll, Token};
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use tokio::runtime::Runtime;

use crate::cert_resolver::{gen_root_ca, DynamicCertificateResolver};
use crate::dns_resolver::DnsResolver;
use crate::options::{Command, Options};
use crate::proxy_conn::ProxyConnection;
use crate::proxy_manager::ProxyManager;
use crate::tls_conn::TlsStream;
use crate::types::Result;

mod acceptor;
mod cert_resolver;
mod dns_resolver;
mod logger;
mod options;
mod proxy_conn;
mod proxy_manager;
mod tls_conn;
mod types;
mod utils;

static mut OPTIONS: MaybeUninit<Options> = MaybeUninit::uninit();

pub fn options<'a>() -> &'a Options {
    unsafe { OPTIONS.assume_init_ref() }
}

fn main() {
    let ops = Options::parse();
    unsafe {
        OPTIONS.write(ops);
    }

    logger::setup_logger(options().log_file.as_str(), options().log_level).unwrap();
    match options().command {
        Command::Run(_) => {
            if let Err(err) = run() {
                log::error!("run failed:{:?}", err);
            }
        }
        Command::Proxy(_) => {
            if let Err(err) = proxy() {
                log::error!("proxy failed:{:?}", err);
            }
        }
        Command::Generate(_) => {
            if let Err(err) = gen() {
                log::error!("generate failed:{:?}", err);
            }
        }
    }
}

fn gen() -> Result<()> {
    let (ca_crt, ca_key) = gen_root_ca()?;

    let mut file = File::create(&options().ca_crt_path)?;
    file.write_all(ca_crt.as_bytes())?;

    let mut file = File::create(&options().ca_key_path)?;
    file.write_all(ca_key.as_bytes())?;

    Ok(())
}

fn proxy() -> Result<()> {
    let resolver = Arc::new(DynamicCertificateResolver::new(
        options().ca_crt_path.clone(),
        options().ca_key_path.clone(),
        options().as_proxy().certificate_store.clone(),
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
    let mut resolver = DnsResolver::new(
        options().as_proxy().dns_server.clone(),
        Token(1),
        poll.registry(),
    )?;
    let mut manager = ProxyManager::new();
    let mut events = Events::with_capacity(1024);
    let mut index = 2;
    while let Ok(()) = poll.poll(&mut events, None) {
        for event in &events {
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
                    manager.dispatch(i / 2 * 2, poll.registry(), &mut resolver);
                }
            }
            manager.safe_remove(poll.registry());
        }
    }
    Ok(())
}

fn run() -> Result<()> {
    let listener = TcpListener::bind("0.0.0.0:443".parse()?)?;
    let runtime = Runtime::new()?;
    let _ = runtime.block_on(acceptor::run(listener))?;
    Ok(())
}
