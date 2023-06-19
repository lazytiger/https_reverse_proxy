use std::collections::HashMap;
use std::io::{ErrorKind, Write};
use std::sync::Arc;

use clap::Parser;
use mio::{Events, Interest, Poll, Token};
use mio::event::Source;
use mio::net::TcpListener;
use rcgen::{CertificateParams, KeyPair};
use rustls::{ConfigBuilder, ServerConfig, ServerConnection};

use crate::options::Options;
use crate::resolver::DynamicCertificateResolver;

mod options;
mod types;
mod resolver;
mod logger;

fn main() {
    let options = Options::parse();
    logger::setup_logger(options.log_file.as_str(), options.log_level).unwrap();
    let resolver = Arc::new(DynamicCertificateResolver::new(options.ca_crt_path, options.ca_key_path).unwrap());
    let mut server_config = Arc::new(ServerConfig::builder().with_safe_defaults().with_no_client_auth().with_cert_resolver(resolver.clone()));
    let mut listener = TcpListener::bind("0.0.0.0:443".parse().unwrap()).unwrap();
    let mut poll = Poll::new().unwrap();
    listener.register(poll.registry(), Token(0), Interest::READABLE).unwrap();
    let mut events = Events::with_capacity(1024);
    let mut index = 1;
    let mut clients = HashMap::new();
    loop {
        poll.poll(&mut events, None).unwrap();
        for event in &events {
            match event.token().0 {
                0 => {
                    let (mut client, _) = listener.accept().unwrap();
                    client.register(poll.registry(), Token(index), Interest::READABLE | Interest::WRITABLE).unwrap();
                    clients.insert(index, (client, ServerConnection::new(server_config.clone()).unwrap()));
                    index += 2;
                }
                i if i % 2 == 1 => {
                    println!("found event:{:?}", event);
                    let (client, session) = clients.get_mut(&i).unwrap();
                    if event.is_readable() {
                        loop {
                            match session.read_tls(client) {
                               Ok(n)  => {
                                   println!("read {} bytes", n);
                               }
                                Err(err)if err.kind() == ErrorKind::WouldBlock => {
                                    break;
                                }
                                Err(err) => {
                                    println!("read failed:{}", err);
                                    break;
                                }
                            }
                        }
                        session.process_new_packets().unwrap();
                    }
                    //session.writer().write("Status 200".as_bytes()).unwrap();
                    session.write_tls(client).unwrap();
                    if let Some(name) = session.server_name() {
                        println!("{} handshake finished", name);
                    }
                }
                _ => {}
            }
        }
    }
}
