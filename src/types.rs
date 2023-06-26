use std::io::ErrorKind;

use derive_more::{Display, Error, From};

#[derive(From, Debug, Error, Display)]
pub enum Error {
    StdIo(std::io::Error),
    Rcgen(rcgen::RcgenError),
    PrivateKeyNotFound,
    RustlsSign(rustls::sign::SignError),
    SetLogger(log::SetLoggerError),
    Rustls(rustls::Error),
    ReaderClosed,
    WriterClosed,
    Handshake,
    DnsQuery,
    StdNetAddrParse(std::net::AddrParseError),
    TrustDnsProto(trust_dns_proto::error::ProtoError),
    RustClientInvalidDnsName(rustls::client::InvalidDnsNameError),
    ReadLock,
    WriteLock,
    Eof,
    TokioJoin(tokio::task::JoinError),
}

pub type Result<T> = std::result::Result<T, Error>;

pub fn from_io_error(err: std::io::Error) -> Option<Error> {
    match err.kind() {
        ErrorKind::WouldBlock | ErrorKind::NotConnected | ErrorKind::Interrupted => None,
        _ => Some(Error::Handshake),
    }
}

pub fn is_would_block(err: &std::io::Error) -> bool {
    match err.kind() {
        ErrorKind::NotConnected | ErrorKind::Interrupted => true,
        _ => false,
    }
}
