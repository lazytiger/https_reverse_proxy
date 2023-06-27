use std::io::ErrorKind;

use derive_more::{Display, Error, From};
use hyper::http;

#[derive(From, Debug, Error, Display)]
pub enum Error {
    Hyper(hyper::Error),
    StdIo(std::io::Error),
    Rustls(rustls::Error),
    Rcgen(rcgen::RcgenError),
    SetLogger(log::SetLoggerError),
    TokioJoin(tokio::task::JoinError),
    InvalidUri(http::uri::InvalidUri),
    RustlsSign(rustls::sign::SignError),
    StdNetAddrParse(std::net::AddrParseError),
    HttpHeaderToStr(http::header::ToStrError),
    TrustDnsProto(trust_dns_proto::error::ProtoError),
    RustClientInvalidDnsName(rustls::client::InvalidDnsNameError),
    //Eof,
    DnsQuery,
    ReadLock,
    WriteLock,
    Handshake,
    NoHostName,
    ReaderClosed,
    WriterClosed,
    NoPathAndQuery,
    PrivateKeyNotFound,
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
