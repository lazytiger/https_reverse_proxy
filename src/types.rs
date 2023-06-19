use std::io::ErrorKind;

use derive_more::From;

#[derive(From, Debug)]
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
}

pub type Result<T> = std::result::Result<T, Error>;

pub fn from_io_error(err: std::io::Error) -> Option<Error> {
    match err.kind() {
        ErrorKind::WouldBlock | ErrorKind::NotConnected => None,
        _ => Some(Error::Handshake),
    }
}
