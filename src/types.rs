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
    NoHostName,
    NoPathAndQuery,
    PrivateKeyNotFound,
}

pub type Result<T> = std::result::Result<T, Error>;
