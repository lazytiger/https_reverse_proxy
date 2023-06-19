use derive_more::From;

#[derive(From, Debug)]
pub enum Error {
    StdIo(std::io::Error),
    Rcgen(rcgen::RcgenError),
    PrivateKeyNotFound,
    RustlsSign(rustls::sign::SignError),
    SetLogger(log::SetLoggerError),
}

pub type Result<T> = std::result::Result<T, Error>;