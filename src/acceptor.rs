use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use hyper::server::accept::Accept;
use rustls::{ServerConfig, ServerConnection};
use tokio::net::TcpListener;

use crate::tls_stream::TlsServerStream;
use crate::types;

pub struct TlsAcceptor {
    listener: TcpListener,
    config: Arc<ServerConfig>,
}

impl TlsAcceptor {
    pub fn new(listener: TcpListener, config: Arc<ServerConfig>) -> types::Result<Self> {
        Ok(Self { listener, config })
    }
}

impl Accept for TlsAcceptor {
    type Conn = TlsServerStream;
    type Error = types::Error;

    fn poll_accept(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Self::Conn, Self::Error>>> {
        let pin = self.get_mut();
        match Pin::new(&mut pin.listener).poll_accept(cx) {
            Poll::Ready(Ok((stream, addr))) => {
                log::info!("new connection from:{}", addr);
                let conn = TlsServerStream::new(
                    stream,
                    ServerConnection::new(pin.config.clone()).unwrap(),
                );
                Poll::Ready(Some(Ok(conn)))
            }
            Poll::Ready(Err(err)) => Poll::Ready(Some(Err(err.into()))),
            Poll::Pending => Poll::Pending,
        }
    }
}
