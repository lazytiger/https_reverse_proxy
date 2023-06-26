use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::io::{Error, ErrorKind, Read, Write};
use std::pin::Pin;
use std::sync::{Arc, RwLock, RwLockReadGuard};
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use hyper::server::accept::Accept;
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Response};
use mio::event::Source;
use mio::net::{TcpListener, TcpStream};
use mio::{Events, Poll as MPoll, Token};
use rustls::{ServerConfig, ServerConnection};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::cert_resolver::DynamicCertificateResolver;
use crate::options::Options;
use crate::tls_conn::TlsConnection;
use crate::tls_conn::TlsStream;
use crate::types;
use crate::types::is_would_block;

#[derive(Clone)]
pub struct TlsPoll {
    poll: Arc<RwLock<MPoll>>,
    read_wakers: Arc<RwLock<HashMap<Token, Waker>>>,
    write_wakers: Arc<RwLock<HashMap<Token, Waker>>>,
    flush_wakers: Arc<RwLock<HashMap<Token, Waker>>>,
}

impl TlsPoll {
    pub fn new() -> types::Result<Self> {
        Ok(TlsPoll {
            poll: Arc::new(RwLock::new(MPoll::new()?)),
            read_wakers: Default::default(),
            write_wakers: Default::default(),
            flush_wakers: Default::default(),
        })
    }

    pub fn wake_read(&self, token: Token) -> types::Result<()> {
        let lock = self
            .read_wakers
            .read()
            .map_err(|_| types::Error::ReadLock)?;
        if let Some(waker) = lock.get(&token) {
            waker.wake_by_ref();
        }
        Ok(())
    }

    pub fn wake_write(&self, token: Token) -> types::Result<()> {
        let lock = self
            .write_wakers
            .read()
            .map_err(|_| types::Error::ReadLock)?;
        if let Some(waker) = lock.get(&token) {
            waker.wake_by_ref();
        }
        Ok(())
    }

    pub fn wake_flush(&self, token: Token) -> types::Result<()> {
        let lock = self
            .flush_wakers
            .read()
            .map_err(|_| types::Error::ReadLock)?;
        if let Some(waker) = lock.get(&token) {
            waker.wake_by_ref();
        }
        Ok(())
    }

    pub fn set_read_waker(&self, token: Token, waker: Waker) -> types::Result<()> {
        let mut lock = self
            .read_wakers
            .write()
            .map_err(|_| types::Error::WriteLock)?;
        lock.insert(token, waker);
        Ok(())
    }

    pub fn set_write_waker(&self, token: Token, waker: Waker) -> types::Result<()> {
        let mut lock = self
            .write_wakers
            .write()
            .map_err(|_| types::Error::WriteLock)?;
        lock.insert(token, waker);
        Ok(())
    }

    pub fn set_flush_waker(&self, token: Token, waker: Waker) -> types::Result<()> {
        let mut lock = self
            .flush_wakers
            .write()
            .map_err(|_| types::Error::WriteLock)?;
        lock.insert(token, waker);
        Ok(())
    }

    pub fn poll(&self, events: &mut Events, timeout: Option<Duration>) -> types::Result<()> {
        let mut lock = self.poll.write().map_err(|_| types::Error::WriteLock)?;
        lock.poll(events, timeout)?;
        Ok(())
    }

    pub fn register(
        &self,
        source: &mut impl Source,
        token: Token,
        interests: mio::Interest,
    ) -> types::Result<()> {
        let lock = self.poll.read().map_err(|_| types::Error::ReadLock)?;
        source.register(lock.registry(), token, interests)?;
        Ok(())
    }

    pub fn deregister(&self, source: &mut impl Source) -> types::Result<()> {
        let lock = self.poll.read().map_err(|_| types::Error::ReadLock)?;
        source.deregister(lock.registry())?;
        Ok(())
    }

    pub fn reregister(
        &self,
        source: &mut impl Source,
        token: Token,
        interests: mio::Interest,
    ) -> types::Result<()> {
        let lock = self.poll.read().map_err(|_| types::Error::ReadLock)?;
        source.reregister(lock.registry(), token, interests)?;
        Ok(())
    }
}

pub struct TlsAcceptor {
    listener: TcpListener,
    config: Arc<ServerConfig>,
    poll: TlsPoll,
    next_token: usize,
}

impl TlsAcceptor {
    pub fn new(
        mut listener: TcpListener,
        config: Arc<ServerConfig>,
        poll: TlsPoll,
    ) -> types::Result<Self> {
        poll.register(&mut listener, Token(0), mio::Interest::READABLE)?;
        Ok(Self {
            listener,
            config,
            poll,
            next_token: 1,
        })
    }
}

impl Accept for TlsAcceptor {
    type Conn = HttpsConnection;
    type Error = types::Error;

    fn poll_accept(
        self: Pin<&mut Self>,
        ctx: &mut Context<'_>,
    ) -> Poll<Option<Result<Self::Conn, Self::Error>>> {
        let pin = self.get_mut();
        let _ = pin.poll.set_read_waker(Token(0), ctx.waker().clone());
        match pin.listener.accept() {
            Ok((stream, addr)) => {
                log::info!("new connection from:{}", addr);
                let token = Token(pin.next_token);
                pin.next_token += 1;
                match HttpsConnection::new(pin.poll.clone(), token, stream, pin.config.clone()) {
                    Ok(conn) => {
                        log::info!("new connection found");
                        Poll::Ready(Some(Ok(conn)))
                    }
                    Err(err) => {
                        log::error!("failed to create connection: {}", err);
                        Poll::Ready(None)
                    }
                }
            }
            Err(err) if err.kind() == ErrorKind::WouldBlock => Poll::Pending,
            Err(err) => Poll::Ready(Some(Err(err.into()))),
        }
    }
}

pub struct HttpsConnection {
    stream: TlsStream,
    poll: TlsPoll,
    token: Token,
}

impl HttpsConnection {
    fn new(
        poll: TlsPoll,
        token: Token,
        mut stream: TcpStream,
        config: Arc<ServerConfig>,
    ) -> types::Result<Self> {
        poll.register(
            &mut stream,
            token,
            mio::Interest::READABLE | mio::Interest::WRITABLE,
        )?;
        let stream = TlsStream::new_server(stream, config, None)?;
        Ok(Self {
            token,
            poll,
            stream,
        })
    }
}

impl AsyncRead for HttpsConnection {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let pin = self.get_mut();
        let _ = pin.poll.set_read_waker(pin.token, cx.waker().clone());
        let mut offset = buf.filled().len();
        let mut buffer = buf.initialize_unfilled();
        match pin.stream.read(buffer) {
            Ok(n) => {
                offset += n;
                buf.set_filled(offset);
                Poll::Ready(Ok(()))
            }
            Err(err) if err.kind() == ErrorKind::WouldBlock => Poll::Pending,
            Err(err) => Poll::Ready(Err(err.into())),
        }
    }
}

impl AsyncWrite for HttpsConnection {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, Error>> {
        let pin = self.get_mut();
        let _ = pin.poll.set_write_waker(pin.token, cx.waker().clone());
        match pin.stream.write(buf) {
            Ok(n) => Poll::Ready(Ok(n)),
            Err(err) if err.kind() == ErrorKind::WouldBlock => Poll::Pending,
            Err(err) => Poll::Ready(Err(err.into())),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        let pin = self.get_mut();
        match pin.stream.flush() {
            Ok(_) => Poll::Ready(Ok(())),
            Err(err) if err.kind() == ErrorKind::WouldBlock => Poll::Pending,
            Err(err) => Poll::Ready(Err(err.into())),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        let pin = self.get_mut();
        let _ = pin.stream.shutdown();
        Poll::Ready(Ok(()))
    }
}

pub async fn build(listener: TcpListener, options: Options) -> types::Result<()> {
    let resolver = Arc::new(DynamicCertificateResolver::new(
        options.ca_crt_path.clone(),
        options.ca_key_path.clone(),
        options.as_run().certificate_store.clone(),
    )?);
    let config = Arc::new(
        ServerConfig::builder()
            .with_safe_defaults()
            .with_no_client_auth()
            .with_cert_resolver(resolver),
    );
    let poll = TlsPoll::new().unwrap();
    let builder = hyper::server::Server::builder(TlsAcceptor::new(listener, config, poll.clone())?);
    let make_server = make_service_fn(|conn: &HttpsConnection| {
        let server_name = conn.stream.server_name().unwrap_or("").to_string();
        log::info!("server_name:{}", server_name);
        async move {
            Ok::<_, types::Error>(service_fn(|req| async move {
                log::info!("uri:{}", req.uri());
                log::info!("header:{:?}", req.headers());
                Ok::<_, types::Error>(Response::new(Body::from("Hello, World!")))
            }))
        }
    });

    let server = builder.serve(make_server);

    std::thread::spawn(move || {
        log::info!("mio thread started");
        let mut events = Events::with_capacity(1024);
        while let Ok(()) = poll.poll(&mut events, Some(Duration::from_millis(1))) {
            for event in events.iter() {
                if event.is_readable() {
                    let _ = poll.wake_read(event.token());
                }
                if event.is_writable() {
                    let _ = poll.wake_write(event.token());
                    let _ = poll.wake_flush(event.token());
                }
            }
        }
    });
    if let Err(err) = server.await {
        log::error!("server exit:{}", err);
    }
    Ok(())
}
