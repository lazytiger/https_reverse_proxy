use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::{Error, ErrorKind, Read, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::str::FromStr;
use std::sync::{Arc, RwLock};
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use hyper::body::Bytes;
use hyper::client::HttpConnector;
use hyper::http::HeaderName;
use hyper::server::accept::Accept;
use hyper::service::{make_service_fn, service_fn};
use hyper::{http, Body, Client, HeaderMap, Request, Response, StatusCode, Uri};
use hyper_rustls::HttpsConnector;
use mio::event::Source;
use mio::net::{TcpListener, TcpStream};
use mio::{Events, Poll as MPoll, Token};
use rustls::ServerConfig;
use scan_fmt::scan_fmt;
use tokio::io::{AsyncRead, AsyncSeekExt, AsyncWrite, ReadBuf};

use crate::cert_resolver::DynamicCertificateResolver;
use crate::tls_conn::TlsStream;
use crate::{options, types, utils};

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
        } else {
            log::info!("read waker for connection:{} not found", token.0);
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
        } else {
            //log::warn!("write waker for connection:{} not found", token.0);
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
        } else {
            log::warn!("flush waker for connection:{} not found", token.0);
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

    #[allow(dead_code)]
    pub fn deregister(&self, source: &mut impl Source) -> types::Result<()> {
        let lock = self.poll.read().map_err(|_| types::Error::ReadLock)?;
        source.deregister(lock.registry())?;
        Ok(())
    }

    #[allow(dead_code)]
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
                        log::info!("new connection created");
                        Poll::Ready(Some(Ok(conn)))
                    }
                    Err(err) => {
                        log::error!("failed to create connection: {}", err);
                        Poll::Ready(None)
                    }
                }
            }
            Err(err) if err.kind() == ErrorKind::WouldBlock => {
                log::info!("accept blocked");
                Poll::Pending
            }
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

impl Drop for HttpsConnection {
    fn drop(&mut self) {
        let _ = self.poll.deregister(&mut self.stream);
        log::info!("connection:{} dropped", self.token.0);
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
        let buffer = buf.initialize_unfilled();
        match pin.stream.read(buffer) {
            Ok(n) => {
                offset += n;
                buf.set_filled(offset);
                //cx.waker().wake_by_ref();
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
            Ok(n) => {
                //cx.waker().wake_by_ref();
                Poll::Ready(Ok(n))
            }
            Err(err) if err.kind() == ErrorKind::WouldBlock => Poll::Pending,
            Err(err) => Poll::Ready(Err(err.into())),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        let pin = self.get_mut();
        let _ = pin.poll.set_flush_waker(pin.token, cx.waker().clone());
        match pin.stream.flush() {
            Ok(_) => {
                //cx.waker().wake_by_ref();
                Poll::Ready(Ok(()))
            }
            Err(err) if err.kind() == ErrorKind::WouldBlock => Poll::Pending,
            Err(err) => Poll::Ready(Err(err.into())),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        let pin = self.get_mut();
        let _ = pin.stream.shutdown();
        Poll::Ready(Ok(()))
    }
}

lazy_static::lazy_static! {
    static ref CLIENT:Client<HttpsConnector<HttpConnector>, Body> = {
       let https = hyper_rustls::HttpsConnectorBuilder::new()
        .with_native_roots()
        .https_only()
        .enable_http1()
        .build();
        Client::builder().build(https)
    };
}

async fn do_request(mut req: Request<Body>) -> types::Result<Response<Body>> {
    let host = req
        .headers()
        .get(http::header::HOST)
        .ok_or(types::Error::NoHostName)?
        .to_str()?;
    let query = req
        .uri()
        .path_and_query()
        .ok_or(types::Error::NoPathAndQuery)?
        .as_str();
    let url = format!("https://{}{}", host, query);
    let range = get_header_value(req.headers(), http::header::RANGE, "".to_string());
    let (range_start, range_end) = if let Ok((range_start, range_end)) =
        scan_fmt!(range.as_str(), "bytes={}-{}", usize, usize)
    {
        (range_start, range_end)
    } else {
        log::info!("parse range:'{}' failed", range);
        (0, 0)
    };
    *req.uri_mut() = Uri::from_str(url.as_str())?;
    let mut resp = CLIENT.request(req).await?;
    let content_length = get_header_value(resp.headers(), http::header::CONTENT_LENGTH, 0usize);
    log::info!("status:{}", resp.status());
    if resp.status().is_success() {
        resp = match do_cache(range_start, range_end, content_length, url.clone(), resp).await {
            Ok(ret) => ret,
            Err(err) => {
                log::error!("found error:{}", err);
                Response::builder()
                    .status(StatusCode::SERVICE_UNAVAILABLE)
                    .body(Body::empty())
                    .unwrap()
            }
        }
    }
    Ok(resp)
}

fn get_header_value<T>(headers: &HeaderMap, key: HeaderName, dft: T) -> T
where
    T: Clone,
    T: FromStr,
{
    headers
        .get(key)
        .map(|header| header.to_str().map(|s| s.parse()))
        .unwrap_or(Ok(Ok(dft.clone())))
        .unwrap_or(Ok(dft.clone()))
        .unwrap_or(dft)
}

async fn do_cache(
    range_start: usize,
    range_end: usize,
    content_length: usize,
    url: String,
    mut resp: Response<Body>,
) -> types::Result<Response<Body>> {
    let content_type = get_header_value(resp.headers(), http::header::CONTENT_TYPE, "".to_string());
    log::info!(
        "content-type:{}, content-length:{}, range:{}-{}",
        content_type,
        content_length,
        range_start,
        range_end,
    );
    if options().as_run().content_types.contains(&content_type) {
        let (path, name) = utils::get_path_and_name(url.as_str(), 3);
        let root = PathBuf::from(options().as_run().cache_store.clone());
        let dir = root.join(path);
        std::fs::create_dir_all(&dir)?;
        let name = dir.join(name);
        if !name.is_file() && range_start == 0 && content_length > 0 {
            let tmp_file = name.to_string_lossy().to_string() + ".tmp";
            if let Ok(file) = OpenOptions::new()
                .create_new(true)
                .write(true)
                .append(true)
                .open(&tmp_file)
            {
                log::info!("cache not found, save response now");
                let (parts, body) = resp.into_parts();
                let saver =
                    BodySaverStream::new(file, body, tmp_file, name.clone(), content_length);
                resp = Response::from_parts(parts, Body::wrap_stream(saver));
            } else {
                log::info!("cache already going");
                return Ok(resp);
            }
        }
        if name.is_file() {
            log::info!("cache found");
            let file = FileStream::new(&name, range_start, range_end).await?;
            *resp.body_mut() = Body::wrap_stream(file);
        }
    } else {
        log::info!("content-type:{} ignored", content_type);
    }
    Ok(resp)
}

pub async fn run() -> types::Result<()> {
    let resolver = Arc::new(DynamicCertificateResolver::new(
        options().ca_crt_path.clone(),
        options().ca_key_path.clone(),
        options().as_run().certificate_store.clone(),
    )?);
    let config = Arc::new(
        ServerConfig::builder()
            .with_safe_defaults()
            .with_no_client_auth()
            .with_cert_resolver(resolver),
    );
    let poll = TlsPoll::new().unwrap();

    let listener = TcpListener::bind(options().as_run().listen_address.parse()?)?;
    let builder = hyper::server::Server::builder(TlsAcceptor::new(listener, config, poll.clone())?);
    let make_server = make_service_fn(|_conn: &HttpsConnection| async {
        Ok::<_, types::Error>(service_fn(do_request))
    });

    let server = builder.http1_keepalive(true).serve(make_server);

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
            std::thread::sleep(Duration::from_millis(1));
        }
    });
    if let Err(err) = server.await {
        log::error!("server exit:{}", err);
    }
    Ok(())
}

pub struct FileStream {
    file: tokio::fs::File,
    offset: usize,
    range_end: usize,
}

impl FileStream {
    pub async fn new(
        name: impl AsRef<Path>,
        range_start: usize,
        mut range_end: usize,
    ) -> types::Result<FileStream> {
        if range_end == 0 {
            range_end = std::fs::metadata(&name)?.len() as usize;
        }
        let mut file = tokio::fs::File::open(name).await?;
        file.seek(SeekFrom::Start(range_start as u64)).await?;
        Ok(Self {
            file,
            offset: range_start,
            range_end,
        })
    }
}

impl futures_core::Stream for FileStream {
    type Item = types::Result<Vec<u8>>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let mut data = vec![0u8; options().as_run().file_buffer * 1024];
        let len = data.len().min(self.range_end - self.offset);
        let mut buf = ReadBuf::new(&mut data.as_mut_slice()[..len]);
        if self.range_end == self.offset {
            return Poll::Ready(None);
        }
        match Pin::new(&mut self.file).poll_read(cx, &mut buf) {
            Poll::Ready(Ok(_)) => {
                unsafe {
                    let len = buf.filled().len();
                    self.offset += len;
                    data.set_len(len);
                }
                Poll::Ready(Some(Ok(data)))
            }
            Poll::Ready(Err(err)) => Poll::Ready(Some(Err(err.into()))),
            Poll::Pending => Poll::Pending,
        }
    }
}

pub struct BodySaverStream {
    file: std::fs::File,
    body: Body,
    tmp_file: String,
    name: PathBuf,
    content_length: usize,
    length: usize,
    completed: bool,
}

impl BodySaverStream {
    fn new(
        file: std::fs::File,
        body: Body,
        tmp_file: String,
        name: PathBuf,
        content_length: usize,
    ) -> BodySaverStream {
        Self {
            file,
            body,
            tmp_file,
            name,
            content_length,
            length: 0,
            completed: false,
        }
    }
    fn done(&self, mut ok: bool) {
        if self.completed {
            return;
        }
        if self.content_length != self.length {
            if ok {
                log::error!(
                    "{} - {}, content_length not match length",
                    self.content_length,
                    self.length
                );
                ok = false;
            }
        }
        log::info!("body saver finished:{}", ok);

        let ret = if ok {
            std::fs::rename(&self.tmp_file, &self.name)
        } else {
            std::fs::remove_file(&self.tmp_file)
        };

        if let Err(err) = ret {
            log::error!("file operation failed:{}", err);
        }
    }
}

impl futures_core::Stream for BodySaverStream {
    type Item = types::Result<Bytes>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match Pin::new(&mut self.body).poll_next(cx) {
            Poll::Ready(Some(Ok(item))) => {
                if let Err(err) = self.file.write_all(item.as_ref()) {
                    self.done(false);
                    Poll::Ready(Some(Err(err.into())))
                } else {
                    self.length += item.len();
                    if self.length == self.content_length {
                        log::info!("done now");
                        self.done(true);
                    }
                    Poll::Ready(Some(Ok(item)))
                }
            }
            Poll::Ready(None) => {
                self.done(true);
                Poll::Ready(None)
            }
            Poll::Ready(Some(Err(err))) => {
                self.done(false);
                Poll::Ready(Some(Err(err.into())))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}
