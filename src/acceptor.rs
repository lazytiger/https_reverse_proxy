use std::fs::OpenOptions;
use std::io::{Error, ErrorKind, Read, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::str::FromStr;
use std::sync::Arc;
use std::task::{Context, Poll};

use hyper::body::Bytes;
use hyper::client::HttpConnector;
use hyper::http::HeaderName;
use hyper::server::accept::Accept;
use hyper::service::{make_service_fn, service_fn};
use hyper::{http, Body, Client, HeaderMap, Request, Response, StatusCode, Uri};
use hyper_rustls::HttpsConnector;
use rustls::{ServerConfig, ServerConnection};
use scan_fmt::scan_fmt;
use tokio::io::{AsyncRead, AsyncSeekExt, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, TcpStream};

use crate::cert_resolver::DynamicCertificateResolver;
use crate::{options, types, utils};

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
    type Conn = HttpsConnection;
    type Error = types::Error;

    fn poll_accept(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Self::Conn, Self::Error>>> {
        let pin = self.get_mut();
        match Pin::new(&mut pin.listener).poll_accept(cx) {
            Poll::Ready(Ok((stream, addr))) => {
                log::info!("new connection from:{}", addr);
                match HttpsConnection::new(stream, pin.config.clone()) {
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
            Poll::Ready(Err(err)) => Poll::Ready(Some(Err(err.into()))),
            Poll::Pending => Poll::Pending,
        }
    }
}

pub struct HttpsConnection {
    stream: TcpStream,
    session: ServerConnection,
    recv_buf: Vec<u8>,
    send_buf: Vec<u8>,
}

impl HttpsConnection {
    fn new(stream: TcpStream, config: Arc<ServerConfig>) -> types::Result<Self> {
        let session = ServerConnection::new(config)?;
        Ok(Self {
            stream,
            session,
            recv_buf: vec![0u8; options().as_run().net_buffer_size],
            send_buf: Vec::new(),
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
        if let Err(err) = pin.session.reader().read(buf.initialize_unfilled()) {
            if err.kind() != ErrorKind::WouldBlock {
                return Poll::Ready(Err(err));
            }
        } else {
            return Poll::Ready(Ok(()));
        }
        let mut raw_buf = ReadBuf::new(pin.recv_buf.as_mut_slice());
        match Pin::new(&mut pin.stream).poll_read(cx, &mut raw_buf) {
            Poll::Ready(Ok(_)) => {
                if let Err(err) = pin.session.read_tls(&mut raw_buf.filled()) {
                    Poll::Ready(Err(err))
                } else if let Err(_) = pin.session.process_new_packets() {
                    Poll::Ready(Err(ErrorKind::InvalidData.into()))
                } else {
                    Pin::new(pin).poll_read(cx, buf)
                }
            }
            ret => ret,
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
        if pin.send_buf.is_empty() {
            // session is empty, write buf to session first
            match pin.session.writer().write(buf) {
                // read actual data from session, drain the session.
                Ok(n) => match pin.session.write_tls(&mut pin.send_buf) {
                    // trying to flush data
                    Ok(_) => match Pin::new(pin).poll_flush(cx) {
                        Poll::Ready(Ok(_)) => Poll::Ready(Ok(n)),
                        Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
                        Poll::Pending => Poll::Pending,
                    },
                    Err(err) => Poll::Ready(Err(err)),
                },
                Err(err) => Poll::Ready(Err(err)),
            }
        } else {
            // session is not empty, flush data first and always return pending, except error
            match Pin::new(pin).poll_flush(cx).map(|t| t.map(|_| 0usize)) {
                Poll::Ready(Ok(_)) => Poll::Pending,
                ret => ret,
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        let pin = self.get_mut();
        if pin.send_buf.is_empty() {
            Poll::Ready(Ok(()))
        } else {
            match Pin::new(&mut pin.stream).poll_write(cx, pin.send_buf.as_slice()) {
                Poll::Ready(Ok(0)) => Poll::Ready(Err(ErrorKind::UnexpectedEof.into())),
                Poll::Ready(Ok(n)) => {
                    pin.send_buf.copy_within(n.., 0);
                    unsafe {
                        pin.send_buf.set_len(pin.send_buf.len() - n);
                    }
                    Poll::Ready(Ok(()))
                }
                Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
                Poll::Pending => Poll::Pending,
            }
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        let pin = self.get_mut();
        Pin::new(&mut pin.stream).poll_shutdown(cx)
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

    let listener = TcpListener::bind(options().as_run().listen_address.as_str()).await?;
    let builder = hyper::server::Server::builder(TlsAcceptor::new(listener, config)?);
    let make_server = make_service_fn(|_conn: &HttpsConnection| async {
        Ok::<_, types::Error>(service_fn(do_request))
    });

    let server = builder.http1_keepalive(true).serve(make_server);
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
        let mut data = vec![0u8; options().as_run().file_buffer_size * 1024];
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
