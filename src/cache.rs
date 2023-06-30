use std::fs::OpenOptions;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;

use hyper::client::HttpConnector;
use hyper::header::HeaderName;
use hyper::service::{make_service_fn, service_fn};
use hyper::Client;
use hyper::{http, Body, HeaderMap, Request, Response, StatusCode, Uri};
use hyper_rustls::HttpsConnector;
use rustls::ServerConfig;
use scan_fmt::scan_fmt;
use tokio::net::TcpListener;

use crate::acceptor::TlsAcceptor;
use crate::cert_resolver::DynamicCertificateResolver;
use crate::file_stream::{BodySaverStream, FileStream};
use crate::tls_stream::TlsServerStream;
use crate::{options, types, utils};

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
    let make_server = make_service_fn(|_conn: &TlsServerStream| async {
        Ok::<_, types::Error>(service_fn(do_request))
    });

    let server = builder.http1_keepalive(true).serve(make_server);
    if let Err(err) = server.await {
        log::error!("server exit:{}", err);
    }
    Ok(())
}
