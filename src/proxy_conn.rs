use std::io::{ErrorKind, Read, Write};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use mio::event::Source;
use mio::net::TcpStream;
use mio::{Interest, Registry, Token};
use rustls::{ClientConfig, ServerName};

use crate::dns_resolver::DnsResolver;
use crate::tls_conn::TlsConnection;
use crate::types::{Error, Result};

pub struct ProxyConnection<L> {
    local: L,
    remote: Option<L>,
    local_remaining: Option<Vec<u8>>,
    remote_remaining: Option<Vec<u8>>,
    local_handshake_done: bool,
    remote_handshake_done: bool,
    local_closed: bool,
    remote_closed: bool,
    index: usize,
    config: Arc<ClientConfig>,
}

impl<L> ProxyConnection<L>
where
    L: TlsConnection,
{
    pub fn new(
        mut local: L,
        index: usize,
        config: Arc<ClientConfig>,
        registry: &Registry,
    ) -> Result<Self> {
        local.register(
            registry,
            Token(index),
            Interest::WRITABLE | Interest::READABLE,
        )?;
        Ok(Self {
            local,
            remote: None,
            local_remaining: None,
            remote_remaining: None,
            local_handshake_done: false,
            remote_handshake_done: false,
            local_closed: false,
            remote_closed: false,
            index,
            config,
        })
    }

    pub fn local_to_remote(&mut self, registry: &Registry) {
        if self.remote_closed {
            return;
        }
        let old_remaining = self.local_remaining.is_some();
        match copy_with_remaining(
            &mut self.local_remaining,
            &mut self.local,
            self.remote.as_mut().unwrap(),
        ) {
            Err(Error::ReaderClosed) => {
                self.local_closed = true;
            }
            Err(_err) => {
                self.remote_closed = true;
            }
            Ok(_) => {
                if let Err(err) = reregister(
                    old_remaining,
                    self.local_remaining.is_some(),
                    self.remote.as_mut().unwrap(),
                    registry,
                    Token(self.index + 1),
                ) {
                    self.remote_closed = true;
                    log::error!("remote reregister failed:{:?}", err);
                }
            }
        }
    }

    pub fn remote_to_local(&mut self, registry: &Registry) {
        if self.local_closed {
            return;
        }
        let old_remaining = self.remote_remaining.is_some();
        match copy_with_remaining(
            &mut self.remote_remaining,
            self.remote.as_mut().unwrap(),
            &mut self.local,
        ) {
            Err(Error::ReaderClosed) => {
                self.remote_closed = true;
            }
            Err(_) => {
                self.local_closed = true;
            }
            Ok(_) => {
                if let Err(err) = reregister(
                    old_remaining,
                    self.remote_remaining.is_some(),
                    &mut self.local,
                    registry,
                    Token(self.index),
                ) {
                    self.local_closed = true;
                    log::error!("local reregister failed:{:?}", err);
                }
            }
        }
    }

    pub fn tick(&mut self, registry: &Registry, resolver: &mut DnsResolver) {
        if !self.local_handshake_done {
            match self.local.handshake() {
                Err(_) => {
                    self.local_closed = true;
                    self.remote_closed = true;
                }
                Ok(true) => {
                    self.local_handshake_done = true;
                    if let Some(server_name) = self.local.server_name() {
                        resolver.query(server_name, self.index).unwrap();
                        #[cfg(windows)]
                        let _ =
                            self.local
                                .reregister(registry, Token(self.index), Interest::READABLE);
                    } else {
                        self.local_closed = true;
                        self.remote_closed = true;
                    }
                }
                _ => {}
            }
        }

        if self.remote.is_some() {
            if !self.remote_handshake_done && !self.remote.as_mut().unwrap().is_handshaking() {
                self.remote_handshake_done = true;
                #[cfg(windows)]
                let _ = self.remote.as_mut().unwrap().reregister(
                    registry,
                    Token(self.index + 1),
                    Interest::READABLE,
                );
            }
            self.local_to_remote(registry);
            self.remote_to_local(registry);
            if !self.local_closed {
                let _ = self.local.flush();
            }
            if !self.remote_closed {
                let _ = self.remote.as_mut().unwrap().flush();
            }
        }
    }

    fn connect_to_remote(&mut self, ips: &Vec<IpAddr>, registry: &Registry) -> Result<()> {
        let ip = ips.get(0).ok_or(Error::DnsQuery)?;
        let addr = SocketAddr::new(*ip, 443);
        let stream = TcpStream::connect(addr)?;
        let mut remote = self.local.new_client_with_stream(
            stream,
            self.config.clone(),
            ServerName::try_from(self.local.server_name().unwrap())?,
        )?;
        remote.register(
            registry,
            Token(self.index + 1),
            Interest::WRITABLE | Interest::READABLE,
        )?;
        let _ = self.remote.replace(remote);
        Ok(())
    }

    pub fn resolved(&mut self, ips: &Vec<IpAddr>, registry: &Registry) {
        if let Err(_) = self.connect_to_remote(ips, registry) {
            self.remote_closed = true;
            self.local_closed = true;
        } else {
            self.local_to_remote(registry);
            self.remote_to_local(registry);
        }
    }

    pub(crate) fn is_safe_to_close(&self) -> bool {
        match (self.local_closed, self.remote_closed) {
            (true, true) => true,
            (false, true) => self.remote_remaining.is_none(),
            (true, false) => self.local_remaining.is_none(),
            (false, false) => false,
        }
    }

    pub fn close_now(&mut self, registry: &Registry) {
        let _ = self.local.deregister(registry);
        if let Some(remote) = &mut self.remote {
            let _ = remote.deregister(registry);
        }
    }
}

#[cfg(windows)]
fn reregister<S>(
    old_remaining: bool,
    new_remaining: bool,
    source: &mut S,
    registry: &Registry,
    token: Token,
) -> Result<()>
where
    S: Source,
{
    if old_remaining != new_remaining {
        if new_remaining {
            source.reregister(registry, token, Interest::WRITABLE | Interest::READABLE)?;
        } else {
            source.reregister(registry, token, Interest::READABLE)?;
        }
    }
    Ok(())
}

#[cfg(not(windows))]
fn reregister<S>(
    _old_remaining: bool,
    _new_remaining: bool,
    _source: &mut S,
    _registry: &Registry,
    _token: Token,
) -> Result<()>
where
    S: Source,
{
    Ok(())
}

fn copy_with_remaining<R, W>(
    remaining: &mut Option<Vec<u8>>,
    reader: &mut R,
    writer: &mut W,
) -> Result<()>
where
    R: Read,
    W: Write,
{
    if let Some(remaining) = remaining {
        let n = write_all(writer, remaining.as_slice())?;
        let m = remaining.len();
        if n > 0 && n < m {
            remaining.copy_within(n..m, 0);
            unsafe {
                remaining.set_len(m - n);
            }
        }
        if !remaining.is_empty() {
            return Ok(());
        }
    }
    *remaining = None;
    let ret = copy(reader, writer)?;
    *remaining = ret;
    Ok(())
}

fn copy<R, W>(reader: &mut R, writer: &mut W) -> Result<Option<Vec<u8>>>
where
    R: Read,
    W: Write,
{
    let mut buffer = vec![0u8; 1024];
    loop {
        match reader.read(buffer.as_mut_slice()) {
            Ok(0) => return Err(Error::ReaderClosed),
            Ok(n) => match write_all(writer, &buffer.as_slice()[..n]) {
                Ok(m) => {
                    if m < n {
                        buffer.copy_within(m..n, 0);
                        unsafe {
                            buffer.set_len(n - m);
                        }
                        return Ok(Some(buffer));
                    }
                }
                Err(err) => return Err(err),
            },
            Err(err) if err.kind() == ErrorKind::WouldBlock => return Ok(None),
            Err(_) => return Err(Error::ReaderClosed),
        }
    }
}

fn write_all<W>(writer: &mut W, mut data: &[u8]) -> Result<usize>
where
    W: Write,
{
    let mut len = 0;
    loop {
        match writer.write(data) {
            Ok(0) => return Err(Error::WriterClosed),
            Ok(n) => {
                len += n;
                if n == data.len() {
                    return Ok(len);
                }
                data = &data[n..];
            }
            Err(err) if err.kind() == ErrorKind::WouldBlock => return Ok(len),
            Err(_) => return Err(Error::WriterClosed),
        }
    }
}
