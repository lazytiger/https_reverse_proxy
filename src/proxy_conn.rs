use std::io::{ErrorKind, Read, Write};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

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
    handshake_done: bool,
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
            Interest::READABLE | Interest::WRITABLE,
        )?;
        Ok(Self {
            local,
            remote: None,
            local_remaining: None,
            remote_remaining: None,
            handshake_done: false,
            local_closed: false,
            remote_closed: false,
            index,
            config,
        })
    }

    pub fn local_to_remote(&mut self) {
        match copy_with_remaining(
            &mut self.local_remaining,
            &mut self.local,
            self.remote.as_mut().unwrap(),
            !self.local_closed,
        ) {
            Err(Error::ReaderClosed) => self.local_closed = true,
            Err(Error::WriterClosed) => self.remote_closed = true,
            _ => {}
        }
    }

    pub fn remote_to_local(&mut self) {
        match copy_with_remaining(
            &mut self.remote_remaining,
            self.remote.as_mut().unwrap(),
            &mut self.local,
            !self.remote_closed,
        ) {
            Err(Error::ReaderClosed) => self.remote_closed = true,
            Err(Error::WriterClosed) => self.local_closed = true,
            _ => {}
        }
    }

    pub fn tick(&mut self, resolver: &mut DnsResolver) {
        if !self.handshake_done {
            match self.local.handshake() {
                Err(_) => self.local_closed = true,
                Ok(true) => {
                    self.handshake_done = true;
                    if let Some(server_name) = self.local.server_name() {
                        resolver.query(server_name, self.index).unwrap();
                    } else {
                        log::error!("no server name found");
                        self.local_closed = true;
                        self.remote_closed = true;
                    }
                }
                _ => (),
            }
        }
        if self.remote.is_some() {
            self.local_to_remote();
            self.remote_to_local();
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
            Interest::READABLE | Interest::WRITABLE,
        )?;
        let _ = self.remote.replace(remote);
        Ok(())
    }

    pub fn resolved(&mut self, ips: &Vec<IpAddr>, registry: &Registry) {
        if let Err(err) = self.connect_to_remote(ips, registry) {
            log::error!("connect to remote:{:?} failed:{:?}", ips, err);
            self.remote_closed = true;
            self.local_closed = true;
        }
    }

    pub(crate) fn is_safe_to_close(&self) -> bool {
        match (self.local_closed, self.remote_closed) {
            (true, true) => true,
            (false, true) => self.remote_remaining.is_some(),
            (true, false) => self.local_remaining.is_some(),
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

fn copy_with_remaining<R, W>(
    remaining: &mut Option<Vec<u8>>,
    reader: &mut R,
    writer: &mut W,
    should_copy: bool,
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
    if should_copy {
        let ret = copy(reader, writer)?;
        *remaining = ret;
    }
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
