use std::io::{Error, ErrorKind, Read, Write};
use std::net::Shutdown;
use std::sync::Arc;

use mio::event::Source;
use mio::net::TcpStream;
use mio::{Interest, Registry, Token};
use rustls::{
    ClientConfig, ClientConnection, IoState, Reader, ServerConfig, ServerConnection, ServerName,
    Writer,
};

use crate::types::{from_io_error, is_would_block, Result};

pub enum TlsSession {
    Server(ServerConnection),
    Client(ClientConnection),
}

impl TlsSession {
    pub fn is_handshaking(&self) -> bool {
        match self {
            TlsSession::Server(conn) => conn.is_handshaking(),
            TlsSession::Client(conn) => conn.is_handshaking(),
        }
    }
    pub fn reader(&mut self) -> Reader {
        match self {
            TlsSession::Server(conn) => conn.reader(),
            TlsSession::Client(conn) => conn.reader(),
        }
    }

    pub fn read_tls(&mut self, rd: &mut dyn Read) -> std::result::Result<usize, Error> {
        match self {
            TlsSession::Server(conn) => conn.read_tls(rd),
            TlsSession::Client(conn) => conn.read_tls(rd),
        }
    }

    pub fn writer(&mut self) -> Writer {
        match self {
            TlsSession::Server(conn) => conn.writer(),
            TlsSession::Client(conn) => conn.writer(),
        }
    }

    pub fn write_tls(&mut self, wr: &mut dyn Write) -> std::result::Result<usize, Error> {
        match self {
            TlsSession::Server(conn) => conn.write_tls(wr),
            TlsSession::Client(conn) => conn.write_tls(wr),
        }
    }

    pub fn process_new_packets(&mut self) -> std::result::Result<IoState, rustls::Error> {
        match self {
            TlsSession::Server(conn) => conn.process_new_packets(),
            TlsSession::Client(conn) => conn.process_new_packets(),
        }
    }

    pub fn server_name(&self) -> Option<&str> {
        match self {
            TlsSession::Server(conn) => conn.server_name(),
            TlsSession::Client(_) => None,
        }
    }

    pub fn wants_write(&self) -> bool {
        match self {
            TlsSession::Server(conn) => conn.wants_write(),
            TlsSession::Client(conn) => conn.wants_write(),
        }
    }

    pub fn send_close_notify(&mut self) {
        match self {
            TlsSession::Server(conn) => {
                conn.send_close_notify();
            }
            TlsSession::Client(conn) => {
                conn.send_close_notify();
            }
        }
    }
}

pub struct TlsStream {
    stream: TcpStream,
    session: TlsSession,
    buffer_limit: Option<usize>,
}

impl TlsStream {
    pub fn new_server(
        stream: TcpStream,
        config: Arc<ServerConfig>,
        buffer_limit: Option<usize>,
    ) -> Result<Self> {
        let mut session = ServerConnection::new(config)?;
        session.set_buffer_limit(buffer_limit);
        Ok(Self {
            stream,
            session: TlsSession::Server(session),
            buffer_limit,
        })
    }

    pub fn new_client(
        stream: TcpStream,
        config: Arc<ClientConfig>,
        buffer_limit: Option<usize>,
        server_name: ServerName,
    ) -> Result<Self> {
        let mut session = ClientConnection::new(config, server_name)?;
        session.set_buffer_limit(buffer_limit);
        Ok(Self {
            stream,
            session: TlsSession::Client(session),
            buffer_limit,
        })
    }

    pub fn shutdown(&mut self) -> std::io::Result<()> {
        self.session.send_close_notify();
        self.stream.shutdown(Shutdown::Both)
    }
}

impl Source for TlsStream {
    fn register(
        &mut self,
        registry: &Registry,
        token: Token,
        interests: Interest,
    ) -> std::io::Result<()> {
        self.stream.register(registry, token, interests)
    }

    fn reregister(
        &mut self,
        registry: &Registry,
        token: Token,
        interests: Interest,
    ) -> std::io::Result<()> {
        self.stream.reregister(registry, token, interests)
    }

    fn deregister(&mut self, registry: &Registry) -> std::io::Result<()> {
        self.stream.deregister(registry)
    }
}

impl Read for TlsStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        debug_assert!(!buf.is_empty());
        match self.session.reader().read(buf) {
            Err(err) if err.kind() == ErrorKind::WouldBlock => {
                match self.session.read_tls(&mut self.stream) {
                    Ok(n) if n > 0 => {
                        if let Err(err) = self.session.process_new_packets() {
                            Err(Error::new(ErrorKind::InvalidData, err))
                        } else {
                            self.read(buf)
                        }
                    }
                    Err(err) if is_would_block(&err) => Err(ErrorKind::WouldBlock.into()),
                    ret => ret,
                }
            }
            ret => ret,
        }
    }
}

impl Write for TlsStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        debug_assert!(!buf.is_empty());
        match self.session.writer().write(buf) {
            Ok(0) => match self.session.write_tls(&mut self.stream) {
                Err(err) if is_would_block(&err) => Err(ErrorKind::WouldBlock.into()),
                Ok(n) if n > 0 => self.write(buf),
                ret => ret,
            },
            ret => ret,
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        let ret = self
            .session
            .write_tls(&mut self.stream)
            .map(|_| {})
            .map_err(|err| {
                if is_would_block(&err) {
                    ErrorKind::WouldBlock.into()
                } else {
                    err
                }
            });
        ret
    }
}

pub trait TlsConnection: Read + Write + Source + Sized {
    fn server_name(&self) -> Option<&str>;
    fn handshake(&mut self) -> Result<bool>;
    fn new_client_with_stream(
        &mut self,
        stream: TcpStream,
        config: Arc<ClientConfig>,
        server_name: ServerName,
    ) -> Result<Self>;
    fn new_server_with_stream(
        &mut self,
        stream: TcpStream,
        config: Arc<ServerConfig>,
    ) -> Result<Self>;
    fn is_handshaking(&self) -> bool;
    fn wants_write(&self) -> bool;
}

impl TlsConnection for TlsStream {
    fn server_name(&self) -> Option<&str> {
        self.session.server_name()
    }

    fn handshake(&mut self) -> Result<bool> {
        if self.session.server_name().is_none() {
            match self
                .session
                .read_tls(&mut self.stream)
                .map_err(from_io_error)
            {
                Err(Some(err)) => return Err(err),
                _ => (),
            }
            self.session.process_new_packets()?;

            match self
                .session
                .write_tls(&mut self.stream)
                .map_err(from_io_error)
            {
                Err(Some(err)) => return Err(err),
                _ => (),
            }
        }
        Ok(self.session.server_name().is_some())
    }

    fn new_client_with_stream(
        &mut self,
        stream: TcpStream,
        config: Arc<ClientConfig>,
        server_name: ServerName,
    ) -> Result<Self> {
        TlsStream::new_client(stream, config, self.buffer_limit, server_name)
    }

    fn new_server_with_stream(
        &mut self,
        stream: TcpStream,
        config: Arc<ServerConfig>,
    ) -> Result<Self> {
        TlsStream::new_server(stream, config, self.buffer_limit)
    }

    fn is_handshaking(&self) -> bool {
        self.session.is_handshaking()
    }

    fn wants_write(&self) -> bool {
        self.session.wants_write()
    }
}
